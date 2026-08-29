import hashlib
import importlib.util
import json
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".gitea" / "scripts" / "release_artifacts.py"
RELEASE_INPUT = ROOT / ".gitea" / "release-tools.in"
RELEASE_LOCK = ROOT / ".gitea" / "release-tools.lock"
WORKFLOW = ROOT / ".gitea" / "workflows" / "publish-pypi.yml"
SPEC = importlib.util.spec_from_file_location("release_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_artifacts = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_artifacts
SPEC.loader.exec_module(release_artifacts)


def _dist(
    tmp_path: Path, version: str = "0.1.8.post1"
) -> tuple[Path, dict[str, bytes]]:
    dist = tmp_path / "dist"
    dist.mkdir()
    payloads = {
        f"netbox_rpc-{version}-py3-none-any.whl": b"wheel-bytes",
        f"netbox_rpc-{version}.tar.gz": b"sdist-bytes",
    }
    for name, payload in payloads.items():
        (dist / name).write_bytes(payload)
    return dist, payloads


def _manifest(tmp_path: Path) -> tuple[Path, dict, dict[str, bytes]]:
    dist, payloads = _dist(tmp_path)
    value = release_artifacts.create_manifest(
        dist=dist,
        package="netbox-rpc",
        version="0.1.8.post1",
        source_sha="a" * 40,
    )
    return dist, value, payloads


def _metadata(package_type: str, package: str, version: str, repository=None) -> bytes:
    return json.dumps(
        {
            "name": package,
            "repository": repository,
            "type": package_type,
            "version": version,
        }
    ).encode()


def _rows(manifest: dict, names: set[str] | None = None) -> bytes:
    selected = [
        row for row in manifest["artifacts"] if names is None or row["name"] in names
    ]
    return json.dumps(
        [_registry_row(row, file_id=391 + index) for index, row in enumerate(selected)]
    ).encode()


def _registry_row(row: dict, *, file_id: int = 391) -> dict:
    return {
        "id": file_id,
        "size": row["size"],
        "name": row["name"],
        "md5": "1" * 32,
        "sha1": "2" * 40,
        "sha256": row["sha256"],
        "sha512": "3" * 128,
    }


class _FakeResponse:
    def __init__(self, status: int, body: bytes = b"", url: str | None = None):
        self.status = status
        self.body = body
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def geturl(self) -> str:
        assert self.url is not None
        return self.url

    def read(self, maximum: int) -> bytes:
        return self.body[:maximum]


class _FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout: int):
        assert timeout == 30
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        if response.url is None:
            response.url = request.full_url
        return response


def _install_opener(monkeypatch: pytest.MonkeyPatch, responses) -> _FakeOpener:
    opener = _FakeOpener(responses)
    monkeypatch.setattr(
        release_artifacts.urllib.request, "build_opener", lambda *_: opener
    )
    return opener


def test_manifest_is_canonical_and_matches_exact_local_bytes(tmp_path: Path) -> None:
    dist, expected, _ = _manifest(tmp_path)
    path = tmp_path / "release-manifest.json"
    written = release_artifacts.write_manifest(
        dist=dist,
        package="netbox-rpc",
        version="0.1.8.post1",
        source_sha="a" * 40,
        output=path,
    )
    assert written == expected
    assert path.read_bytes() == (
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    assert (
        release_artifacts.verify_manifest(
            manifest_path=path,
            dist=dist,
            package="netbox-rpc",
            version="0.1.8.post1",
            source_sha="a" * 40,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("version", "source_sha"),
    [
        ("01.2.3", "a" * 40),
        ("1.2", "a" * 40),
        ("1.2.3+local", "a" * 40),
        ("1.2.3.post01", "a" * 40),
        ("1.2.3", "A" * 40),
        ("1.2.3", "a" * 39),
    ],
)
def test_manifest_rejects_noncanonical_identity(
    tmp_path: Path, version: str, source_sha: str
) -> None:
    dist, _ = _dist(tmp_path, version)
    with pytest.raises(release_artifacts.ReleaseArtifactError):
        release_artifacts.create_manifest(
            dist=dist,
            package="netbox-rpc",
            version=version,
            source_sha=source_sha,
        )


@pytest.mark.parametrize("schema", [True, 1.0, "1"])
def test_manifest_loader_rejects_noninteger_schema(
    tmp_path: Path, schema: object
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    manifest["schema"] = schema
    path = tmp_path / "release-manifest.json"
    path.write_bytes(release_artifacts._manifest_bytes(manifest))
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="identity"):
        release_artifacts.load_manifest(path)


def test_manifest_rejects_extra_wrong_and_unsafe_entries(tmp_path: Path) -> None:
    dist, _ = _dist(tmp_path)
    (dist / "extra.txt").write_text("unexpected")
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="exact"):
        release_artifacts.create_manifest(
            dist=dist,
            package="netbox-rpc",
            version="0.1.8.post1",
            source_sha="a" * 40,
        )

    (dist / "extra.txt").unlink()
    wheel = dist / "netbox_rpc-0.1.8.post1-py3-none-any.whl"
    wheel.unlink()
    wheel.symlink_to(dist / "netbox_rpc-0.1.8.post1.tar.gz")
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="Unsafe"):
        release_artifacts.create_manifest(
            dist=dist,
            package="netbox-rpc",
            version="0.1.8.post1",
            source_sha="a" * 40,
        )


def test_manifest_loader_rejects_noncanonical_or_mutated_evidence(
    tmp_path: Path,
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    path = tmp_path / "release-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="canonical"):
        release_artifacts.load_manifest(path)

    manifest["unexpected"] = True
    path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="schema"):
        release_artifacts.load_manifest(path)


def test_manifest_verification_detects_changed_artifact_bytes(tmp_path: Path) -> None:
    dist, manifest, _ = _manifest(tmp_path)
    path = tmp_path / "release-manifest.json"
    path.write_bytes(release_artifacts._manifest_bytes(manifest))
    (dist / "netbox_rpc-0.1.8.post1.tar.gz").write_bytes(b"changed")
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="does not match"):
        release_artifacts.verify_manifest(
            manifest_path=path,
            dist=dist,
            package="netbox-rpc",
            version="0.1.8.post1",
            source_sha="a" * 40,
        )


def test_missing_artifacts_supports_absent_and_exact_partial_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    absent = _install_opener(
        monkeypatch,
        [urllib.error.HTTPError("registry", 404, "missing", {}, None)],
    )
    assert release_artifacts.missing_gitea_artifacts(
        owner="N-MultiCloud",
        repository="netbox-rpc",
        manifest=manifest,
        token="secret",
    ) == sorted(row["name"] for row in manifest["artifacts"])
    assert "secret" not in absent.requests[0].full_url

    wheel = next(row for row in manifest["artifacts"] if row["name"].endswith(".whl"))
    _install_opener(
        monkeypatch,
        [
            _FakeResponse(
                200,
                _metadata("pypi", "netbox-rpc", "0.1.8.post1"),
            ),
            _FakeResponse(200, _rows(manifest, {wheel["name"]})),
            _FakeResponse(200, b"wheel-bytes"),
        ],
    )
    assert release_artifacts.missing_gitea_artifacts(
        owner="N-MultiCloud",
        repository="netbox-rpc",
        manifest=manifest,
        token="secret",
    ) == ["netbox_rpc-0.1.8.post1.tar.gz"]


@pytest.mark.parametrize(
    "bad_rows",
    [
        [_registry_row({"name": "extra.whl", "sha256": "0" * 64, "size": 1})],
        [
            _registry_row(
                {
                    "name": "netbox_rpc-0.1.8.post1.tar.gz",
                    "sha256": "0" * 64,
                    "size": 11,
                }
            )
        ],
    ],
)
def test_partial_resume_rejects_conflicting_registry_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_rows: list[dict]
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    _install_opener(
        monkeypatch,
        [
            _FakeResponse(
                200,
                _metadata("pypi", "netbox-rpc", "0.1.8.post1"),
            ),
            _FakeResponse(200, json.dumps(bad_rows).encode()),
        ],
    )
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="differ"):
        release_artifacts.missing_gitea_artifacts(
            owner="N-MultiCloud",
            repository="netbox-rpc",
            manifest=manifest,
            token="secret",
        )


def test_partial_resume_does_not_treat_a_missing_inventory_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    _install_opener(
        monkeypatch,
        [
            _FakeResponse(
                200,
                _metadata("pypi", "netbox-rpc", "0.1.8.post1"),
            ),
            urllib.error.HTTPError("registry", 404, "missing", {}, None),
        ],
    )
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="inventory"):
        release_artifacts.missing_gitea_artifacts(
            owner="N-MultiCloud",
            repository="netbox-rpc",
            manifest=manifest,
            token="secret",
        )


def test_partial_resume_verifies_existing_download_before_requesting_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    wheel = next(row for row in manifest["artifacts"] if row["name"].endswith(".whl"))
    _install_opener(
        monkeypatch,
        [
            _FakeResponse(
                200,
                _metadata("pypi", "netbox-rpc", "0.1.8.post1"),
            ),
            _FakeResponse(200, _rows(manifest, {wheel["name"]})),
            _FakeResponse(200, b"x" * len(b"wheel-bytes")),
        ],
    )
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="Downloaded"):
        release_artifacts.missing_gitea_artifacts(
            owner="N-MultiCloud",
            repository="netbox-rpc",
            manifest=manifest,
            token="secret",
        )


def test_complete_package_requires_link_and_exact_downloaded_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, payloads = _manifest(tmp_path)
    repository = {"full_name": "N-MultiCloud/netbox-rpc"}
    responses = [
        _FakeResponse(200, _metadata("pypi", "netbox-rpc", "0.1.8.post1", repository)),
        _FakeResponse(200, _rows(manifest)),
        _FakeResponse(200, _metadata("pypi", "netbox-rpc", "0.1.8.post1", repository)),
    ]
    responses.extend(_FakeResponse(200, payloads[name]) for name in sorted(payloads))
    opener = _install_opener(monkeypatch, responses)
    release_artifacts.verify_gitea_artifacts(
        owner="N-MultiCloud",
        repository="netbox-rpc",
        manifest=manifest,
        token="secret",
    )
    assert len(opener.requests) == 5
    assert all("secret" not in request.full_url for request in opener.requests)


def test_complete_package_rejects_wrong_association_before_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    opener = _install_opener(
        monkeypatch,
        [
            _FakeResponse(
                200,
                _metadata(
                    "pypi",
                    "netbox-rpc",
                    "0.1.8.post1",
                    {"full_name": "N-MultiCloud/other"},
                ),
            ),
        ],
    )
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="identity"):
        release_artifacts.complete_gitea_artifacts(
            owner="N-MultiCloud",
            repository="netbox-rpc",
            manifest=manifest,
            token="secret",
        )
    assert [request.get_method() for request in opener.requests] == ["GET"]


def _generic_responses(manifest: dict, raw: bytes, first) -> list:
    package = "netbox-rpc-release-manifest"
    linked_metadata = _metadata(
        "generic",
        package,
        "0.1.8.post1",
        {"full_name": "N-MultiCloud/netbox-rpc"},
    )
    unlinked_metadata = _metadata("generic", package, "0.1.8.post1")
    files = json.dumps(
        [
            _registry_row(
                {
                    "name": "release-manifest.json",
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            )
        ]
    ).encode()
    return [
        first,
        _FakeResponse(200, unlinked_metadata),
        _FakeResponse(200, files),
        _FakeResponse(200, raw),
        _FakeResponse(204),
        _FakeResponse(200, linked_metadata),
        _FakeResponse(200, files),
        _FakeResponse(200, raw),
    ]


@pytest.mark.parametrize(
    "first",
    [
        _FakeResponse(201),
        urllib.error.HTTPError("registry", 409, "exists", {}, None),
    ],
)
def test_manifest_publish_is_idempotent_only_for_identical_existing_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, first
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    raw = release_artifacts._manifest_bytes(manifest)
    opener = _install_opener(monkeypatch, _generic_responses(manifest, raw, first))
    release_artifacts.publish_gitea_manifest(
        owner="N-MultiCloud",
        repository="netbox-rpc",
        manifest=manifest,
        token="secret",
    )
    assert [request.get_method() for request in opener.requests] == [
        "PUT",
        "GET",
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
        "GET",
    ]


def test_manifest_conflict_rejects_forged_existing_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    raw = release_artifacts._manifest_bytes(manifest)
    forged = raw.replace(b'"source_sha":"' + b"a" * 40, b'"source_sha":"' + b"b" * 40)
    responses = _generic_responses(
        manifest,
        forged,
        urllib.error.HTTPError("registry", 409, "exists", {}, None),
    )
    opener = _install_opener(monkeypatch, responses)
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="changed"):
        release_artifacts.publish_gitea_manifest(
            owner="N-MultiCloud",
            repository="netbox-rpc",
            manifest=manifest,
            token="secret",
        )
    assert [request.get_method() for request in opener.requests] == [
        "PUT",
        "GET",
        "GET",
        "GET",
    ]


def test_manifest_conflict_rejects_wrong_association_before_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, _ = _manifest(tmp_path)
    opener = _install_opener(
        monkeypatch,
        [
            urllib.error.HTTPError("registry", 409, "exists", {}, None),
            _FakeResponse(
                200,
                _metadata(
                    "generic",
                    "netbox-rpc-release-manifest",
                    "0.1.8.post1",
                    {"full_name": "N-MultiCloud/other"},
                ),
            ),
        ],
    )
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="identity"):
        release_artifacts.publish_gitea_manifest(
            owner="N-MultiCloud",
            repository="netbox-rpc",
            manifest=manifest,
            token="secret",
        )
    assert [request.get_method() for request in opener.requests] == ["PUT", "GET"]


def test_registry_request_rejects_redirect_oversize_and_hides_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = _install_opener(
        monkeypatch,
        [_FakeResponse(200, b"{}", "https://elsewhere.invalid/object")],
    )
    with pytest.raises(release_artifacts.ReleaseArtifactError) as caught:
        release_artifacts._request(
            "https://git.nmulti.cloud/object", token="registry-secret", maximum=10
        )
    assert "registry-secret" not in str(caught.value)
    assert opener.requests

    _install_opener(monkeypatch, [_FakeResponse(200, b"123456")])
    with pytest.raises(release_artifacts.ReleaseArtifactError, match="size bound"):
        release_artifacts._request(
            "https://git.nmulti.cloud/object", token="registry-secret", maximum=5
        )

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="malformed"):
        release_artifacts._request(
            "https://git.nmulti.cloud/object", token="secret\nheader", maximum=5
        )


def test_registry_inventory_accepts_only_the_gitea_package_file_contract() -> None:
    live_row = {
        "id": 391,
        "size": 495949,
        "name": "netbox_rpc-0.1.8-py3-none-any.whl",
        "md5": "14b2466ae7f29a5d9b3ff84e79efb3d4",
        "sha1": "71b9a304929fca60882d5a96e8bb2c94e71efcd0",
        "sha256": "c2358375709238f7a71759e3d3dc7cd346b9726d5a868b204e790824796ee921",
        "sha512": (
            "e8627e51835bbd3b8919d284704a5a0185217ac1e9df9a12621b49b6cc7b7175"
            "b435cbac76a4c194a3ce237abb4e6d01e6165618594059d6577214556b1217b4"
        ),
    }
    assert release_artifacts._inventory_rows([live_row]) == {
        live_row["name"]: {
            "name": live_row["name"],
            "sha256": live_row["sha256"],
            "size": live_row["size"],
        }
    }

    for mutation in (
        {**live_row, "unexpected": "field"},
        {key: value for key, value in live_row.items() if key != "sha512"},
        {**live_row, "id": True},
        {**live_row, "md5": "not-a-digest"},
    ):
        with pytest.raises(release_artifacts.ReleaseArtifactError, match="inventory"):
            release_artifacts._inventory_rows([mutation])


def test_publish_workflow_is_inert_until_trusted_control_exists() -> None:
    workflow = WORKFLOW.read_text()
    loaded = yaml.load(workflow, Loader=yaml.BaseLoader)
    assert loaded == {
        "name": "Package publication is disabled",
        "on": {},
        "permissions": {},
        "jobs": {},
    }
    assert workflow == (
        'name: Package publication is disabled\n\n"on": {}\npermissions: {}\njobs: {}\n'
    )
    assert "secrets." not in workflow
    assert "runs-on" not in workflow
    assert "workflow_dispatch" not in workflow


def test_release_tool_lock_is_complete_hashed_and_direct_inputs_are_exact() -> None:
    assert RELEASE_INPUT.read_text().splitlines() == [
        "build==1.3.0",
        "setuptools==83.0.0",
        "twine==6.2.0",
    ]
    lock = RELEASE_LOCK.read_text()
    requirement_names = []
    current = None
    hashes: dict[str, int] = {}
    for line in lock.splitlines():
        if line and not line.startswith((" ", "#")):
            current = line.split("==", 1)[0]
            requirement_names.append(current)
            hashes[current] = 0
        elif "--hash=sha256:" in line:
            assert current is not None
            hashes[current] += 1
    assert len(requirement_names) == len(set(requirement_names)) == 30
    assert all(count >= 1 for count in hashes.values())
    assert {"build", "setuptools", "twine"}.issubset(hashes)
    assert "build==1.3.0" in lock
    assert "setuptools==83.0.0" in lock
    assert "twine==6.2.0" in lock
