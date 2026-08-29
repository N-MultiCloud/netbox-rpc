#!/usr/bin/env python3
"""Create and publish exact registry-bound release evidence consumed by NMS."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

GITEA_ORIGIN = "https://git.nmulti.cloud"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
MD5_RE = re.compile(r"^[a-f0-9]{32}$")
SHA1_RE = re.compile(r"^[a-f0-9]{40}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SHA512_RE = re.compile(r"^[a-f0-9]{128}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:(?:a|b|rc)(?:0|[1-9][0-9]*))?"
    r"(?:\.post(?:0|[1-9][0-9]*))?"
    r"(?:\.dev(?:0|[1-9][0-9]*))?$"
)


class ReleaseArtifactError(ValueError):
    """The release artifact set or registry evidence is invalid."""


class _RegistryNotFound(ReleaseArtifactError):
    """The requested registry object does not exist."""


class _RegistryConflict(ReleaseArtifactError):
    """The registry object already exists."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def canonical_name(value: str) -> str:
    """Return the PEP 503 spelling used by the registry contract."""
    return re.sub(r"[-_.]+", "-", value).lower()


def _validate_version(version: str) -> None:
    if VERSION_RE.fullmatch(version) is None:
        raise ReleaseArtifactError("Version is not canonical")


def _expected_names(package: str, version: str) -> set[str]:
    normalized = canonical_name(package).replace("-", "_")
    return {
        f"{normalized}-{version}-py3-none-any.whl",
        f"{normalized}-{version}.tar.gz",
    }


def _record(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or SAFE_ID_RE.fullmatch(path.name) is None
        or not 0 < metadata.st_size <= MAX_ARTIFACT_BYTES
    ):
        raise ReleaseArtifactError(f"Unsafe release artifact: {path.name!r}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise ReleaseArtifactError("Release artifact exceeds its size bound")
            digest.update(chunk)
    return {"name": path.name, "sha256": digest.hexdigest(), "size": size}


def _manifest_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _manifest_identity(value: dict[str, Any]) -> tuple[str, str, str]:
    package = value.get("package")
    version = value.get("version")
    source_sha = value.get("source_sha")
    schema = value.get("schema")
    if type(schema) is not int or schema != 1:
        raise ReleaseArtifactError("Manifest identity is invalid")
    if not isinstance(package, str):
        raise ReleaseArtifactError("Manifest identity is invalid")
    if canonical_name(package) != package:
        raise ReleaseArtifactError("Manifest identity is invalid")
    if SAFE_ID_RE.fullmatch(package) is None:
        raise ReleaseArtifactError("Manifest identity is invalid")
    if not isinstance(version, str):
        raise ReleaseArtifactError("Manifest identity is invalid")
    if not isinstance(source_sha, str):
        raise ReleaseArtifactError("Manifest identity is invalid")
    if SHA_RE.fullmatch(source_sha) is None:
        raise ReleaseArtifactError("Manifest identity is invalid")
    _validate_version(version)
    return package, version, source_sha


def _valid_name(value: object, seen: set[str], error: str) -> str:
    if not isinstance(value, str):
        raise ReleaseArtifactError(error)
    if value in seen:
        raise ReleaseArtifactError(error)
    if SAFE_ID_RE.fullmatch(value) is None:
        raise ReleaseArtifactError(error)
    return value


def _valid_digest(value: object, pattern: re.Pattern[str], error: str) -> str:
    if not isinstance(value, str):
        raise ReleaseArtifactError(error)
    if pattern.fullmatch(value) is None:
        raise ReleaseArtifactError(error)
    return value


def _valid_size(value: object, error: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseArtifactError(error)
    if not 0 < value <= MAX_ARTIFACT_BYTES:
        raise ReleaseArtifactError(error)
    return value


def _artifact_row(row: object, seen: set[str], error: str) -> dict[str, object]:
    if not isinstance(row, dict):
        raise ReleaseArtifactError(error)
    if set(row) != {"name", "sha256", "size"}:
        raise ReleaseArtifactError(error)
    name = _valid_name(row.get("name"), seen, error)
    digest = _valid_digest(row.get("sha256"), SHA256_RE, error)
    size = _valid_size(row.get("size"), error)
    return {"name": name, "sha256": digest, "size": size}


def _registry_artifact_row(
    row: object, seen: set[str], error: str
) -> dict[str, object]:
    """Validate Gitea's exact PackageFile response and project proof fields."""
    if not isinstance(row, dict):
        raise ReleaseArtifactError(error)
    if set(row) != {"id", "name", "size", "md5", "sha1", "sha256", "sha512"}:
        raise ReleaseArtifactError(error)
    file_id = row.get("id")
    if isinstance(file_id, bool) or not isinstance(file_id, int) or file_id <= 0:
        raise ReleaseArtifactError(error)
    name = _valid_name(row.get("name"), seen, error)
    size = _valid_size(row.get("size"), error)
    _valid_digest(row.get("md5"), MD5_RE, error)
    _valid_digest(row.get("sha1"), SHA1_RE, error)
    digest = _valid_digest(row.get("sha256"), SHA256_RE, error)
    _valid_digest(row.get("sha512"), SHA512_RE, error)
    return {"name": name, "sha256": digest, "size": size}


def _validate_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseArtifactError("Manifest schema is not exact")
    if set(value) != {
        "artifacts",
        "package",
        "schema",
        "source_sha",
        "version",
    }:
        raise ReleaseArtifactError("Manifest schema is not exact")
    package, version, _source_sha = _manifest_identity(value)
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise ReleaseArtifactError("Manifest artifact set is not exact")
    if len(artifacts) != 2:
        raise ReleaseArtifactError("Manifest artifact set is not exact")
    names: set[str] = set()
    for row in artifacts:
        validated = _artifact_row(row, names, "Manifest artifact row is invalid")
        names.add(str(validated["name"]))
    if names != _expected_names(package, version):
        raise ReleaseArtifactError("Manifest artifact names are not exact")
    if [row["name"] for row in artifacts] != sorted(names):
        raise ReleaseArtifactError("Manifest artifacts are not canonical")
    return value


def create_manifest(
    *, dist: Path, package: str, version: str, source_sha: str
) -> dict[str, Any]:
    """Describe exactly one pure-Python wheel and one source distribution."""
    package = canonical_name(package)
    if SAFE_ID_RE.fullmatch(package) is None:
        raise ReleaseArtifactError("Package name is invalid")
    _validate_version(version)
    if SHA_RE.fullmatch(source_sha) is None:
        raise ReleaseArtifactError("Source SHA must be canonical lowercase 40-hex")
    entries = sorted(dist.iterdir(), key=lambda path: path.name)
    if len(entries) != 2 or {path.name for path in entries} != _expected_names(
        package, version
    ):
        raise ReleaseArtifactError(
            "Release set must contain the exact wheel and sdist names"
        )
    manifest = {
        "artifacts": [_record(path) for path in entries],
        "package": package,
        "schema": 1,
        "source_sha": source_sha,
        "version": version,
    }
    return _validate_manifest(manifest)


def write_manifest(
    *, dist: Path, package: str, version: str, source_sha: str, output: Path
) -> dict[str, Any]:
    """Create one canonical manifest outside the exact distribution directory."""
    manifest = create_manifest(
        dist=dist, package=package, version=version, source_sha=source_sha
    )
    output.write_bytes(_manifest_bytes(manifest))
    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    """Load an exact-schema canonical manifest."""
    raw = path.read_bytes()
    if not 0 < len(raw) <= MAX_RESPONSE_BYTES:
        raise ReleaseArtifactError("Manifest size is invalid")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseArtifactError("Manifest is not valid JSON") from exc
    manifest = _validate_manifest(value)
    if _manifest_bytes(manifest) != raw:
        raise ReleaseArtifactError("Manifest is not canonical schema 1 JSON")
    return manifest


def verify_manifest(
    *, manifest_path: Path, dist: Path, package: str, version: str, source_sha: str
) -> dict[str, Any]:
    """Require the manifest to match independently hashed local files."""
    expected = create_manifest(
        dist=dist, package=package, version=version, source_sha=source_sha
    )
    actual = load_manifest(manifest_path)
    if actual != expected:
        raise ReleaseArtifactError("Manifest does not match local artifact bytes")
    return actual


def _quoted(value: str) -> str:
    if SAFE_ID_RE.fullmatch(value) is None:
        raise ReleaseArtifactError("Registry identity contains unsafe characters")
    return urllib.parse.quote(value, safe="")


def _registry_request(
    url: str, *, token: str, method: str, payload: bytes | None
) -> urllib.request.Request:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ReleaseArtifactError("Only the canonical HTTPS Gitea origin is allowed")
    if parsed.netloc != "git.nmulti.cloud":
        raise ReleaseArtifactError("Only the canonical HTTPS Gitea origin is allowed")
    if any(character in token for character in "\r\n\0"):
        raise ReleaseArtifactError("Gitea package token is malformed")
    headers = {"Accept": "application/json", "User-Agent": "release-artifacts/1"}
    if token:
        headers["Authorization"] = f"token {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=payload, headers=headers, method=method)


def _read_response(
    response: object, *, url: str, maximum: int, accepted: frozenset[int]
) -> bytes:
    if response.geturl() != url:
        raise ReleaseArtifactError("Registry returned an invalid response")
    if response.status not in accepted:
        raise ReleaseArtifactError("Registry returned an invalid response")
    content = response.read(maximum + 1)
    if len(content) > maximum:
        raise ReleaseArtifactError("Registry response exceeds its size bound")
    return content


def _raise_http_error(exc: urllib.error.HTTPError) -> None:
    if exc.code == 404:
        raise _RegistryNotFound("Registry object is absent") from exc
    if exc.code == 409:
        raise _RegistryConflict("Registry object already exists") from exc
    raise ReleaseArtifactError("Registry request was rejected") from exc


def _request(
    url: str,
    *,
    token: str,
    maximum: int,
    method: str = "GET",
    payload: bytes | None = None,
    accepted: frozenset[int] = frozenset({200}),
) -> bytes:
    request = _registry_request(url, token=token, method=method, payload=payload)
    try:
        with urllib.request.build_opener(_NoRedirect).open(
            request, timeout=30
        ) as response:
            return _read_response(response, url=url, maximum=maximum, accepted=accepted)
    except urllib.error.HTTPError as exc:
        _raise_http_error(exc)
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise ReleaseArtifactError("Registry request failed") from exc
    raise AssertionError("unreachable")


def _json_request(url: str, *, token: str) -> object:
    raw = _request(url, token=token, maximum=MAX_RESPONSE_BYTES)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseArtifactError("Registry response is not valid JSON") from exc


def _package_root(owner: str, package_type: str, package: str) -> str:
    return (
        f"{GITEA_ORIGIN}/api/v1/packages/{_quoted(owner)}/"
        f"{_quoted(package_type)}/{_quoted(package)}"
    )


def _inventory_rows(value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, list):
        raise ReleaseArtifactError("Registry file inventory is malformed")
    rows: dict[str, dict[str, object]] = {}
    for row in value:
        validated = _registry_artifact_row(
            row,
            set(rows),
            "Registry file inventory entry is invalid",
        )
        rows[str(validated["name"])] = validated
    return rows


def _repository_link(metadata: dict[str, Any]) -> str | None:
    repository = metadata.get("repository")
    if repository is None:
        return None
    if not isinstance(repository, dict):
        raise ReleaseArtifactError("Registry package repository link is invalid")
    full_name = repository.get("full_name")
    if not isinstance(full_name, str):
        raise ReleaseArtifactError("Registry package repository link is invalid")
    return full_name


def _validate_pypi_metadata(
    metadata: object, *, package: str, version: str, repository: str
) -> str | None:
    if not isinstance(metadata, dict):
        raise ReleaseArtifactError("Registry package identity is invalid")
    if metadata.get("type") != "pypi":
        raise ReleaseArtifactError("Registry package identity is invalid")
    if canonical_name(str(metadata.get("name", ""))) != package:
        raise ReleaseArtifactError("Registry package identity is invalid")
    if metadata.get("version") != version:
        raise ReleaseArtifactError("Registry package identity is invalid")
    linked = _repository_link(metadata)
    if linked not in {None, repository}:
        raise ReleaseArtifactError("Registry package identity is invalid")
    return linked


def _validate_generic_metadata(
    metadata: object,
    *,
    package: str,
    version: str,
    repository: str,
    allow_unlinked: bool,
) -> None:
    if not isinstance(metadata, dict):
        raise ReleaseArtifactError("Gitea release manifest identity is invalid")
    if metadata.get("type") != "generic":
        raise ReleaseArtifactError("Gitea release manifest identity is invalid")
    if metadata.get("name") != package:
        raise ReleaseArtifactError("Gitea release manifest identity is invalid")
    if metadata.get("version") != version:
        raise ReleaseArtifactError("Gitea release manifest identity is invalid")
    linked = _repository_link(metadata)
    if allow_unlinked and linked in {None, repository}:
        return
    if linked != repository:
        raise ReleaseArtifactError("Gitea release manifest identity is invalid")


def _pypi_state(
    *, owner: str, repository: str, manifest: dict[str, Any], token: str
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    package, version = manifest["package"], manifest["version"]
    root = _package_root(owner, "pypi", package)
    metadata = _json_request(f"{root}/{_quoted(version)}", token=token)
    _validate_pypi_metadata(
        metadata,
        package=package,
        version=version,
        repository=f"{owner}/{repository}",
    )
    try:
        files = _inventory_rows(
            _json_request(f"{root}/{_quoted(version)}/files", token=token)
        )
    except _RegistryNotFound as exc:
        raise ReleaseArtifactError(
            "Registry package exists but its file inventory is unavailable"
        ) from exc
    expected = {row["name"]: row for row in manifest["artifacts"]}
    if not set(files).issubset(expected):
        raise ReleaseArtifactError("Registry artifacts differ from local evidence")
    if any(files[name] != expected[name] for name in files):
        raise ReleaseArtifactError("Registry artifacts differ from local evidence")
    return files, expected


def missing_gitea_artifacts(
    *, owner: str, repository: str, manifest: dict[str, Any], token: str
) -> list[str]:
    """Return only absent artifacts; reject every conflicting existing byte set."""
    try:
        present, expected = _pypi_state(
            owner=owner, repository=repository, manifest=manifest, token=token
        )
    except _RegistryNotFound:
        return sorted(row["name"] for row in manifest["artifacts"])
    _verify_pypi_downloads(
        owner=owner,
        manifest=manifest,
        rows=present,
        token=token,
    )
    return sorted(set(expected) - set(present))


def _link_package(
    *, owner: str, repository: str, package_type: str, package: str, token: str
) -> None:
    if not token:
        raise ReleaseArtifactError("Gitea package token is unavailable")
    url = f"{_package_root(owner, package_type, package)}/-/link/{_quoted(repository)}"
    try:
        _request(
            url,
            token=token,
            maximum=MAX_RESPONSE_BYTES,
            method="POST",
            payload=b"",
            accepted=frozenset({200, 201, 204}),
        )
    except _RegistryConflict:
        pass


def verify_gitea_artifacts(
    *, owner: str, repository: str, manifest: dict[str, Any], token: str
) -> None:
    """Verify the exact linked PyPI inventory and every downloaded byte."""
    present, expected = _pypi_state(
        owner=owner, repository=repository, manifest=manifest, token=token
    )
    if present != expected:
        raise ReleaseArtifactError("Registry release artifact set is incomplete")
    package, version = manifest["package"], manifest["version"]
    root = _package_root(owner, "pypi", package)
    metadata = _json_request(f"{root}/{_quoted(version)}", token=token)
    repo = metadata.get("repository") if isinstance(metadata, dict) else None
    if not isinstance(repo, dict) or repo.get("full_name") != f"{owner}/{repository}":
        raise ReleaseArtifactError("Registry package repository link is invalid")
    _verify_pypi_downloads(
        owner=owner,
        manifest=manifest,
        rows=expected,
        token=token,
    )


def complete_gitea_artifacts(
    *, owner: str, repository: str, manifest: dict[str, Any], token: str
) -> None:
    """Validate unlinked bytes before associating and reverify after linking."""
    present, expected = _pypi_state(
        owner=owner, repository=repository, manifest=manifest, token=token
    )
    if present != expected:
        raise ReleaseArtifactError("Registry release artifact set is incomplete")
    _verify_pypi_downloads(
        owner=owner,
        manifest=manifest,
        rows=expected,
        token=token,
    )
    _link_package(
        owner=owner,
        repository=repository,
        package_type="pypi",
        package=str(manifest["package"]),
        token=token,
    )
    verify_gitea_artifacts(
        owner=owner,
        repository=repository,
        manifest=manifest,
        token=token,
    )


def _verify_pypi_downloads(
    *,
    owner: str,
    manifest: dict[str, Any],
    rows: dict[str, dict[str, object]],
    token: str,
) -> None:
    package, version = manifest["package"], manifest["version"]
    for name, row in sorted(rows.items()):
        url = (
            f"{GITEA_ORIGIN}/api/packages/{_quoted(owner)}/pypi/files/"
            f"{_quoted(package)}/{_quoted(version)}/{_quoted(name)}"
        )
        content = _request(url, token=token, maximum=int(row["size"]))
        if (
            len(content) != row["size"]
            or hashlib.sha256(content).hexdigest() != row["sha256"]
        ):
            raise ReleaseArtifactError("Downloaded artifact differs from evidence")


def fetch_gitea_manifest(
    *,
    owner: str,
    repository: str,
    package: str,
    version: str,
    token: str,
    allow_unlinked: bool = False,
) -> dict[str, Any]:
    """Fetch and validate the one repository-linked generic manifest."""
    manifest_package = f"{canonical_name(package)}-release-manifest"
    root = _package_root(owner, "generic", manifest_package)
    metadata = _json_request(f"{root}/{_quoted(version)}", token=token)
    _validate_generic_metadata(
        metadata,
        package=manifest_package,
        version=version,
        repository=f"{owner}/{repository}",
        allow_unlinked=allow_unlinked,
    )
    files = _inventory_rows(
        _json_request(f"{root}/{_quoted(version)}/files", token=token)
    )
    if set(files) != {"release-manifest.json"}:
        raise ReleaseArtifactError("Gitea release manifest identity is invalid")
    row = files["release-manifest.json"]
    if int(row["size"]) > MAX_RESPONSE_BYTES:
        raise ReleaseArtifactError("Gitea release manifest inventory is invalid")
    url = (
        f"{GITEA_ORIGIN}/api/packages/{_quoted(owner)}/generic/"
        f"{_quoted(manifest_package)}/{_quoted(version)}/release-manifest.json"
    )
    raw = _request(url, token=token, maximum=int(row["size"]))
    if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise ReleaseArtifactError("Downloaded release manifest differs from inventory")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseArtifactError("Gitea release manifest is not valid JSON") from exc
    manifest = _validate_manifest(value)
    if _manifest_bytes(manifest) != raw:
        raise ReleaseArtifactError("Gitea release manifest is not canonical JSON")
    return manifest


def publish_gitea_manifest(
    *, owner: str, repository: str, manifest: dict[str, Any], token: str
) -> None:
    """Publish the manifest last and independently verify its exact bytes."""
    if not token:
        raise ReleaseArtifactError("Gitea package token is unavailable")
    package = f"{manifest['package']}-release-manifest"
    version = str(manifest["version"])
    raw = _manifest_bytes(manifest)
    url = (
        f"{GITEA_ORIGIN}/api/packages/{_quoted(owner)}/generic/"
        f"{_quoted(package)}/{_quoted(version)}/release-manifest.json"
    )
    try:
        _request(
            url,
            token=token,
            maximum=MAX_RESPONSE_BYTES,
            method="PUT",
            payload=raw,
            accepted=frozenset({200, 201, 204}),
        )
    except _RegistryConflict:
        pass
    existing = fetch_gitea_manifest(
        owner=owner,
        repository=repository,
        package=str(manifest["package"]),
        version=version,
        token=token,
        allow_unlinked=True,
    )
    if existing != manifest:
        raise ReleaseArtifactError("Published release manifest changed")
    _link_package(
        owner=owner,
        repository=repository,
        package_type="generic",
        package=package,
        token=token,
    )
    published = fetch_gitea_manifest(
        owner=owner,
        repository=repository,
        package=str(manifest["package"]),
        version=version,
        token=token,
    )
    if published != manifest:
        raise ReleaseArtifactError("Published release manifest changed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("manifest", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--dist", type=Path, required=True)
        command.add_argument("--package", required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--source-sha", required=True)
        command.add_argument("--manifest", type=Path, required=True)
    for name in ("missing-gitea", "complete-gitea", "publish-manifest"):
        command = commands.add_parser(name)
        command.add_argument("--owner", required=True)
        command.add_argument("--repository", required=True)
        command.add_argument("--manifest", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "manifest":
            write_manifest(
                dist=args.dist,
                package=args.package,
                version=args.version,
                source_sha=args.source_sha,
                output=args.manifest,
            )
        elif args.command == "verify":
            verify_manifest(
                manifest_path=args.manifest,
                dist=args.dist,
                package=args.package,
                version=args.version,
                source_sha=args.source_sha,
            )
        else:
            manifest = load_manifest(args.manifest)
            token = os.getenv("GITEA_PACKAGE_TOKEN", "")
            if args.command == "missing-gitea":
                for name in missing_gitea_artifacts(
                    owner=args.owner,
                    repository=args.repository,
                    manifest=manifest,
                    token=token,
                ):
                    print(name)
            elif args.command == "complete-gitea":
                complete_gitea_artifacts(
                    owner=args.owner,
                    repository=args.repository,
                    manifest=manifest,
                    token=token,
                )
            else:
                publish_gitea_manifest(
                    owner=args.owner,
                    repository=args.repository,
                    manifest=manifest,
                    token=token,
                )
    except (OSError, ReleaseArtifactError) as exc:
        raise SystemExit(f"error: {exc}") from None


if __name__ == "__main__":
    main()
