import hashlib
import re
import tomllib
from pathlib import Path

import pytest
import yaml
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
from yaml.events import AliasEvent
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    FlowMappingStartToken,
    FlowSequenceStartToken,
    TagToken,
)


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".gitea" / "workflows" / "ci.yml"
INTEGRATION_WORKFLOW_PATH = ROOT / ".gitea" / "workflows" / "integration.yml"
LOCK_PATH = ROOT / ".gitea" / "ci-requirements.lock"
PYTEST_CONFIG_PATH = ROOT / ".gitea" / "pytest-ci.ini"
CHECKOUT_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
LOCK_SHA256 = "e26ad1915e48f6a20916ddb2c72ad3bda27b4c36266d7ec6249939a2fda97842"
PYTEST_CONFIG_SHA256 = (
    "7f0a35baee4c8d0d2b3fce080490ec0a53f352d784a444ee91930f1728e9fc12"
)
INTEGRATION_WORKFLOW_SHA256 = (
    "c62bff36be7e147f148f7d2c1b360974628faf82beca87c6f0ddd224c58ef8fd"
)
STEP_RUN_SHA256 = {
    "Verify preprovisioned toolchain": (
        "8e371c88d91f45cbdce5d25a290abaf45e3ba899effcdfe0ab43c2056150b038"
    ),
    "Create isolated venv and install locked wheels": (
        "f080f69479ad7361b28a493957db402c37d43f67ad1ae08268ab3fc10b4bc110"
    ),
    "Syntax check (py_compile)": (
        "570d287e0381b6a32efaea962065a4c6c9ff46e771820617e2fe0b212cf7006e"
    ),
    "Run tests": "d3f3c440f8e34c685f93be000d450f568f647811c62943de3a1c56262329687d",
}

LOCKED_VERSIONS = {
    "annotated-types": "0.8.0",
    "attrs": "26.1.0",
    "certifi": "2026.7.22",
    "cffi": "2.1.1",
    "charset-normalizer": "3.5.1",
    "cryptography": "50.0.0",
    "idna": "3.18",
    "iniconfig": "2.3.0",
    "jinja2": "3.1.6",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.9.1",
    "markupsafe": "3.0.3",
    "packaging": "26.3",
    "pluggy": "1.6.0",
    "pycparser": "3.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "pygments": "2.21.0",
    "pytest": "9.1.1",
    "pytest-asyncio": "1.4.0",
    "pyyaml": "6.0.3",
    "referencing": "0.37.0",
    "requests": "2.34.2",
    "rpds-py": "2026.6.3",
    "setuptools": "83.0.0",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.4",
    "urllib3": "2.7.0",
}

LOCK_ENTRY_RE = re.compile(
    r"^# wheel: (?P<wheel>[^\s]+\.whl)\n"
    r"(?P<name>[a-z0-9][a-z0-9-]*)==(?P<version>[^\s\\]+) \\\n"
    r"    --hash=sha256:(?P<digest>[0-9a-f]{64})$",
    re.MULTILINE,
)


class _UniqueNoAliasLoader(yaml.BaseLoader):
    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise AssertionError("YAML aliases are forbidden in ordinary CI")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise AssertionError(f"duplicate YAML key: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_ci_workflow(workflow: str) -> dict:
    forbidden_tokens = (
        AliasToken,
        AnchorToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
        TagToken,
    )
    assert not any(isinstance(token, forbidden_tokens) for token in yaml.scan(workflow))
    loaded = yaml.load(workflow, Loader=_UniqueNoAliasLoader)
    assert isinstance(loaded, dict)
    return loaded


def _assert_ci_contract(workflow: str) -> None:
    loaded = _load_ci_workflow(workflow)
    assert set(loaded) == {"name", "on", "permissions", "concurrency", "jobs"}
    assert loaded["name"] == "CI"
    assert loaded["on"] == {"push": "", "pull_request": ""}
    assert loaded["permissions"] == {"contents": "read"}
    assert loaded["concurrency"] == {
        "group": "ci-${{ github.ref }}",
        "cancel-in-progress": "true",
    }
    assert set(loaded["jobs"]) == {"test"}

    job = loaded["jobs"]["test"]
    assert set(job) == {"name", "runs-on", "env", "steps"}
    assert job["name"] == "Syntax check and tests"
    assert job["runs-on"] == "ci-untrusted-python312"
    assert job["env"] == {
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_NO_CONFIG": "1",
        "UV_NO_SOURCES": "1",
    }

    steps = job["steps"]
    assert [step["name"] for step in steps] == [
        "Checkout",
        "Verify preprovisioned toolchain",
        "Create isolated venv and install locked wheels",
        "Syntax check (py_compile)",
        "Run tests",
    ]
    checkout = steps[0]
    assert set(checkout) == {"name", "uses", "with"}
    assert checkout["uses"] == CHECKOUT_ACTION
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": "false",
    }
    for step in steps[1:]:
        assert set(step) == {"name", "shell", "run"}
        assert step["shell"] == "bash"
        assert (
            hashlib.sha256(step["run"].encode()).hexdigest()
            == STEP_RUN_SHA256[step["name"]]
        )

    assert 'test "$("$python_bin" --version)" = "Python 3.12.14"' in workflow
    assert (
        'test "$("$uv_bin" --version)" = '
        '"uv 0.12.5 (x86_64-unknown-linux-gnu)"' in workflow
    )
    assert workflow.count('python_bin="/usr/local/bin/python3.12"') == 2
    assert workflow.count('uv_bin="/usr/local/bin/uv"') == 2
    assert workflow.count('test -x "$python_bin"') == 2
    assert workflow.count('test -x "$uv_bin"') == 2
    assert '"$python_bin" -I -S -' in workflow
    assert 'platform.python_implementation() != "CPython"' in workflow
    assert "sys.version_info[:3] != (3, 12, 14)" in workflow
    assert 'platform.machine() != "x86_64"' in workflow
    assert 'libc_name != "glibc"' in workflow
    assert "< (2, 34)" in workflow

    assert "UV_PYTHON_DOWNLOADS: never" in workflow
    assert 'UV_NO_CONFIG: "1"' in workflow
    assert 'UV_NO_SOURCES: "1"' in workflow
    assert workflow.count("env -i") == 5
    assert workflow.count("UV_PYTHON_DOWNLOADS=never") == 2
    assert workflow.count("UV_NO_CONFIG=1") == 2
    assert workflow.count("UV_NO_SOURCES=1") == 2

    assert "--python-version 3.12.14" in workflow
    assert "--python-platform x86_64-manylinux_2_34" in workflow
    assert workflow.count("--no-managed-python") == 2
    assert "--require-hashes" in workflow
    assert "--only-binary=:all:" in workflow
    assert workflow.count("--no-sources") == 1
    assert workflow.count("--no-python-downloads") == 2
    assert workflow.count("--no-config") == 2
    assert workflow.count("--no-cache") == 2
    assert "--keyring-provider disabled" in workflow
    assert "--index-strategy first-index" in workflow
    assert "--default-index https://pypi.org/simple" in workflow
    assert "--exact" in workflow
    assert "--strict" in workflow
    assert "--requirements .gitea/ci-requirements.lock" in workflow
    assert workflow.count("/usr/bin/find ") == 2
    assert workflow.count("/usr/bin/env -i PYTHONNOUSERSITE=1") == 2
    assert workflow.count(".ci-venv/bin/python -I -m py_compile") == 2
    assert workflow.count("PYTHONNOUSERSITE=1") == 3
    assert "PYTEST_ADDOPTS=" in workflow
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in workflow
    assert ".ci-venv/bin/python -I -m pytest" in workflow
    assert "-p pytest_asyncio.plugin" in workflow
    assert (
        "-c .gitea/pytest-ci.ini \\\n              tests/ -q --tb=short"
    ) in workflow

    lowered = workflow.lower()
    for forbidden in (
        "mirror-host",
        "prod-deploy",
        "self-hosted",
        "ubuntu-latest",
        "setup-python",
        "setup-uv",
        "curl ",
        "wget ",
        "install.sh",
        "pipx ",
        "command -v python",
        "command -v uv",
        'path="$path"',
        "--no-verify-hashes",
        "--no-binary",
        "--extra-index",
        "--find-links",
        "--config-file",
        "--sources",
        "pythonhome=",
        "pythonpath=",
        "pytest_plugins=",
    ):
        assert forbidden not in lowered


def _assert_manual_privileged_integration_contract(workflow: str) -> None:
    assert hashlib.sha256(workflow.encode()).hexdigest() == (
        INTEGRATION_WORKFLOW_SHA256
    )
    loaded = _load_ci_workflow(workflow)
    assert set(loaded) == {
        "name",
        "on",
        "permissions",
        "concurrency",
        "jobs",
    }
    assert loaded["on"] == {"workflow_dispatch": ""}
    assert loaded["permissions"] == {"contents": "read"}
    assert set(loaded["jobs"]) == {"integration", "compatibility"}
    integration_guard = (
        "${{ github.repository == 'N-MultiCloud/netbox-rpc' && "
        "github.ref == 'refs/heads/main' }}"
    )
    # The compatibility leg is restricted to canonical main because it runs
    # candidate code on `trusted-exact`, the dedicated credentials-free CI VM.
    # The integration leg stays on `mirror-host` because it drives a real
    # /opt/netbox deployment.
    compatibility_guard = (
        "${{ github.repository == 'N-MultiCloud/netbox-rpc' && "
        "github.ref == 'refs/heads/main' }}"
    )
    assert loaded["jobs"]["integration"]["if"] == integration_guard
    assert loaded["jobs"]["integration"]["runs-on"] == "mirror-host"
    assert loaded["jobs"]["compatibility"]["if"] == compatibility_guard
    assert loaded["jobs"]["compatibility"]["runs-on"] == "trusted-exact"
    assert workflow.count(CHECKOUT_ACTION) == 2
    assert workflow.count("ref: ${{ github.sha }}") == 2
    assert workflow.count("persist-credentials: false") == 2


def _assert_compatibility_job_is_pinned(workflow: str) -> None:
    assert workflow.count("NETBOX_TAG: ${{ matrix.netbox-tag }}") == 1
    assert workflow.count("refs/tags/${NETBOX_TAG}:refs/tags/${NETBOX_TAG}") == 1
    assert workflow.count("${NETBOX_TAG}^{commit}") == 1
    assert "github.actor" not in workflow
    assert "curl " not in workflow
    assert "requirements.txt" not in workflow
    assert "--require-hashes" in workflow
    assert "--only-binary=:all:" in workflow
    assert "--no-sources" in workflow
    assert "netbox-${NETBOX_VERSION}-ci.lock" in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert "fail-closed Gitea gate" not in workflow
    assert not re.search(r"(?:issue|PR|#)\s*#?\d+", workflow, re.IGNORECASE)


def _parse_lock(lock: str) -> dict[str, tuple[str, str, str]]:
    entries = {
        match.group("name"): (
            match.group("version"),
            match.group("wheel"),
            match.group("digest"),
        )
        for match in LOCK_ENTRY_RE.finditer(lock)
    }
    assert len(entries) == len(LOCKED_VERSIONS)
    assert list(entries) == sorted(entries)
    assert {name: values[0] for name, values in entries.items()} == LOCKED_VERSIONS

    requirement_lines = [
        line
        for line in lock.splitlines()
        if line and not line.startswith("#") and not line.startswith("    ")
    ]
    hash_lines = [line for line in lock.splitlines() if line.startswith("    --hash=")]
    wheel_lines = [line for line in lock.splitlines() if line.startswith("# wheel: ")]
    assert len(requirement_lines) == len(entries)
    assert len(hash_lines) == len(entries)
    assert len(wheel_lines) == len(entries)

    for version, wheel, digest in entries.values():
        assert version
        assert wheel.endswith(".whl")
        assert ".tar.gz" not in wheel and ".zip" not in wheel
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        if not wheel.endswith("-py3-none-any.whl"):
            assert "-cp312-" in wheel or "-cp311-abi3-" in wheel
            assert "manylinux" in wheel
            assert "x86_64.whl" in wheel
    return entries


def _assert_declared_requirements_satisfied(
    pyproject: str,
    entries: dict[str, tuple[str, str, str]],
) -> None:
    project = tomllib.loads(pyproject)["project"]
    requirements = [
        *project["dependencies"],
        *project["optional-dependencies"]["test"],
        *tomllib.loads(pyproject)["build-system"]["requires"],
        "pytest",
        "pytest-asyncio",
    ]
    marker_environment = default_environment()
    marker_environment.update(
        {
            "implementation_name": "cpython",
            "implementation_version": "3.12.14",
            "os_name": "posix",
            "platform_machine": "x86_64",
            "platform_python_implementation": "CPython",
            "platform_system": "Linux",
            "python_full_version": "3.12.14",
            "python_version": "3.12",
            "sys_platform": "linux",
        }
    )
    for raw_requirement in requirements:
        requirement = Requirement(raw_requirement)
        if requirement.marker is not None:
            assert requirement.marker.evaluate(environment=marker_environment)
        assert requirement.url is None
        name = canonicalize_name(requirement.name)
        assert name in entries
        locked_version = Version(entries[name][0])
        assert locked_version in requirement.specifier


def test_ordinary_ci_is_fail_closed_and_immutable() -> None:
    _assert_ci_contract(_read(WORKFLOW_PATH))
    pytest_config = PYTEST_CONFIG_PATH.read_bytes()
    assert hashlib.sha256(pytest_config).hexdigest() == PYTEST_CONFIG_SHA256
    assert pytest_config == b"[pytest]\npythonpath = ..\ntestpaths = ../tests\n"


def test_privileged_integration_is_manual_main_only_and_non_gating() -> None:
    workflow = _read(INTEGRATION_WORKFLOW_PATH)
    _assert_manual_privileged_integration_contract(workflow)
    _assert_compatibility_job_is_pinned(workflow)
    assert "Manual, non-gating diagnostics only" in workflow
    assert "never required pull-request evidence" in workflow


def test_ci_lock_is_canonical_wheel_only_closure() -> None:
    lock_bytes = LOCK_PATH.read_bytes()
    assert hashlib.sha256(lock_bytes).hexdigest() == LOCK_SHA256
    entries = _parse_lock(lock_bytes.decode("utf-8"))
    _assert_declared_requirements_satisfied(
        _read(ROOT / "pyproject.toml"),
        entries,
    )


def test_netbox_compatibility_locks_are_hash_pinned_binary_closures() -> None:
    for version in ("v4.5.8", "v4.6.5", "v4.7.0"):
        lock = _read(ROOT / f".gitea/deploy/netbox-{version}-ci.lock")
        assert lock.startswith("# This file was autogenerated by uv")
        assert "--hash=sha256:" in lock
        assert ".tar.gz" not in lock
        assert "--no-binary" not in lock


def test_public_ci_contract_docs_do_not_leak_private_tracker_ids() -> None:
    for path in (
        WORKFLOW_PATH,
        INTEGRATION_WORKFLOW_PATH,
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "docs" / "architecture.md",
    ):
        assert not re.search(r"\bnmulticloud-context#\d+\b", _read(path))
    agents = _read(ROOT / "AGENTS.md")
    architecture = _read(ROOT / "docs" / "architecture.md")
    readme = _read(ROOT / "README.md")
    for source in (agents, architecture, readme):
        normalized = " ".join(source.split())
        assert "defense in depth" in normalized
        assert "production-capable" in normalized
        assert "blocked/queued" in normalized
        assert "supplementary post-mirror evidence" in normalized
        assert "not canonical pre-merge evidence" in normalized


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        (
            "on:\n  workflow_dispatch:",
            "on:\n  push:\n  pull_request:\n  workflow_dispatch:",
        ),
        (
            "github.ref == 'refs/heads/main'",
            "github.ref != 'refs/heads/main'",
        ),
        (CHECKOUT_ACTION, "actions/checkout@v4"),
        ("persist-credentials: false", "persist-credentials: true"),
    ),
)
def test_manual_privileged_integration_rejects_trigger_or_ref_drift(
    needle: str,
    replacement: str,
) -> None:
    workflow = _read(INTEGRATION_WORKFLOW_PATH)
    assert needle in workflow
    mutated = workflow.replace(needle, replacement, 1)
    with pytest.raises((AssertionError, yaml.YAMLError)):
        _assert_manual_privileged_integration_contract(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        (
            "jobs:\n  test:",
            "jobs:\n"
            "  bypass:\n"
            "    name: Bypass\n"
            "    runs-on: ci-untrusted-python312\n"
            "    steps:\n"
            "      - name: Bypass\n"
            "        run: 'true'\n"
            "  test:",
        ),
        (
            "runs-on: ci-untrusted-python312",
            "runs-on: [ci-untrusted-python312, mirror-host]",
        ),
        (
            "runs-on: ci-untrusted-python312",
            "runs-on: ci-untrusted-python312\n    permissions:\n      contents: write",
        ),
        (
            "runs-on: ci-untrusted-python312",
            "runs-on: ci-untrusted-python312\n    runs-on: ci-untrusted-python312",
        ),
        (
            "runs-on: ci-untrusted-python312",
            "runs-on: &runner ci-untrusted-python312",
        ),
        (CHECKOUT_ACTION, "actions/checkout@v4"),
        ("ref: ${{ github.sha }}", "ref: ${{ github.ref }}"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("Python 3.12.14", "Python 3.12.15"),
        (
            "uv 0.12.5 (x86_64-unknown-linux-gnu)",
            "uv 0.12.4 (x86_64-unknown-linux-gnu)",
        ),
        ("/usr/local/bin/python3.12", "$(command -v python3.12)"),
        ("/usr/local/bin/uv", "$(command -v uv)"),
        ("UV_PYTHON_DOWNLOADS: never", "UV_PYTHON_DOWNLOADS: automatic"),
        ("/usr/bin/env -i", "/usr/bin/env"),
        ("--require-hashes", "--no-verify-hashes"),
        ("--only-binary=:all:", "--no-binary=:all:"),
        ("--no-sources", "--sources"),
        ("--no-config", "--config-file pyproject.toml"),
        ("https://pypi.org/simple", "https://packages.invalid/simple"),
        ("PYTEST_ADDOPTS=", "PYTEST_ADDOPTS=--collect-only"),
        (
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=0",
        ),
        (".ci-venv/bin/python -I -m pytest", ".ci-venv/bin/python -m pytest"),
        ("-p pytest_asyncio.plugin", "-p no:pytest_asyncio.plugin"),
        (
            "/usr/bin/env -i PYTHONNOUSERSITE=1",
            "/usr/bin/env -i PYTHONPATH=/tmp PYTHONNOUSERSITE=1",
        ),
        ("tests/ -q --tb=short", "tests/ --collect-only -q --tb=short"),
        (
            "# Run the netbox-rpc test suite",
            "# curl https://example.invalid/install.sh\n# Run the netbox-rpc test suite",
        ),
    ),
)
def test_ci_contract_rejects_security_regressions(
    needle: str,
    replacement: str,
) -> None:
    workflow = _read(WORKFLOW_PATH)
    assert needle in workflow
    mutated = workflow.replace(needle, replacement, 1)
    with pytest.raises((AssertionError, yaml.YAMLError)):
        _assert_ci_contract(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        ("pytest==9.1.1", "pytest>=9.1.1"),
        ("--hash=sha256:37a86", "--hash=sha256:07a86"),
        ("pytest-9.1.1-py3-none-any.whl", "pytest-9.1.1.tar.gz"),
        ("requests==2.34.2", "requests @ https://example.invalid/requests.whl"),
    ),
)
def test_ci_lock_rejects_mutable_or_noncanonical_inputs(
    needle: str,
    replacement: str,
) -> None:
    lock = _read(LOCK_PATH)
    assert needle in lock
    mutated = lock.replace(needle, replacement, 1)
    with pytest.raises(AssertionError):
        assert hashlib.sha256(mutated.encode()).hexdigest() == LOCK_SHA256
        _parse_lock(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        ("testpaths = ../tests", "addopts = --collect-only"),
        ("pythonpath = ..", "pythonpath = /tmp"),
    ),
)
def test_pytest_config_rejects_bypass_mutations(
    needle: str,
    replacement: str,
) -> None:
    config = _read(PYTEST_CONFIG_PATH)
    assert needle in config
    mutated = config.replace(needle, replacement, 1)
    assert hashlib.sha256(mutated.encode()).hexdigest() != PYTEST_CONFIG_SHA256


@pytest.mark.parametrize(
    "replacement",
    (
        '"requests>=999"',
        "\"requests>=2.32; python_version < '3.12'\"",
    ),
)
def test_lock_rejects_unsatisfied_direct_specs_or_markers(replacement: str) -> None:
    pyproject = _read(ROOT / "pyproject.toml")
    assert '"requests>=2.32"' in pyproject
    mutated = pyproject.replace('"requests>=2.32"', replacement, 1)
    entries = _parse_lock(_read(LOCK_PATH))
    with pytest.raises(AssertionError):
        _assert_declared_requirements_satisfied(mutated, entries)
