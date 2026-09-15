import hashlib
import re
import subprocess
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
GITHUB_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "test.yml"
LOCK_PATH = ROOT / ".gitea" / "ci-requirements.lock"
PYTEST_CONFIG_PATH = ROOT / ".gitea" / "pytest-ci.ini"
CHECKOUT_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP_UV_ACTION = (
    "https://github.com/astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990"
)
SETUP_UV_VERSION = "0.12.5"
SETUP_UV_CHECKSUM = "68a509da24b06b4223a1c0175fb5eb5bc79342b76cbeff0cfe51ac3f5b17b6b2"
LOCK_SHA256 = "e26ad1915e48f6a20916ddb2c72ad3bda27b4c36266d7ec6249939a2fda97842"
PYTEST_CONFIG_SHA256 = (
    "7f0a35baee4c8d0d2b3fce080490ec0a53f352d784a444ee91930f1728e9fc12"
)
INTEGRATION_WORKFLOW_SHA256 = (
    "0bab9f5902d0c6e99f9ffabdd831e88f519467951bdcba273754c6a156a354da"
)
EXPECTED_COMPATIBILITY_MATRIX = [
    {
        "netbox-version": "v4.5.8",
        "netbox-tag": "v4.5.8",
        "netbox-ref": "75e1b86613792458b4d4c8d0cbbfc94df16cfaaf",
        "compat-db": "netbox_rpc_compat_n458",
        "redis-port": "16388",
        "redis-tasks-db": "0",
        "redis-cache-db": "1",
    },
    {
        "netbox-version": "v4.6.5",
        "netbox-tag": "v4.6.5",
        "netbox-ref": "ebee3578b90901ba69ea646815f9b0662f627726",
        "compat-db": "netbox_rpc_compat_n465",
        "redis-port": "16389",
        "redis-tasks-db": "0",
        "redis-cache-db": "1",
    },
    {
        "netbox-version": "v4.7.0",
        "netbox-tag": "v4.7.0",
        "netbox-ref": "5f06007e4c9bacc93ce17c1e645fc1143d60df3d",
        "compat-db": "netbox_rpc_compat_n470",
        "redis-port": "16390",
        "redis-tasks-db": "0",
        "redis-cache-db": "1",
    },
]
EXPECTED_GITHUB_MATRIX = [
    {key: entry[key] for key in ("netbox-version", "netbox-tag", "netbox-ref")}
    for entry in EXPECTED_COMPATIBILITY_MATRIX
]
EXPECTED_SOURCE_BUILD_LOCK = (
    "# Hash-pinned build backend for source-only dependencies in older NetBox locks.\n"
    "# Install this wheel before the NetBox closure, then build dependency source\n"
    "# archives with --no-build-isolation so no undeclared build requirement can be\n"
    "# resolved or downloaded.\n"
    "setuptools==83.0.0 \\\n"
    "    --hash=sha256:29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3\n"
)
EXPECTED_GITHUB_INSTALL_COMMANDS = (
    "python -m pip install \\\n"
    "  --require-hashes \\\n"
    "  --only-binary=:all: \\\n"
    "  --no-cache-dir \\\n"
    "  --disable-pip-version-check \\\n"
    "  -r plugin/.gitea/deploy/netbox-source-build.lock",
    "python -m pip install \\\n"
    "  --require-hashes \\\n"
    "  --no-build-isolation \\\n"
    "  --no-cache-dir \\\n"
    "  --disable-pip-version-check \\\n"
    '  -r "plugin/.gitea/deploy/netbox-${NETBOX_VERSION}-ci.lock"',
    "python -m pip install --no-deps --no-build-isolation -e ./plugin",
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


def _named_step_run(job: dict, name: str) -> str:
    return _named_step(job, name)["run"]


def _named_step(job: dict, name: str) -> dict:
    matches = tuple(step for step in job["steps"] if step.get("name") == name)
    assert len(matches) == 1
    return matches[0]


def _pip_install_commands(script: str) -> tuple[str, ...]:
    return tuple(
        re.findall(r"^python -m pip install(?:.*(?:\n  .*)*)$", script, re.MULTILINE)
    )


def _load_ci_workflow(workflow: str) -> dict:
    forbidden_tokens = (
        AliasToken,
        AnchorToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
        TagToken,
    )
    assert not any(isinstance(token, forbidden_tokens) for token in yaml.scan(workflow))
    return _load_unique_yaml(workflow)


def _load_unique_yaml(workflow: str) -> dict:
    loaded = yaml.load(workflow, Loader=_UniqueNoAliasLoader)
    assert isinstance(loaded, dict)
    return loaded


def _assert_optional_integration_preflight(job: dict) -> None:
    steps = job["steps"]
    assert [step["name"] for step in steps[:2]] == [
        "Preflight (soft-skip if unconfigured)",
        "Checkout",
    ]
    preflight, checkout = steps[:2]
    venv_check = preflight["run"].index('if [ ! -x "${NETBOX_ROOT}/venv/bin/python" ]')
    secret_check = preflight["run"].index('if [ -z "${NETBOX_DB_PASSWORD}" ]')
    node_check = preflight["run"].index("if ! command -v node")
    assert venv_check < secret_check < node_check
    assert "if ! command -v node" in preflight["run"]
    assert (
        "::error::Node is required for checkout on configured mirror-host."
        in preflight["run"]
    )
    assert preflight["run"].count('echo "run=true" >> "$GITHUB_OUTPUT"') == 1
    assert "actions/" not in preflight["run"]
    assert "github.sha" not in preflight["run"]
    assert checkout["if"] == "steps.preflight.outputs.run == 'true'"


def _assert_exact_toolchain_observability(job: dict) -> None:
    _assert_private_toolchain_step_order(job)
    _assert_private_toolchain_prepare_step(job)
    _assert_pinned_uv_setup_step(job)
    provision = _assert_python_provision_step(job)
    _assert_python_provision_source(provision["run"])
    _assert_platform_probe_source(provision["run"])
    _assert_exact_identity_probe_order(provision["run"])
    _assert_private_toolchain_consumers_and_cleanup(job)


def _assert_private_toolchain_step_order(job: dict) -> None:
    steps = job["steps"]
    names = [step["name"] for step in steps]
    expected_order = (
        "Preflight (fail if host services are unavailable)",
        "Prepare private toolchain root",
        "Install pinned uv",
        "Provision exact task-private Python 3.12",
        "Provision a UTF8 compatibility database",
        "Start isolated authenticated Redis",
        "Checkout plugin",
        "Check out NetBox",
        "Install NetBox and plugin",
        "Run compatibility checks (fresh database)",
        "Stop isolated Redis",
        "Remove private toolchain",
    )
    assert tuple(names) == expected_order


def _assert_private_toolchain_prepare_step(job: dict) -> None:
    prepare = _named_step(job, "Prepare private toolchain root")
    assert set(prepare) == {"name", "id", "shell", "run"}
    assert prepare["id"] == "toolchain"
    assert prepare["shell"] == "bash"
    assert (
        'created_root="$(/usr/bin/mktemp -d '
        '"${runner_temp}/netbox-rpc-toolchain.XXXXXX")"' in prepare["run"]
    )
    assert 'toolchain_root="$(/usr/bin/realpath -e "$created_root")"' in prepare["run"]
    assert (
        'test "$(/usr/bin/dirname "$toolchain_root")" = "$runner_temp"'
        in prepare["run"]
    )
    assert "netbox-rpc-toolchain.??????" in prepare["run"]
    assert prepare["run"].count("-m 0700") == 1
    assert prepare["run"].count("chmod 0700") == 1
    assert "trap cleanup_failed_prepare ERR INT TERM" in prepare["run"]
    assert "trap - ERR INT TERM" in prepare["run"]
    assert "printf 'temp=%s\\n' \"$toolchain_root/tmp\"" in prepare["run"]
    _assert_prepare_trap_order(prepare["run"])


def _assert_prepare_trap_order(script: str) -> None:
    mktemp = script.index('created_root="$(/usr/bin/mktemp -d ')
    install_trap = script.index("trap cleanup_failed_prepare ERR INT TERM")
    canonicalize = script.index(
        'toolchain_root="$(/usr/bin/realpath -e "$created_root")"'
    )
    first_output = script.index("printf 'root=%s\\n'")
    last_output = script.index("printf 'temp=%s\\n'")
    disarm = script.rindex("trap - ERR INT TERM")
    assert mktemp < install_trap < canonicalize < first_output < last_output < disarm


def _assert_pinned_uv_setup_step(job: dict) -> None:
    setup = _named_step(job, "Install pinned uv")
    assert set(setup) == {"name", "id", "uses", "env", "with"}
    assert setup["id"] == "uv"
    assert setup["uses"] == SETUP_UV_ACTION
    assert setup["env"] == {
        "RUNNER_TEMP": "${{ steps.toolchain.outputs.temp }}",
        "TMPDIR": "${{ steps.toolchain.outputs.temp }}",
        "RUNNER_TOOL_CACHE": "${{ steps.toolchain.outputs.tool_cache }}",
        "UV_CACHE_DIR": "${{ steps.toolchain.outputs.uv_cache }}",
        "UV_PYTHON_INSTALL_DIR": "${{ steps.toolchain.outputs.uv_python }}",
        "UV_TOOL_DIR": "${{ steps.toolchain.outputs.uv_tools }}",
        "UV_TOOL_BIN_DIR": "${{ steps.toolchain.outputs.uv_tool_bin }}",
        "UV_NO_MODIFY_PATH": "1",
    }
    assert setup["with"] == {
        "version": SETUP_UV_VERSION,
        "python-version": "3.12.14",
        "checksum": SETUP_UV_CHECKSUM,
        "github-token": "",
        "download-from-astral-mirror": "false",
        "enable-cache": "false",
        "add-problem-matchers": "false",
    }


def _assert_python_provision_step(job: dict) -> dict:
    provision = _named_step(job, "Provision exact task-private Python 3.12")
    assert set(provision) == {"name", "id", "shell", "env", "run"}
    assert provision["id"] == "interpreter"
    assert provision["shell"] == "bash"
    assert provision["env"] == {
        "TOOLCHAIN_ROOT": "${{ steps.toolchain.outputs.root }}",
        "UV_BIN": "${{ steps.uv.outputs.uv-path }}",
        "UV_CACHE_DIR": "${{ steps.toolchain.outputs.uv_cache }}",
        "UV_PYTHON_INSTALL_DIR": "${{ steps.toolchain.outputs.uv_python }}",
        "UV_TOOL_DIR": "${{ steps.toolchain.outputs.uv_tools }}",
        "UV_TOOL_BIN_DIR": "${{ steps.toolchain.outputs.uv_tool_bin }}",
        "TMPDIR": "${{ steps.toolchain.outputs.temp }}",
        "UV_NO_CONFIG": "1",
        "UV_NO_SOURCES": "1",
        "UV_PYTHON_INSTALL_BIN": "0",
        "UV_PYTHON_DOWNLOADS": "manual",
    }
    return provision


def _assert_python_provision_source(script: str) -> None:
    assert script.count('"$python_bin" --version') == 1
    assert script.count('"$uv_bin" --version') == 1
    assert script.count('"$toolchain_root"/*') == 2
    assert '"$uv_bin" python install 3.12.14' in script
    assert "--no-bin" in script
    assert "--no-config" in script
    assert "--no-cache" in script
    assert "--no-progress" in script
    assert (
        'python_bin="$(UV_PYTHON_DOWNLOADS=never "$uv_bin" python find '
        '--managed-python 3.12.14)"' in script
    )
    assert 'UV_PYTHON_DOWNLOADS=never "$uv_bin" venv' in script
    assert "printf 'python_bin=%s\\n'" in script
    assert "printf 'uv_bin=%s\\n'" in script


def _assert_platform_probe_source(script: str) -> None:
    assert "\"$python_bin\" -I -S - <<'PY'" in script
    assert 'platform.python_implementation() != "CPython"' in script
    assert "sys.version_info[:3] != (3, 12, 14)" in script
    assert 'platform.machine() != "x86_64"' in script
    assert 'libc_name != "glibc"' in script
    assert 'tuple(map(int, libc_version.split("."))) < (2, 34)' in script


def _assert_exact_identity_probe_order(script: str) -> None:
    python_error = script.index("Missing exact Python executable")
    python_probe_error = script.index("Exact Python version probe failed")
    python_print = script.index("Python identity: %s")
    python_test = script.index('test "$python_identity" = "Python 3.12.14"')
    uv_error = script.index("Missing exact uv executable")
    uv_probe_error = script.index("Exact uv version probe failed")
    uv_print = script.index("uv identity: %s")
    uv_test = script.index(
        'test "$uv_identity" = "uv 0.12.5 (x86_64-unknown-linux-gnu)"'
    )
    assert python_error < python_probe_error < python_print < python_test
    assert uv_error < uv_probe_error < uv_print < uv_test


def _assert_private_toolchain_consumers_and_cleanup(job: dict) -> None:
    install = _named_step(job, "Install NetBox and plugin")
    assert install["env"] == {
        "UV_BIN": "${{ steps.interpreter.outputs.uv_bin }}",
        "TMPDIR": "${{ steps.toolchain.outputs.temp }}",
    }
    assert install["run"].count('UV_PYTHON_DOWNLOADS=never "$UV_BIN" pip install') == 3

    cleanup = _named_step(job, "Remove private toolchain")
    assert cleanup["if"] == "always()"
    assert cleanup["env"] == {"TOOLCHAIN_ROOT": "${{ steps.toolchain.outputs.root }}"}
    assert 'runner_temp="$(/usr/bin/realpath -e "$RUNNER_TEMP")"' in cleanup["run"]
    assert 'workspace="$(/usr/bin/realpath -e "$GITHUB_WORKSPACE")"' in cleanup["run"]
    assert (
        'toolchain_root="$(/usr/bin/realpath -e "$TOOLCHAIN_ROOT")"' in cleanup["run"]
    )
    assert 'test ! -L "$TOOLCHAIN_ROOT"' in cleanup["run"]
    assert 'test "$toolchain_root" != "$workspace"' in cleanup["run"]
    assert (
        'test "$(/usr/bin/dirname "$toolchain_root")" = "$runner_temp"'
        in cleanup["run"]
    )
    assert "netbox-rpc-toolchain.??????" in cleanup["run"]
    assert '/usr/bin/rm -rf -- "$toolchain_root"' in cleanup["run"]


def _run_bash(script: str, environment: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", script],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_fake_executable(path: Path, identity: str, status: int = 0) -> None:
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$#" -ne 1 ] || [ "$1" != "--version" ]; then\n'
        "  printf '%s\\n' 'unexpected version-probe arguments' >&2\n"
        "  exit 64\n"
        "fi\n"
        f"printf '%s\\n' '{identity}'\n"
        f"exit {status}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fake_uv_provisioner(path: Path, python_bin: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then\n'
        "  printf '%s\\n' 'uv 0.12.5 (x86_64-unknown-linux-gnu)'\n"
        "  exit 0\n"
        "fi\n"
        'if [ "$#" -eq 7 ] && [ "$1" = "python" ] && [ "$2" = "install" ] '
        '&& [ "$3" = "3.12.14" ] && [ "$4" = "--no-bin" ] '
        '&& [ "$5" = "--no-config" ] && [ "$6" = "--no-cache" ] '
        '&& [ "$7" = "--no-progress" ]; then\n'
        '  test -n "${TMPDIR:-}" && test -d "$TMPDIR" || exit 65\n'
        '  temp_probe="$(/usr/bin/mktemp "$TMPDIR/uv-python-stage.XXXXXX")" || exit 66\n'
        '  case "$temp_probe" in "$TMPDIR"/*) ;; *) exit 67 ;; esac\n'
        '  /usr/bin/rm -f -- "$temp_probe"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$#" -eq 4 ] && [ "$1" = "python" ] && [ "$2" = "find" ] '
        '&& [ "$3" = "--managed-python" ] && [ "$4" = "3.12.14" ]; then\n'
        f"  printf '%s\\n' '{python_bin}'\n"
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "venv" ]; then\n'
        "  exit 0\n"
        "fi\n"
        "printf '%s\\n' 'unexpected uv arguments' >&2\n"
        "exit 64\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fake_python_runtime(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then\n'
        "  printf '%s\\n' 'Python 3.12.14'\n"
        "  exit 0\n"
        "fi\n"
        'if [ "$#" -eq 3 ] && [ "$1" = "-I" ] && [ "$2" = "-S" ] '
        '&& [ "$3" = "-" ]; then\n'
        '  probe="$(/usr/bin/cat)"\n'
        "  case \"$probe\" in *'platform.python_implementation() != \"CPython\"'*) ;; *) printf '%s\\n' 'invalid platform probe' >&2; exit 68 ;; esac\n"
        "  case \"$probe\" in *'sys.version_info[:3] != (3, 12, 14)'*) ;; *) printf '%s\\n' 'invalid platform probe' >&2; exit 68 ;; esac\n"
        "  case \"$probe\" in *'platform.machine() != \"x86_64\"'*) ;; *) printf '%s\\n' 'invalid platform probe' >&2; exit 68 ;; esac\n"
        "  case \"$probe\" in *'libc_name != \"glibc\"'*) ;; *) printf '%s\\n' 'invalid platform probe' >&2; exit 68 ;; esac\n"
        "  case \"$probe\" in *'tuple(map(int, libc_version.split(\".\"))) < (2, 34)'*) ;; *) printf '%s\\n' 'invalid platform probe' >&2; exit 68 ;; esac\n"
        "  exit 0\n"
        "fi\n"
        "printf '%s\\n' 'unexpected Python arguments' >&2\n"
        "exit 64\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _toolchain_identity_script(job: dict) -> str:
    provision = _named_step_run(job, "Provision exact task-private Python 3.12")
    uv_start = provision.index("# Verify the contained setup action output")
    uv_end = provision.index('"$uv_bin" python install')
    python_start = provision.index("# Verify the contained managed-interpreter output")
    python_end = provision.index('"$python_bin" -I -S -')
    identity_script = provision[uv_start:uv_end] + provision[python_start:python_end]
    return (
        "set -euo pipefail\n"
        'python_bin="${TEST_PYTHON_BIN}"\n'
        'uv_bin="${TEST_UV_BIN}"\n'
        f"{identity_script}"
    )


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
    assert loaded["concurrency"] == {
        "group": "netbox-rpc-integration",
        "cancel-in-progress": "false",
    }
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
    integration = loaded["jobs"]["integration"]
    compatibility = loaded["jobs"]["compatibility"]
    assert integration["if"] == integration_guard
    assert integration["runs-on"] == "mirror-host"
    assert integration["timeout-minutes"] == "30"
    _assert_optional_integration_preflight(integration)
    assert compatibility["if"] == compatibility_guard
    assert compatibility["runs-on"] == "trusted-exact"
    _assert_exact_toolchain_observability(compatibility)
    assert workflow.count(CHECKOUT_ACTION) == 2
    assert workflow.count("ref: ${{ github.sha }}") == 2
    assert workflow.count("persist-credentials: false") == 2


def _assert_compatibility_job_is_pinned(workflow: str) -> None:
    loaded = _load_ci_workflow(workflow)
    matrix = loaded["jobs"]["compatibility"]["strategy"]["matrix"]["include"]
    assert matrix == EXPECTED_COMPATIBILITY_MATRIX
    _assert_compatibility_source_identity(workflow)
    _assert_compatibility_install_lockdown(workflow)
    _assert_compatibility_cleanup_order(workflow)


def _assert_compatibility_source_identity(workflow: str) -> None:
    assert workflow.count("NETBOX_TAG: ${{ matrix.netbox-tag }}") == 1
    assert workflow.count("refs/tags/${NETBOX_TAG}:refs/tags/${NETBOX_TAG}") == 1
    assert workflow.count("${NETBOX_TAG}^{commit}") == 1
    assert "github.actor" not in workflow
    assert "curl " not in workflow
    assert "requirements.txt" not in workflow


def _assert_compatibility_install_lockdown(workflow: str) -> None:
    assert "--require-hashes" in workflow
    assert "--only-binary=:all:" in workflow
    assert "--no-build-isolation" in workflow
    assert "--no-sources" in workflow
    assert "netbox-source-build.lock" in workflow
    assert "netbox-${NETBOX_VERSION}-ci.lock" in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert "fail-closed Gitea gate" not in workflow
    assert not re.search(r"(?:issue|PR|#)\s*#?\d+", workflow, re.IGNORECASE)


def _assert_compatibility_cleanup_order(workflow: str) -> None:
    redis_password_export = workflow.index("printf 'NETBOX_REDIS_PASSWORD=%s\\n'")
    redis_pidfile_export = workflow.index("printf 'NETBOX_REDIS_PIDFILE=%s\\n'")
    readiness_loop = workflow.index("for attempt in {1..20}")
    assert redis_password_export < readiness_loop
    assert redis_pidfile_export < readiness_loop
    build_backend_install = workflow.index("netbox-source-build.lock")
    netbox_closure_install = workflow.index("netbox-${NETBOX_VERSION}-ci.lock")
    assert build_backend_install < netbox_closure_install
    loaded = _load_ci_workflow(workflow)
    steps = loaded["jobs"]["compatibility"]["steps"]
    names = [step["name"] for step in steps]
    redis_cleanup = _named_step(loaded["jobs"]["compatibility"], "Stop isolated Redis")
    toolchain_cleanup = _named_step(
        loaded["jobs"]["compatibility"], "Remove private toolchain"
    )
    assert redis_cleanup["if"] == "always()"
    assert toolchain_cleanup["if"] == "always()"
    assert names.index("Stop isolated Redis") < names.index("Remove private toolchain")


def _assert_github_compatibility_contract(workflow: str) -> None:
    loaded = _load_unique_yaml(workflow)
    job = loaded["jobs"]["integration"]
    assert job["strategy"]["matrix"]["include"] == EXPECTED_GITHUB_MATRIX
    install = _named_step_run(job, "Install NetBox + plugin")
    assert _pip_install_commands(install) == EXPECTED_GITHUB_INSTALL_COMMANDS


def _assert_source_build_lock(lock: str) -> None:
    assert lock == EXPECTED_SOURCE_BUILD_LOCK


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


def test_github_compatibility_matrix_and_install_are_pinned() -> None:
    _assert_github_compatibility_contract(_read(GITHUB_WORKFLOW_PATH))


def test_github_compatibility_install_rejects_flags_moved_between_stages() -> None:
    workflow = _read(GITHUB_WORKFLOW_PATH)
    swapped_stage_flags = (
        workflow.replace("--only-binary=:all:", "INSTALL_FLAG_PLACEHOLDER", 1)
        .replace("--no-build-isolation", "--only-binary=:all:", 1)
        .replace("INSTALL_FLAG_PLACEHOLDER", "--no-build-isolation", 1)
    )
    moved_hash_flag = workflow.replace(
        "            --require-hashes \\\n            --only-binary=:all:",
        "            --only-binary=:all:",
        1,
    ).replace(
        "            --require-hashes \\\n            --no-build-isolation",
        "            --require-hashes \\\n"
        "            --require-hashes \\\n"
        "            --no-build-isolation",
        1,
    )

    for mutation in (swapped_stage_flags, moved_hash_flag):
        with pytest.raises(AssertionError):
            _assert_github_compatibility_contract(mutation)


def test_ci_lock_is_canonical_wheel_only_closure() -> None:
    lock_bytes = LOCK_PATH.read_bytes()
    assert hashlib.sha256(lock_bytes).hexdigest() == LOCK_SHA256
    entries = _parse_lock(lock_bytes.decode("utf-8"))
    _assert_declared_requirements_satisfied(
        _read(ROOT / "pyproject.toml"),
        entries,
    )


def test_netbox_compatibility_locks_are_hash_pinned_closures() -> None:
    for version in ("v4.5.8", "v4.6.5", "v4.7.0"):
        lock = _read(ROOT / f".gitea/deploy/netbox-{version}-ci.lock")
        assert lock.startswith("# This file was autogenerated by uv")
        assert "--hash=sha256:" in lock
        assert "--no-binary" not in lock


def test_netbox_source_build_backend_is_exact_and_hash_pinned() -> None:
    lock = _read(ROOT / ".gitea/deploy/netbox-source-build.lock")
    _assert_source_build_lock(lock)


def test_netbox_source_build_backend_rejects_additional_packages() -> None:
    lock = _read(ROOT / ".gitea/deploy/netbox-source-build.lock")
    extra_requirement = "wheel==1.0.0 \\\n    --hash=sha256:" + "0" * 64 + "\n"
    with pytest.raises(AssertionError):
        _assert_source_build_lock(lock + extra_requirement)


def test_public_ci_contract_docs_do_not_leak_private_tracker_ids() -> None:
    for path in (
        WORKFLOW_PATH,
        INTEGRATION_WORKFLOW_PATH,
        GITHUB_WORKFLOW_PATH,
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "docs" / "architecture.md",
    ):
        assert not re.search(r"\bnmulticloud-context#\d+\b", _read(path))
    agents = _read(ROOT / "AGENTS.md")
    claude = _read(ROOT / "CLAUDE.md")
    architecture = _read(ROOT / "docs" / "architecture.md")
    readme = _read(ROOT / "README.md")
    for source in (agents, architecture, readme):
        normalized = " ".join(source.split())
        assert "defense in depth" in normalized
        assert "production-capable" in normalized
        assert "blocked/queued" in normalized
        assert "supplementary post-mirror evidence" in normalized
        assert "not canonical pre-merge evidence" in normalized
    for source in (agents, claude, architecture, readme):
        normalized = " ".join(source.split())
        assert "mode-0700 task-private" in normalized
        assert "exact uv 0.12.5" in normalized
        assert "exact CPython 3.12.14" in normalized
        assert "managed-Python catalog" in normalized


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
        ("if ! command -v node", "if command -v node"),
        (
            "if: steps.preflight.outputs.run == 'true'\n        uses: actions/checkout",
            "if: always()\n        uses: actions/checkout",
        ),
        (
            "- name: Preflight (soft-skip if unconfigured)",
            "- name: Late preflight (soft-skip if unconfigured)",
        ),
        (
            'echo "run=true" >> "$GITHUB_OUTPUT"',
            'echo "run=false" >> "$GITHUB_OUTPUT"',
        ),
    ),
)
def test_optional_integration_rejects_preflight_bypass(
    needle: str,
    replacement: str,
) -> None:
    workflow = _read(INTEGRATION_WORKFLOW_PATH)
    assert needle in workflow
    mutated = workflow.replace(needle, replacement, 1)
    job = _load_ci_workflow(mutated)["jobs"]["integration"]
    with pytest.raises((AssertionError, KeyError, ValueError)):
        _assert_optional_integration_preflight(job)


@pytest.mark.parametrize(
    ("has_venv", "db_password", "expected_notice"),
    (
        (False, "configured", "NetBox venv not found"),
        (True, "", "NETBOX_DB_PASSWORD secret is not configured"),
    ),
)
def test_optional_integration_soft_skips_only_when_unconfigured(
    tmp_path: Path,
    has_venv: bool,
    db_password: str,
    expected_notice: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["integration"]
    preflight = _named_step_run(job, "Preflight (soft-skip if unconfigured)")
    netbox_root = tmp_path / "netbox"
    if has_venv:
        python_bin = netbox_root / "venv" / "bin" / "python"
        python_bin.parent.mkdir(parents=True)
        _write_fake_executable(python_bin, "unused")
    github_output = tmp_path / "github-output"
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()

    result = _run_bash(
        preflight,
        {
            "PATH": str(empty_path),
            "GITHUB_OUTPUT": str(github_output),
            "NETBOX_ROOT": str(netbox_root),
            "NETBOX_DB_PASSWORD": db_password,
        },
    )

    assert result.returncode == 0
    assert expected_notice in result.stdout
    assert result.stderr == ""
    assert github_output.read_text(encoding="utf-8") == "run=false\n"


def test_optional_integration_configured_host_requires_node(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["integration"]
    preflight = _named_step_run(job, "Preflight (soft-skip if unconfigured)")
    netbox_root = tmp_path / "netbox"
    python_bin = netbox_root / "venv" / "bin" / "python"
    python_bin.parent.mkdir(parents=True)
    _write_fake_executable(python_bin, "unused")
    github_output = tmp_path / "github-output"
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()

    result = _run_bash(
        preflight,
        {
            "PATH": str(empty_path),
            "GITHUB_OUTPUT": str(github_output),
            "NETBOX_ROOT": str(netbox_root),
            "NETBOX_DB_PASSWORD": "configured",
        },
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "::error::Node is required for checkout on configured mirror-host.\n"
    )
    assert not github_output.exists()


def test_optional_integration_configured_host_enables_checkout(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["integration"]
    preflight = _named_step_run(job, "Preflight (soft-skip if unconfigured)")
    netbox_root = tmp_path / "netbox"
    python_bin = netbox_root / "venv" / "bin" / "python"
    python_bin.parent.mkdir(parents=True)
    _write_fake_executable(python_bin, "unused")
    executable_path = tmp_path / "bin"
    executable_path.mkdir()
    _write_fake_executable(executable_path / "node", "unused")
    github_output = tmp_path / "github-output"

    result = _run_bash(
        preflight,
        {
            "PATH": str(executable_path),
            "GITHUB_OUTPUT": str(github_output),
            "NETBOX_ROOT": str(netbox_root),
            "NETBOX_DB_PASSWORD": "configured",
        },
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert github_output.read_text(encoding="utf-8") == "run=true\n"


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        (
            SETUP_UV_ACTION,
            "https://github.com/astral-sh/setup-uv@v8",
        ),
        (SETUP_UV_CHECKSUM, "0" * 64),
        ('version: "0.12.5"', 'version: "latest"'),
        ('python-version: "3.12.14"', 'python-version: "3.12"'),
        ('github-token: ""', "github-token: ${{ github.token }}"),
        ("enable-cache: false", "enable-cache: true"),
        ("UV_PYTHON_DOWNLOADS: manual", "UV_PYTHON_DOWNLOADS: automatic"),
        ('UV_PYTHON_INSTALL_BIN: "0"', 'UV_PYTHON_INSTALL_BIN: "1"'),
        ('UV_NO_MODIFY_PATH: "1"', 'UV_NO_MODIFY_PATH: "0"'),
        ("--no-bin", "--default"),
        ("netbox-rpc-toolchain.XXXXXX", "toolchain.XXXXXX"),
        ("/usr/bin/chmod 0700", "/usr/bin/chmod 0755"),
        (
            "- name: Remove private toolchain\n        if: always()",
            "- name: Remove private toolchain\n        if: success()",
        ),
    ),
)
def test_task_private_toolchain_rejects_pin_or_isolation_drift(
    needle: str,
    replacement: str,
) -> None:
    workflow = _read(INTEGRATION_WORKFLOW_PATH)
    assert needle in workflow
    mutated = workflow.replace(needle, replacement, 1)
    job = _load_ci_workflow(mutated)["jobs"]["compatibility"]
    with pytest.raises((AssertionError, KeyError, ValueError)):
        _assert_exact_toolchain_observability(job)


def test_prepare_and_cleanup_private_toolchain_behavior(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    github_output = tmp_path / "github-output"
    prepare = _named_step_run(job, "Prepare private toolchain root")

    result = _run_bash(
        prepare,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(github_output),
        },
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    outputs = dict(
        line.split("=", 1)
        for line in github_output.read_text(encoding="utf-8").splitlines()
    )
    toolchain_root = Path(outputs["root"])
    assert toolchain_root.parent == runner_temp.resolve()
    assert re.fullmatch(r"netbox-rpc-toolchain\.[A-Za-z0-9]{6}", toolchain_root.name)
    assert toolchain_root.stat().st_mode & 0o777 == 0o700
    for key in (
        "temp",
        "tool_cache",
        "uv_cache",
        "uv_python",
        "uv_tools",
        "uv_tool_bin",
    ):
        private_directory = Path(outputs[key])
        assert private_directory.parent == toolchain_root
        assert private_directory.stat().st_mode & 0o777 == 0o700

    marker = toolchain_root / "marker"
    marker.write_text("private", encoding="utf-8")
    cleanup = _named_step_run(job, "Remove private toolchain")
    cleanup_result = _run_bash(
        cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(toolchain_root),
        },
    )

    assert cleanup_result.returncode == 0
    assert cleanup_result.stdout == ""
    assert cleanup_result.stderr == ""
    assert not toolchain_root.exists()


def test_private_toolchain_cleanup_refuses_workspace(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    workspace = runner_temp / "netbox-rpc-toolchain.ABC123"
    workspace.mkdir()
    cleanup = _named_step_run(job, "Remove private toolchain")

    result = _run_bash(
        cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(workspace),
        },
    )

    assert result.returncode != 0
    assert workspace.is_dir()

    workspace_guard = 'test "$toolchain_root" != "$workspace"'
    assert cleanup.count(workspace_guard) == 1
    mutated_cleanup = cleanup.replace(workspace_guard, ":", 1)
    mutation_result = _run_bash(
        mutated_cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(workspace),
        },
    )

    assert mutation_result.returncode == 0
    assert mutation_result.stdout == ""
    assert mutation_result.stderr == ""
    assert not workspace.exists()


def test_prepare_private_toolchain_failure_removes_unpublished_root(
    tmp_path: Path,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    missing_output = tmp_path / "missing-parent" / "github-output"
    prepare = _named_step_run(job, "Prepare private toolchain root")

    result = _run_bash(
        prepare,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(missing_output),
        },
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert not tuple(runner_temp.glob("netbox-rpc-toolchain.??????"))


def test_prepare_failed_realpath_uses_raw_created_root(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    prepare = _named_step_run(job, "Prepare private toolchain root")
    realpath_assignment = 'toolchain_root="$(/usr/bin/realpath -e "$created_root")"'
    assert prepare.count(realpath_assignment) == 1
    forced_failure = prepare.replace(realpath_assignment, 'toolchain_root=""\nfalse', 1)

    runner_temp = tmp_path / "current-runner-temp"
    workspace = tmp_path / "current-workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    result = _run_bash(
        forced_failure,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(tmp_path / "current-output"),
        },
    )
    assert result.returncode != 0
    assert not tuple(runner_temp.glob("netbox-rpc-toolchain.??????"))

    regressed = forced_failure.replace("${created_root:-}", "${toolchain_root:-}", 1)
    regressed = regressed.replace('"$created_root"', '"$toolchain_root"', 2)
    regressed_runner_temp = tmp_path / "regressed-runner-temp"
    regressed_workspace = tmp_path / "regressed-workspace"
    regressed_runner_temp.mkdir()
    regressed_workspace.mkdir()
    regressed_result = _run_bash(
        regressed,
        {
            "RUNNER_TEMP": str(regressed_runner_temp),
            "GITHUB_WORKSPACE": str(regressed_workspace),
            "GITHUB_OUTPUT": str(tmp_path / "regressed-output"),
        },
    )
    assert regressed_result.returncode != 0
    assert len(tuple(regressed_runner_temp.glob("netbox-rpc-toolchain.??????"))) == 1


@pytest.mark.parametrize("unsafe_target", ("runner_temp", "unexpected_name"))
def test_private_toolchain_cleanup_refuses_unsafe_targets(
    tmp_path: Path,
    unsafe_target: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    target = runner_temp
    if unsafe_target == "unexpected_name":
        target = runner_temp / "unexpected-toolchain"
        target.mkdir()
    cleanup = _named_step_run(job, "Remove private toolchain")

    result = _run_bash(
        cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(target),
        },
    )

    assert result.returncode != 0
    assert target.is_dir()


def test_private_toolchain_cleanup_refuses_symlink_substitution(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    victim = runner_temp / "netbox-rpc-toolchain.VICTIM"
    victim.mkdir()
    target = runner_temp / "netbox-rpc-toolchain.ABC123"
    target.symlink_to(victim, target_is_directory=True)
    cleanup = _named_step_run(job, "Remove private toolchain")

    result = _run_bash(
        cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(target),
        },
    )

    assert result.returncode != 0
    assert target.is_symlink()
    assert victim.is_dir()


def test_private_toolchain_cleanup_refuses_replaced_path(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    runner_temp.mkdir()
    workspace.mkdir()
    victim = runner_temp / "netbox-rpc-toolchain.VICTIM"
    victim.mkdir()
    target = runner_temp / "netbox-rpc-toolchain.ABC123"
    target.mkdir()
    cleanup = _named_step_run(job, "Remove private toolchain")
    substitution = f'/usr/bin/rmdir "{target}"\n/usr/bin/ln -s "{victim}" "{target}"\n'
    realpath_line = 'toolchain_root="$(/usr/bin/realpath -e "$TOOLCHAIN_ROOT")"'
    assert cleanup.count(realpath_line) == 1
    replaced_cleanup = cleanup.replace(realpath_line, substitution + realpath_line, 1)

    result = _run_bash(
        replaced_cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(target),
        },
    )

    assert result.returncode != 0
    assert target.is_symlink()
    assert victim.is_dir()


def test_private_toolchain_cleanup_direct_parent_guard_isolated(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    runner_temp = tmp_path / "runner-temp"
    workspace = tmp_path / "workspace"
    outside_parent = tmp_path / "outside"
    runner_temp.mkdir()
    workspace.mkdir()
    outside_parent.mkdir()
    target = outside_parent / "netbox-rpc-toolchain.ABC123"
    target.mkdir()
    cleanup = _named_step_run(job, "Remove private toolchain")
    parent_guard = 'test "$(/usr/bin/dirname "$toolchain_root")" = "$runner_temp"'
    assert cleanup.count(parent_guard) == 1

    result = _run_bash(
        cleanup,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(target),
        },
    )
    assert result.returncode != 0
    assert target.is_dir()

    mutation_result = _run_bash(
        cleanup.replace(parent_guard, ":", 1),
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(workspace),
            "TOOLCHAIN_ROOT": str(target),
        },
    )
    assert mutation_result.returncode == 0
    assert not target.exists()


def test_exact_toolchain_provisioning_accepts_contained_outputs(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    toolchain_root = tmp_path / "netbox-rpc-toolchain.ABC123"
    uv_bin = toolchain_root / "tool-cache" / "uv"
    python_bin = toolchain_root / "uv-python" / "cpython" / "bin" / "python3.12"
    uv_bin.parent.mkdir(parents=True)
    python_bin.parent.mkdir(parents=True)
    (toolchain_root / "tmp").mkdir()
    _write_fake_python_runtime(python_bin)
    _write_fake_uv_provisioner(uv_bin, python_bin)
    github_output = tmp_path / "github-output"
    provision = _named_step_run(job, "Provision exact task-private Python 3.12")

    result = _run_bash(
        provision,
        {
            "GITHUB_OUTPUT": str(github_output),
            "TOOLCHAIN_ROOT": str(toolchain_root),
            "UV_BIN": str(uv_bin),
            "UV_CACHE_DIR": str(toolchain_root / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(toolchain_root / "uv-python"),
            "UV_TOOL_DIR": str(toolchain_root / "uv-tools"),
            "UV_TOOL_BIN_DIR": str(toolchain_root / "uv-tool-bin"),
            "TMPDIR": str(toolchain_root / "tmp"),
            "UV_NO_CONFIG": "1",
            "UV_NO_SOURCES": "1",
            "UV_PYTHON_INSTALL_BIN": "0",
            "UV_PYTHON_DOWNLOADS": "manual",
        },
    )

    assert result.returncode == 0
    assert result.stdout == (
        "uv identity: uv 0.12.5 (x86_64-unknown-linux-gnu)\n"
        "Python identity: Python 3.12.14\n"
    )
    assert result.stderr == ""
    assert github_output.read_text(encoding="utf-8") == (
        f"python_bin={python_bin.resolve()}\nuv_bin={uv_bin.resolve()}\n"
    )


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        (
            'platform.python_implementation() != "CPython"',
            'platform.python_implementation() != "PyPy"',
        ),
        (
            "sys.version_info[:3] != (3, 12, 14)",
            "sys.version_info[:3] != (3, 12, 15)",
        ),
        ('platform.machine() != "x86_64"', 'platform.machine() != "aarch64"'),
        ('libc_name != "glibc"', 'libc_name != "musl"'),
        (
            'tuple(map(int, libc_version.split("."))) < (2, 34)',
            'tuple(map(int, libc_version.split("."))) < (2, 33)',
        ),
    ),
)
def test_exact_toolchain_rejects_platform_probe_mutation(
    tmp_path: Path,
    needle: str,
    replacement: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    provision = _named_step_run(job, "Provision exact task-private Python 3.12")
    assert provision.count(needle) == 1
    provision = provision.replace(needle, replacement, 1)
    toolchain_root = tmp_path / "netbox-rpc-toolchain.ABC123"
    uv_bin = toolchain_root / "tool-cache" / "uv"
    python_bin = toolchain_root / "uv-python" / "cpython" / "bin" / "python3.12"
    uv_bin.parent.mkdir(parents=True)
    python_bin.parent.mkdir(parents=True)
    (toolchain_root / "tmp").mkdir()
    _write_fake_python_runtime(python_bin)
    _write_fake_uv_provisioner(uv_bin, python_bin)

    result = _run_bash(
        provision,
        {
            "GITHUB_OUTPUT": str(tmp_path / "github-output"),
            "TOOLCHAIN_ROOT": str(toolchain_root),
            "UV_BIN": str(uv_bin),
            "UV_CACHE_DIR": str(toolchain_root / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(toolchain_root / "uv-python"),
            "UV_TOOL_DIR": str(toolchain_root / "uv-tools"),
            "UV_TOOL_BIN_DIR": str(toolchain_root / "uv-tool-bin"),
            "TMPDIR": str(toolchain_root / "tmp"),
            "UV_NO_CONFIG": "1",
            "UV_NO_SOURCES": "1",
            "UV_PYTHON_INSTALL_BIN": "0",
            "UV_PYTHON_DOWNLOADS": "manual",
        },
    )

    assert result.returncode == 68
    assert result.stderr == "invalid platform probe\n"


@pytest.mark.parametrize("external_tool", ("uv", "python"))
def test_exact_toolchain_provisioning_rejects_external_executable(
    tmp_path: Path,
    external_tool: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    toolchain_root = tmp_path / "netbox-rpc-toolchain.ABC123"
    toolchain_root.mkdir()
    uv_bin = toolchain_root / "tool-cache" / "uv"
    python_bin = toolchain_root / "uv-python" / "python3.12"
    if external_tool == "uv":
        uv_bin = tmp_path / "external-uv" / "uv"
    else:
        python_bin = tmp_path / "external-python" / "python3.12"
    uv_bin.parent.mkdir(parents=True)
    python_bin.parent.mkdir(parents=True)
    (toolchain_root / "tmp").mkdir()
    _write_fake_python_runtime(python_bin)
    _write_fake_uv_provisioner(uv_bin, python_bin)
    provision = _named_step_run(job, "Provision exact task-private Python 3.12")

    result = _run_bash(
        provision,
        {
            "GITHUB_OUTPUT": str(tmp_path / "github-output"),
            "TOOLCHAIN_ROOT": str(toolchain_root),
            "UV_BIN": str(uv_bin),
            "UV_CACHE_DIR": str(toolchain_root / "uv-cache"),
            "UV_PYTHON_INSTALL_DIR": str(toolchain_root / "uv-python"),
            "UV_TOOL_DIR": str(toolchain_root / "uv-tools"),
            "UV_TOOL_BIN_DIR": str(toolchain_root / "uv-tool-bin"),
            "TMPDIR": str(toolchain_root / "tmp"),
            "UV_NO_CONFIG": "1",
            "UV_NO_SOURCES": "1",
            "UV_PYTHON_INSTALL_BIN": "0",
            "UV_PYTHON_DOWNLOADS": "manual",
        },
    )

    assert result.returncode == 1
    expected_name = "uv" if external_tool == "uv" else "Python"
    expected_stdout = (
        ""
        if external_tool == "uv"
        else "uv identity: uv 0.12.5 (x86_64-unknown-linux-gnu)\n"
    )
    assert result.stdout == expected_stdout
    assert result.stderr == (
        f"::error::{expected_name} executable escaped private toolchain root.\n"
    )


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        ("Python identity: %s", "Observed Python: %s"),
        ("uv identity: %s", "Observed uv: %s"),
        ("Python 3.12.14", "Python 3.12.15"),
        (
            "uv 0.12.5 (x86_64-unknown-linux-gnu)",
            "uv 0.12.4 (x86_64-unknown-linux-gnu)",
        ),
    ),
)
def test_exact_toolchain_rejects_silent_or_relaxed_identity_checks(
    needle: str,
    replacement: str,
) -> None:
    workflow = _read(INTEGRATION_WORKFLOW_PATH)
    assert needle in workflow
    mutated = workflow.replace(needle, replacement, 1)
    job = _load_ci_workflow(mutated)["jobs"]["compatibility"]
    with pytest.raises((AssertionError, ValueError)):
        _assert_exact_toolchain_observability(job)


@pytest.mark.parametrize("probe_name", ("python", "uv"))
@pytest.mark.parametrize("replacement_argument", ("--help", ""))
def test_exact_toolchain_rejects_version_probe_argument_mutation(
    tmp_path: Path,
    probe_name: str,
    replacement_argument: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    script = _toolchain_identity_script(job)
    probe_variable = "python_bin" if probe_name == "python" else "uv_bin"
    exact_probe = f'"${probe_variable}" --version'
    mutated_probe = f'"${probe_variable}" {replacement_argument}'.rstrip()
    assert script.count(exact_probe) == 1
    script = script.replace(exact_probe, mutated_probe, 1)
    python_bin = tmp_path / "python3.12"
    uv_bin = tmp_path / "uv"
    _write_fake_executable(python_bin, "Python 3.12.14")
    _write_fake_executable(uv_bin, "uv 0.12.5 (x86_64-unknown-linux-gnu)")

    result = _run_bash(
        script,
        {
            "TEST_PYTHON_BIN": str(python_bin),
            "TEST_UV_BIN": str(uv_bin),
        },
    )

    expected_path = python_bin if probe_name == "python" else uv_bin
    expected_name = "Python" if probe_name == "python" else "uv"
    assert result.returncode == 64
    assert "unexpected version-probe arguments" in result.stderr
    assert (
        f"::error::Exact {expected_name} version probe failed for {expected_path} "
        "with status 64."
    ) in result.stderr


@pytest.mark.parametrize("missing_probe", ("python", "uv"))
def test_exact_toolchain_reports_missing_executable(
    tmp_path: Path,
    missing_probe: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    script = _toolchain_identity_script(job)
    python_bin = tmp_path / "python3.12"
    uv_bin = tmp_path / "uv"
    if missing_probe != "python":
        _write_fake_executable(python_bin, "Python 3.12.14")
    if missing_probe != "uv":
        _write_fake_executable(uv_bin, "uv 0.12.5 (x86_64-unknown-linux-gnu)")

    result = _run_bash(
        script,
        {
            "TEST_PYTHON_BIN": str(python_bin),
            "TEST_UV_BIN": str(uv_bin),
        },
    )

    missing_path = python_bin if missing_probe == "python" else uv_bin
    missing_name = "Python" if missing_probe == "python" else "uv"
    assert result.returncode == 1
    assert f"Missing exact {missing_name} executable: {missing_path}" in result.stderr


@pytest.mark.parametrize(("failing_probe", "status"), (("python", 7), ("uv", 9)))
def test_exact_toolchain_reports_failed_version_probe(
    tmp_path: Path,
    failing_probe: str,
    status: int,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    script = _toolchain_identity_script(job)
    python_bin = tmp_path / "python3.12"
    uv_bin = tmp_path / "uv"
    _write_fake_executable(
        python_bin,
        "Python 3.12.14",
        status if failing_probe == "python" else 0,
    )
    _write_fake_executable(
        uv_bin,
        "uv 0.12.5 (x86_64-unknown-linux-gnu)",
        status if failing_probe == "uv" else 0,
    )

    result = _run_bash(
        script,
        {
            "TEST_PYTHON_BIN": str(python_bin),
            "TEST_UV_BIN": str(uv_bin),
        },
    )

    failed_path = python_bin if failing_probe == "python" else uv_bin
    failed_name = "Python" if failing_probe == "python" else "uv"
    assert result.returncode == status
    assert result.stderr == (
        f"::error::Exact {failed_name} version probe failed for {failed_path} "
        f"with status {status}.\n"
    )


@pytest.mark.parametrize("mismatched_probe", ("python", "uv"))
def test_exact_toolchain_rejects_successful_identity_mismatch(
    tmp_path: Path,
    mismatched_probe: str,
) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    script = _toolchain_identity_script(job)
    python_identity = (
        "Python 3.12.13" if mismatched_probe == "python" else "Python 3.12.14"
    )
    uv_identity = (
        "uv 0.12.4 (x86_64-unknown-linux-gnu)"
        if mismatched_probe == "uv"
        else "uv 0.12.5 (x86_64-unknown-linux-gnu)"
    )
    python_bin = tmp_path / "python3.12"
    uv_bin = tmp_path / "uv"
    _write_fake_executable(python_bin, python_identity)
    _write_fake_executable(uv_bin, uv_identity)

    result = _run_bash(
        script,
        {
            "TEST_PYTHON_BIN": str(python_bin),
            "TEST_UV_BIN": str(uv_bin),
        },
    )

    assert result.returncode != 0
    expected_identity = python_identity if mismatched_probe == "python" else uv_identity
    assert expected_identity in result.stdout
    assert result.stderr == ""


def test_exact_toolchain_accepts_and_prints_exact_identities(tmp_path: Path) -> None:
    job = _load_ci_workflow(_read(INTEGRATION_WORKFLOW_PATH))["jobs"]["compatibility"]
    script = _toolchain_identity_script(job)
    python_bin = tmp_path / "python3.12"
    uv_bin = tmp_path / "uv"
    _write_fake_executable(python_bin, "Python 3.12.14")
    _write_fake_executable(uv_bin, "uv 0.12.5 (x86_64-unknown-linux-gnu)")

    result = _run_bash(
        script,
        {
            "TEST_PYTHON_BIN": str(python_bin),
            "TEST_UV_BIN": str(uv_bin),
        },
    )

    assert result.returncode == 0
    assert result.stdout == (
        "uv identity: uv 0.12.5 (x86_64-unknown-linux-gnu)\n"
        "Python identity: Python 3.12.14\n"
    )
    assert result.stderr == ""


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
