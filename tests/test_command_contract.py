import importlib.util
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "command_contract",
    ROOT / "netbox_rpc/command_contract.py",
)
assert SPEC and SPEC.loader
command_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(command_contract)

EXEMPT_HANDLER_IDS = command_contract.EXEMPT_HANDLER_IDS
extract_placeholders = command_contract.extract_placeholders
token_has_balanced_placeholders = command_contract.token_has_balanced_placeholders
token_is_safe = command_contract.token_is_safe


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_safe_token_regex_accepts_argv_tokens_and_rejects_shell_metacharacters() -> None:
    for token in (
        "sudo",
        "/bin/systemctl",
        "--no-pager",
        "DEBIAN_FRONTEND=noninteractive",
        "/nodes/{node}/qemu",
        "{target}",
        "bridge=vmbr0,tag=20",
    ):
        assert token_is_safe(token)

    for token in ("echo bad", "foo;bar", "x|y", "$(id)", "a>b", "name`id`"):
        assert not token_is_safe(token)


def test_placeholder_extraction_and_balance_checks() -> None:
    assert extract_placeholders("/nodes/{node}/qemu/{vmid}") == ("node", "vmid")
    assert extract_placeholders("{target}") == ("target",)
    assert extract_placeholders("literal") == ()
    assert token_has_balanced_placeholders("/nodes/{node}/qemu")
    assert not token_has_balanced_placeholders("/nodes/{node/qemu")


def test_seeded_handler_ids_have_command_rows_or_documented_exemption() -> None:
    constants = runpy.run_path(str(ROOT / "netbox_rpc/constants.py"))
    # Command rows are seeded by 0037 and by any later per-procedure command
    # seed migration (procedures added after 0037 seed their representative rows
    # in their own migration). Scan only migrations that actually seed
    # RPCProcedureCommand rows — NOT procedure-seed migrations, which also
    # mention the handler_id but do not create a command row. This keeps the
    # test able to catch a deleted command row.
    migration = "\n".join(
        src
        for src in (
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "netbox_rpc/migrations").glob("0*.py"))
        )
        if "RPCProcedureCommand" in src
    )

    handler_ids = {
        value
        for key, value in constants.items()
        if key.endswith("_HANDLER") and isinstance(value, str)
    }
    handler_ids.update(constants["OOKLA_PROCEDURE_NAMES"])
    handler_ids.update(constants["PACKER_PROCEDURE_NAMES"])
    handler_ids.update(
        {
            constants["DNS_HOST_DEPLOY_PROCEDURE"],
            constants["DNS_HOST_STATUS_PROCEDURE"],
            constants["NGINX_1_CONFIG_TEST"],
            constants["NGINX_1_CONFIG_DEPLOY"],
            constants["NGINX_1_RELOAD"],
            constants["NGINX_1_ROLLBACK"],
        }
    )

    missing = sorted(
        handler
        for handler in handler_ids
        if handler not in migration and handler not in EXEMPT_HANDLER_IDS
    )
    assert missing == []
    for handler in EXEMPT_HANDLER_IDS:
        assert handler in migration
