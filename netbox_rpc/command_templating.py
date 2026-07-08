"""Jinja2 templating + output-capture contract for ``RPCProcedureCommand``.

This module is the **pure-domain, Django-free** half of the command-templating
feature. It is importable and unit-testable with only ``jinja2`` + the stdlib
(the same way ``tests/test_command_contract.py`` imports ``command_contract``).

Two capabilities are modelled here:

1. **Jinja2 templating** (``render_mode="jinja"``). Each ``argv`` token becomes a
   Jinja2 *expression* template rendered — by the nms-backend executor, at run
   time — against a small, fixed context:

   - ``params.<name>``   — the procedure's declared ``params_schema`` values;
   - ``target.<field>``  — fields of the run's NetBox target object
     (**"NetBox objects as variables"**), from the bounded snapshot netbox-rpc
     serializes into ``normalized_params``;
   - ``vars.<name>``     — a value **captured from an earlier command's output**
     (**"output-based variables"** / the nesting chain);
   - ``runtime.<key>``   — the ``rpc_ssh_*`` connection keys;
   - ``item``            — the current ``for_each`` element (when set).

2. **Output capture** (``produces_var`` + ``capture_kind`` + ``capture_expression``).
   A command may capture a named value from *its own* output so a *later*
   command can reference it as ``{{ vars.<name> }}``. This is what lets an
   operator build the chain "command 2 needs a value that only exists in command
   1's output, which itself came from a NetBox object".

Security posture (unchanged from the fixed-argv contract): templating is
**opt-in per command**; the legacy ``literal`` mode is byte-for-byte identical.
Jinja tokens are validated at author time with a **sandboxed** environment,
statement/comment blocks and function/method calls are rejected, literal text
outside ``{{ }}`` must use the conservative argv charset, and every referenced
variable must resolve to a declared param / an earlier output var / a runtime
key / a (non-dunder) target field / the loop item. Because the eventual
executor runs a single shell string over SSH (there is no execve/no-shell path),
the executor MUST additionally shell-quote every rendered token and re-validate
captured values — see ``docs/command-templating.md``.
"""

from __future__ import annotations

import re
from collections import namedtuple

try:  # jinja2 ships with NetBox; guarded so the module still imports standalone.
    from jinja2 import nodes
    from jinja2.exceptions import TemplateSyntaxError
    from jinja2.sandbox import SandboxedEnvironment

    _ENV = SandboxedEnvironment(autoescape=False)
    _JINJA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only where jinja2 is absent
    _JINJA_AVAILABLE = False


# ── Render modes ─────────────────────────────────────────────────────────────

RENDER_LITERAL = "literal"
RENDER_JINJA = "jinja"
RENDER_MODE_CHOICES = (
    (RENDER_LITERAL, "Literal ({param} substitution)"),
    (RENDER_JINJA, "Jinja2 template ({{ ... }})"),
)
RENDER_MODES = frozenset({RENDER_LITERAL, RENDER_JINJA})


# ── Output-capture kinds ─────────────────────────────────────────────────────

CAPTURE_STDOUT = "stdout"
CAPTURE_STDOUT_STRIPPED = "stdout_stripped"
CAPTURE_JSON = "json"
CAPTURE_REGEX = "regex"
CAPTURE_LINE = "line"
CAPTURE_KIND_CHOICES = (
    (CAPTURE_STDOUT, "Full stdout"),
    (CAPTURE_STDOUT_STRIPPED, "Stripped stdout"),
    (CAPTURE_JSON, "JSON path (expression)"),
    (CAPTURE_REGEX, "Regex (one capture group)"),
    (CAPTURE_LINE, "Line index (expression)"),
)
CAPTURE_KINDS = frozenset(kind for kind, _label in CAPTURE_KIND_CHOICES)
# Kinds whose ``capture_expression`` is mandatory (and, for the others, forbidden).
CAPTURE_KINDS_REQUIRING_EXPRESSION = frozenset(
    {CAPTURE_JSON, CAPTURE_REGEX, CAPTURE_LINE}
)


# ── Jinja render-context roots ───────────────────────────────────────────────

ROOT_PARAMS = "params"
ROOT_TARGET = "target"
ROOT_VARS = "vars"
ROOT_RUNTIME = "runtime"
ROOT_ITEM = "item"
JINJA_CONTEXT_ROOTS = frozenset(
    {ROOT_PARAMS, ROOT_TARGET, ROOT_VARS, ROOT_RUNTIME, ROOT_ITEM}
)

# ``runtime.<key>`` keys the executor injects (the SSH connection overrides). The
# bare ``target``/``item`` runtime placeholders of literal mode become their own
# roots in jinja mode, so they are intentionally excluded here.
JINJA_RUNTIME_KEYS = frozenset(
    {
        "rpc_ssh_host",
        "rpc_ssh_port",
        "rpc_ssh_credential_pk",
        "rpc_ssh_known_hosts_entry",
        "rpc_ssh_strict_host_key_checking",
    }
)

# Reserved names a captured output variable may not use (they are context roots).
RESERVED_VAR_NAMES = JINJA_CONTEXT_ROOTS


# ── Patterns ─────────────────────────────────────────────────────────────────

# Captured-variable names are snake_case identifiers.
VAR_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# Literal text OUTSIDE a ``{{ }}`` expression must use the conservative argv
# charset — no whitespace, braces, or shell metacharacters. (Empty is allowed so
# a token that is purely ``{{ expr }}`` passes.)
JINJA_LITERAL_SAFE_RE = re.compile(r"^[A-Za-z0-9_@%+=:,./-]*$")

# A JSON capture path may only contain identifiers, digits, dots and [] indexing.
JSON_PATH_RE = re.compile(r"^[A-Za-z0-9_.\[\]\"'-]+$")

# Statement (``{% %}``) and comment (``{# #}``) blocks are rejected in tokens:
# a command argv token is an expression, not a program. Loops/conditionals are
# expressed with the structured ``for_each_param``/``condition_param`` fields.
_STATEMENT_RE = re.compile(r"\{%|%\}|\{#|#\}")

# Only scalar-safe Jinja filters are allowed in a command token (allowlist, not
# denylist). This deliberately excludes attribute-reaching filters such as
# ``attr``, ``map``, ``selectattr``/``rejectattr``, ``groupby``, and ``sort``
# that could otherwise read arbitrary object attributes at render time.
ALLOWED_FILTERS = frozenset(
    {
        "int",
        "float",
        "string",
        "default",
        "upper",
        "lower",
        "trim",
        "capitalize",
        "title",
        "replace",
        "truncate",
        "length",
        "abs",
        "round",
        "join",
    }
)


# ── Reference extraction ─────────────────────────────────────────────────────


# One first-level variable reference found in a token. ``attr`` is the first
# attribute/string-key after the root (``target.name`` → ``VarRef("target",
# "name")``), or ``None`` when the root is used directly or index-subscripted
# (``{{ item }}`` → ``VarRef("item", None)``). A ``namedtuple`` (not a dataclass)
# so the module loads via ``importlib`` without being registered in
# ``sys.modules`` — the way the pure-domain tests import it.
VarRef = namedtuple("VarRef", ("root", "attr"))


class TokenAnalysis:
    """Structural analysis of one jinja token: collected errors + variable refs."""

    __slots__ = ("errors", "refs")

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.refs: list[VarRef] = []


def _const_str(node: object) -> str | None:
    """Return the string value of a ``Const`` subscript arg, else ``None``."""

    if _JINJA_AVAILABLE and isinstance(node, nodes.Const) and isinstance(node.value, str):
        return node.value
    return None


def analyze_token(token: str) -> TokenAnalysis:
    """Parse one jinja ``argv`` token and return its errors + variable refs.

    Structural validation only (syntax, forbidden constructs, safe literals,
    reference extraction). Semantic resolution of each ref against the declared
    params / produced vars / runtime keys is done by :func:`validate_jinja_argv`.
    """

    result = TokenAnalysis()
    if not isinstance(token, str) or token == "":
        result.errors.append("must be a non-empty string")
        return result
    if not _JINJA_AVAILABLE:  # pragma: no cover - jinja2 present under NetBox/CI
        result.errors.append("Jinja2 is not installed; cannot validate jinja tokens")
        return result
    if _STATEMENT_RE.search(token):
        result.errors.append(
            f"{token!r}: statement/comment blocks ({{% %}} / {{# #}}) are not "
            "allowed; command tokens are expressions only"
        )
        return result
    try:
        ast = _ENV.parse(token)
    except TemplateSyntaxError as exc:
        result.errors.append(f"{token!r}: invalid Jinja template ({exc.message})")
        return result

    # Reject function/method calls: rendered tokens must not invoke anything.
    for _call in ast.find_all(nodes.Call):
        result.errors.append(
            f"{token!r}: function/method calls are not allowed in command tokens"
        )
        break

    # Only allowlisted, scalar-safe filters may be used.
    for filter_node in ast.find_all(nodes.Filter):
        if filter_node.name not in ALLOWED_FILTERS:
            result.errors.append(
                f"{token!r}: filter {filter_node.name!r} is not allowed "
                f"(allowed: {', '.join(sorted(ALLOWED_FILTERS))})"
            )

    # Literal spans (text between the expressions) must be argv-safe.
    for data_node in ast.find_all(nodes.TemplateData):
        if not JINJA_LITERAL_SAFE_RE.fullmatch(data_node.data):
            result.errors.append(
                f"{token!r}: literal text {data_node.data!r} contains characters "
                "outside the safe argv charset"
            )

    # String CONSTANTS inside the expression must also be argv-safe, so shell
    # metacharacters can't be smuggled through a Jinja string literal
    # (e.g. {{ '; rm -rf /' }}) past the literal-span check above.
    for const_node in ast.find_all(nodes.Const):
        if isinstance(const_node.value, str) and not JINJA_LITERAL_SAFE_RE.fullmatch(
            const_node.value
        ):
            result.errors.append(
                f"{token!r}: string literal {const_node.value!r} contains characters "
                "outside the safe argv charset"
            )

    # Reject private/dunder attribute or key access at ANY depth
    # (target.name.__class__, target['_x'], etc.), not just the first hop.
    for access in ast.find_all((nodes.Getattr, nodes.Getitem)):
        attr = (
            access.attr
            if isinstance(access, nodes.Getattr)
            else _const_str(access.arg)
        )
        if attr and attr.startswith("_"):
            result.errors.append(
                f"{token!r}: private/dunder attribute access ({attr!r}) is not allowed"
            )

    # First-level references. A Name used as the target of a Getattr/Getitem is
    # recorded with its attribute; any remaining bare Name is a direct root use.
    attributed_name_ids: set[int] = set()
    for access in ast.find_all((nodes.Getattr, nodes.Getitem)):
        inner = access.node
        if isinstance(inner, nodes.Name):
            attributed_name_ids.add(id(inner))
            attr = (
                access.attr
                if isinstance(access, nodes.Getattr)
                else _const_str(access.arg)
            )
            result.refs.append(VarRef(inner.name, attr))
    for name in ast.find_all(nodes.Name):
        if id(name) not in attributed_name_ids:
            result.refs.append(VarRef(name.name, None))
    return result


def _validate_ref(
    ref: VarRef,
    *,
    param_names: frozenset[str],
    produced_vars: frozenset[str],
    for_each_present: bool,
) -> list[str]:
    root, attr = ref.root, ref.attr
    if root not in JINJA_CONTEXT_ROOTS:
        allowed = ", ".join(sorted(JINJA_CONTEXT_ROOTS))
        return [f"unknown variable root {root!r} (allowed roots: {allowed})"]
    # Dunder/private access is rejected structurally in analyze_token (at any
    # depth), so it need not be re-checked here.

    if root == ROOT_ITEM:
        if not for_each_present:
            return ["'item' is only available when a 'for each' parameter is set"]
        return []

    if attr is None:
        return [
            f"reference a specific key of {root!r} "
            f"(for example {root}.<name>), not the whole object"
        ]

    if root == ROOT_PARAMS and attr not in param_names:
        available = ", ".join(sorted(param_names)) or "(none declared)"
        return [
            f"params.{attr} is not declared in the procedure params schema "
            f"(available: {available})"
        ]
    if root == ROOT_VARS and attr not in produced_vars:
        available = ", ".join(sorted(produced_vars)) or "(none produced earlier)"
        return [
            f"vars.{attr} is not produced by any earlier command "
            f"(available output variables: {available})"
        ]
    if root == ROOT_RUNTIME and attr not in JINJA_RUNTIME_KEYS:
        available = ", ".join(sorted(JINJA_RUNTIME_KEYS))
        return [f"runtime.{attr} is not a known runtime key (available: {available})"]
    # root == ROOT_TARGET: any non-dunder field is accepted; the concrete field
    # set depends on the target object and is resolved from the snapshot at run
    # time (StrictUndefined surfaces typos as an execution error).
    return []


def validate_jinja_argv(
    argv: object,
    *,
    param_names: frozenset[str],
    produced_vars: frozenset[str],
    for_each_present: bool,
) -> list[str]:
    """Validate a jinja-mode ``argv`` token list. Returns a list of errors.

    ``produced_vars`` must contain only the variables produced by commands that
    run **before** this one (strictly smaller ``sequence``); that is what makes
    ``{{ vars.x }}`` resolvable and enforces the output→input ordering of the
    chain.
    """

    if not isinstance(argv, list) or not argv:
        return ["argv must be a non-empty list of non-empty string tokens."]
    errors: list[str] = []
    for index, token in enumerate(argv, start=1):
        analysis = analyze_token(token)
        errors.extend(f"token {index}: {message}" for message in analysis.errors)
        for ref in analysis.refs:
            errors.extend(
                f"token {index}: {message}"
                for message in _validate_ref(
                    ref,
                    param_names=param_names,
                    produced_vars=produced_vars,
                    for_each_present=for_each_present,
                )
            )
    return errors


# ── Output-capture validation ────────────────────────────────────────────────


def validate_capture(
    *,
    produces_var: str,
    capture_kind: str,
    capture_expression: str,
    other_var_names: frozenset[str],
) -> list[str]:
    """Validate the output-capture spec of a single command. Returns errors.

    ``other_var_names`` is the set of ``produces_var`` values used by the *other*
    commands of the same procedure, so uniqueness can be enforced.
    """

    errors: list[str] = []
    var = (produces_var or "").strip()
    kind = (capture_kind or "").strip()
    expression = (capture_expression or "").strip()

    if not var:
        if kind or expression:
            errors.append(
                "capture_kind/capture_expression require produces_var to be set."
            )
        return errors

    if not VAR_NAME_RE.fullmatch(var):
        errors.append(
            f"produces_var {var!r} must be a snake_case identifier ([a-z][a-z0-9_]*)."
        )
    if var in RESERVED_VAR_NAMES:
        reserved = ", ".join(sorted(RESERVED_VAR_NAMES))
        errors.append(f"produces_var {var!r} is a reserved context name ({reserved}).")
    if var in other_var_names:
        errors.append(
            f"produces_var {var!r} is already produced by another command in this "
            "procedure; output variable names must be unique."
        )

    if not kind:
        errors.append("capture_kind is required when produces_var is set.")
        return errors
    if kind not in CAPTURE_KINDS:
        errors.append(
            f"capture_kind {kind!r} is not one of {sorted(CAPTURE_KINDS)}."
        )
        return errors

    requires_expression = kind in CAPTURE_KINDS_REQUIRING_EXPRESSION
    if requires_expression and not expression:
        errors.append(f"capture_expression is required for capture_kind={kind}.")
    if not requires_expression and expression:
        errors.append(f"capture_expression must be empty for capture_kind={kind}.")

    if kind == CAPTURE_REGEX and expression:
        try:
            compiled = re.compile(expression)
        except re.error as exc:
            errors.append(f"capture_expression is not a valid regex: {exc}.")
        else:
            if compiled.groups != 1:
                errors.append(
                    "regex capture_expression must contain exactly one capturing "
                    f"group (found {compiled.groups})."
                )
    elif kind == CAPTURE_LINE and expression:
        try:
            int(expression)
        except ValueError:
            errors.append("line capture_expression must be an integer line index.")
    elif kind == CAPTURE_JSON and expression and not JSON_PATH_RE.fullmatch(expression):
        errors.append(
            "json capture_expression may only contain identifiers, digits, dots, "
            "and [] indexing."
        )
    return errors
