"""Fail-closed NetBox 4.7 prerelease identity validation."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from packaging.version import InvalidVersion, Version


class ReleaseHeldConfig(Protocol):
    """Configuration attributes required by the release guard."""

    approved_netbox_version: str
    approved_netbox_designation: str


def _loader_requires_identity_check(
    config: type[ReleaseHeldConfig], netbox_version: str
) -> bool:
    """Return whether canonical metadata must be checked, failing closed."""
    try:
        candidate = Version(netbox_version)
        approved_numeric = Version(config.approved_netbox_version)
        approved_prerelease = Version(
            f"{config.approved_netbox_version}-{config.approved_netbox_designation}"
        )
    except InvalidVersion as error:
        if not netbox_version.startswith("4.7"):
            return False
        from core.exceptions import IncompatiblePluginError

        raise IncompatiblePluginError(
            f"Plugin {config.__module__} cannot verify malformed NetBox "
            f"4.7 version {netbox_version!r}."
        ) from error

    on_held_numeric_line = candidate.release[:2] == approved_numeric.release[
        :2
    ] and not any(candidate.release[2:])
    if not on_held_numeric_line:
        return False
    if candidate in {approved_numeric, approved_prerelease}:
        return True

    from core.exceptions import IncompatiblePluginError

    raise IncompatiblePluginError(
        f"Plugin {config.__module__} is approved only for NetBox "
        f"{config.approved_netbox_version}-{config.approved_netbox_designation} "
        f"on the 4.7 line (loader: {netbox_version})."
    )


def validate_netbox_release(
    config: type[ReleaseHeldConfig],
    netbox_version: str,
) -> None:
    """Admit only the reviewed canonical identity on the 4.7.0 line."""
    if not _loader_requires_identity_check(config, netbox_version):
        return

    import yaml
    from core.exceptions import IncompatiblePluginError
    from utilities.release import (
        LOCAL_RELEASE_PATH,
        RELEASE_PATH,
        _find_release_base_path,
    )

    release_base_path = Path(_find_release_base_path())

    try:
        release_data = yaml.safe_load(
            release_base_path.joinpath(RELEASE_PATH).read_text(encoding="utf-8")
        )
    except (OSError, yaml.YAMLError) as error:
        raise IncompatiblePluginError(
            f"Plugin {config.__module__} could not verify canonical NetBox "
            f"release identity from {RELEASE_PATH}: {error}"
        ) from error
    if type(release_data) is not dict:
        raise IncompatiblePluginError(
            f"Plugin {config.__module__} requires a mapping in {RELEASE_PATH} "
            "while NetBox 4.7 is release-held."
        )

    local_release_path = release_base_path.joinpath(LOCAL_RELEASE_PATH)
    try:
        local_release_text = local_release_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        local_release_data = {}
    except OSError as error:
        raise IncompatiblePluginError(
            f"Plugin {config.__module__} could not verify {LOCAL_RELEASE_PATH}: {error}"
        ) from error
    else:
        try:
            local_release_data = yaml.safe_load(local_release_text)
        except yaml.YAMLError as error:
            raise IncompatiblePluginError(
                f"Plugin {config.__module__} could not verify {LOCAL_RELEASE_PATH}: {error}"
            ) from error
        if local_release_data is None:
            local_release_data = {}

    unexpected_keys = (
        set(local_release_data) - {"build"}
        if type(local_release_data) is dict
        else {"invalid-content"}
    )
    if unexpected_keys:
        unexpected_labels = ", ".join(sorted(map(str, unexpected_keys)))
        raise IncompatiblePluginError(
            f"Plugin {config.__module__} permits only the build key in "
            f"{LOCAL_RELEASE_PATH} while NetBox 4.7 is release-held "
            f"(unexpected: {unexpected_labels})."
        )

    version = release_data.get("version")
    designation = release_data.get("designation")
    if (
        version != config.approved_netbox_version
        or designation != config.approved_netbox_designation
    ):
        current_release = str(version)
        if designation:
            current_release = f"{current_release}-{designation}"
        raise IncompatiblePluginError(
            f"Plugin {config.__module__} is approved only for NetBox "
            f"{config.approved_netbox_version}-"
            f"{config.approved_netbox_designation} on the 4.7 line "
            f"(canonical: {current_release})."
        )
