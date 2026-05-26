HUAWEI_MA5800_R024_START_ONT = "network.device.huawei.olt.ma5800.r024.start_ont"
HUAWEI_MA5800_R024_START_ONT_HANDLER = "network.huawei_olt_ma5800_r024.start_ont"

UBUNTU_24_RESTART_SERVICE = "os.linux.ubuntu.24.restart_service"
UBUNTU_24_RESTART_SERVICE_HANDLER = "os.linux_ubuntu_24.restart_service"

INITIAL_PROCEDURES = (
    {
        "name": HUAWEI_MA5800_R024_START_ONT,
        "handler_id": HUAWEI_MA5800_R024_START_ONT_HANDLER,
        "target_models": ["netbox_gpon.olt"],
        "effect": "write",
        "timeout_seconds": 90,
        "approval_required": False,
        "params_schema": {
            "type": "object",
            "required": ["frame", "slot", "port", "ont_id"],
            "additionalProperties": False,
            "properties": {
                "frame": {"type": "integer", "minimum": 0},
                "slot": {"type": "integer", "minimum": 1, "maximum": 17},
                "port": {"type": "integer", "minimum": 0, "maximum": 15},
                "ont_id": {"type": "integer", "minimum": 0, "maximum": 127},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "status"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "status": {"type": "string"},
            },
        },
    },
    {
        "name": UBUNTU_24_RESTART_SERVICE,
        "handler_id": UBUNTU_24_RESTART_SERVICE_HANDLER,
        "target_models": ["dcim.device"],
        "effect": "write",
        "timeout_seconds": 45,
        "approval_required": False,
        "params_schema": {
            "type": "object",
            "required": ["service_slug"],
            "additionalProperties": False,
            "properties": {
                "service_slug": {"type": "string", "minLength": 1, "maxLength": 100},
            },
        },
        "result_schema": {
            "type": "object",
            "required": ["ok", "procedure", "target", "service", "active_state"],
            "properties": {
                "ok": {"type": "boolean"},
                "procedure": {"type": "string"},
                "target": {"type": "string"},
                "service": {"type": "string"},
                "active_state": {"type": "string"},
            },
        },
    },
)
