# netbox-rpc Agent Notes

`netbox-rpc` owns procedure policy and audit state. It must never store or
accept arbitrary SSH command text from API clients.

- Procedure records map canonical names to backend `handler_id` values.
- NetBox RQ jobs normalize params and delegate execution to `nms-backend`.
- SSH credentials and host-key pinning live in `netbox-nms.DeviceService`.
- Tests must use mocks and fixtures only; do not connect to real Linux hosts,
  containers, VMs, or Huawei OLTs.
