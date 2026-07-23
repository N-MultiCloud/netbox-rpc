from __future__ import annotations

from typing import Any

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from netbox.api.viewsets import NetBoxModelViewSet, NetBoxReadOnlyModelViewSet
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from .. import models
from ..application.command_handlers import (
    approve_execution,
    cancel_execution,
    create_execution,
    execute_intent,
    reject_execution,
)
from ..application.queries import execution_events
from .serializers import (
    RPCBackendSerializer,
    RPCIntentRunSerializer,
    RPCIntentSerializer,
    RPCLinuxServiceAllowlistSerializer,
    RPCExecutionEventSerializer,
    RPCExecutionSerializer,
    RPCProcedureCommandSerializer,
    RPCProcedureSerializer,
    RpcPluginSettingsSerializer,
)


class RpcPluginSettingsViewSet(NetBoxModelViewSet):
    """REST API for the netbox-rpc opt-in settings singleton (GET + PATCH).

    The singleton row is materialized via ``get_solo()`` so ``GET`` (list/detail)
    and ``PATCH`` always operate on the one settings object. Create/delete are
    disabled — there is exactly one settings row.
    """

    queryset = models.RpcPluginSettings.objects.prefetch_related("tags")
    serializer_class = RpcPluginSettingsSerializer
    http_method_names = ["get", "patch", "head", "options"]

    def get_queryset(self) -> Any:
        # Ensure the singleton exists so GET/PATCH always resolve a row.
        models.RpcPluginSettings.get_solo()
        return models.RpcPluginSettings.objects.prefetch_related("tags").order_by("id")


class RPCBackendViewSet(NetBoxModelViewSet):
    queryset = models.RPCBackend.objects.prefetch_related("tags")
    serializer_class = RPCBackendSerializer


class RPCProcedureViewSet(NetBoxModelViewSet):
    queryset = models.RPCProcedure.objects.prefetch_related("commands", "tags")
    serializer_class = RPCProcedureSerializer

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["get"], url_path="available")
    def available(self, request: Request) -> Response:
        from django.db.models import Q

        target_type = (request.query_params.get("target_type") or "").strip().lower()
        qs = models.RPCProcedure.objects.filter(enabled=True).prefetch_related(
            "tags", "commands"
        )
        if target_type:
            # Include procedures with no target restriction (empty list) or those
            # that explicitly allow the requested target type.
            qs = qs.filter(
                Q(target_models=[]) | Q(target_models__contains=[target_type])
            )

        # #167: when the selected backend advertises a capability manifest, a
        # procedure the backend cannot serve compatibly is not "available".
        # Graceful when the backend advertises nothing (manifest is None).
        from .. import capabilities
        from ..models import RpcPluginSettings

        manifest = capabilities.fetch_backend_capabilities(
            RpcPluginSettings.get_solo().resolved_backend_target()
        )
        if manifest is not None:
            compatible = [
                procedure
                for procedure in qs
                if capabilities.verify_procedure_capability(procedure, manifest)
                is not capabilities.CapabilityStatus.MISMATCH
            ]
            qs = compatible

        page = self.paginate_queryset(qs)
        serializer = self.get_serializer(page if page is not None else qs, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    @extend_schema(
        request=RPCProcedureCommandSerializer,
        responses={
            200: RPCProcedureCommandSerializer(many=True),
            201: RPCProcedureCommandSerializer,
        },
    )
    @action(detail=True, methods=["get", "post"], url_path="commands")
    def commands(self, request: Request, pk: str | None = None) -> Response:
        procedure = self.get_object()
        if request.method == "POST":
            payload = request.data.copy()
            payload["procedure"] = procedure.pk
            serializer = RPCProcedureCommandSerializer(
                data=payload,
                context={"request": request},
            )
            serializer.is_valid(raise_exception=True)
            command = serializer.save()
            output = RPCProcedureCommandSerializer(
                command, context={"request": request}
            )
            return Response(output.data, status=status.HTTP_201_CREATED)

        qs = procedure.commands.all().prefetch_related("tags")
        page = self.paginate_queryset(qs)
        serializer = RPCProcedureCommandSerializer(
            page if page is not None else qs,
            many=True,
            context={"request": request},
        )
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class RPCProcedureCommandViewSet(NetBoxModelViewSet):
    queryset = models.RPCProcedureCommand.objects.select_related(
        "procedure"
    ).prefetch_related("tags")
    serializer_class = RPCProcedureCommandSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        procedure_id = self.request.query_params.get("procedure_id")
        if procedure_id:
            qs = qs.filter(procedure_id=procedure_id)
        return qs


class RPCIntentViewSet(NetBoxModelViewSet):
    queryset = models.RPCIntent.objects.prefetch_related(
        "tags", "intent_procedures__procedure"
    )
    serializer_class = RPCIntentSerializer

    @extend_schema(
        request=RPCIntentRunSerializer,
        responses={201: RPCExecutionSerializer(many=True)},
    )
    @action(detail=True, methods=["post"], url_path="run")
    def run(self, request: Request, pk: str | None = None) -> Response:
        # Trigger surface for issue #130: fans out one child RPCExecution per
        # grouped procedure through execute_intent(), which re-runs every
        # create_execution() gate (permission, #166 opt-in/backend, approval,
        # params, #167 capability) per child -- see command_handlers.py for
        # the full no-bypass contract. get_object() applies NetBox's normal
        # object-scoped restrictions to the intent itself.
        intent = self.get_object()
        run_serializer = RPCIntentRunSerializer(data=request.data)
        run_serializer.is_valid(raise_exception=True)
        children = execute_intent(
            intent,
            request.user,
            assigned_object_type=run_serializer.validated_data["assigned_object_type"],
            assigned_object_id=run_serializer.validated_data["assigned_object_id"],
            params=run_serializer.validated_data.get("params") or {},
        )
        output = RPCExecutionSerializer(
            children, many=True, context={"request": request}
        )
        return Response(output.data, status=status.HTTP_201_CREATED)


class RPCLinuxServiceAllowlistViewSet(NetBoxModelViewSet):
    queryset = models.RPCLinuxServiceAllowlist.objects.prefetch_related("tags")
    serializer_class = RPCLinuxServiceAllowlistSerializer


class RPCExecutionViewSet(NetBoxModelViewSet):
    # Command-only write model for the event-sourced execution aggregate: clients
    # create executions (POST) and transition them via command actions (cancel).
    # PUT/PATCH are disabled (state is derived from the event log, never edited);
    # DELETE is disabled because the execution's RPCExecutionEvent ledger is
    # append-only (its cascade would hit the append-only trigger), so an execution
    # and its history are immutable once created.
    http_method_names = ["get", "post", "head", "options"]
    queryset = models.RPCExecution.objects.select_related(
        "procedure",
        "assigned_object_type",
        "requested_by",
    ).prefetch_related("procedure__commands", "tags")
    serializer_class = RPCExecutionSerializer

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        execution = create_execution(serializer=serializer, user=request.user)
        output = self.get_serializer(execution)
        return Response(output.data, status=status.HTTP_201_CREATED)

    @extend_schema(responses={200: RPCExecutionSerializer})
    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request: Request, pk: str | None = None) -> Response:
        execution = cancel_execution(self.get_object(), request.user)
        serializer = self.get_serializer(execution)
        return Response(serializer.data)

    @extend_schema(responses={200: RPCExecutionSerializer})
    @action(detail=True, methods=["post"], url_path="approve")
    def approve(self, request: Request, pk: str | None = None) -> Response:
        # get_object() applies NetBox object restrictions: an actor without
        # object-scoped view access to this execution 404s before deciding.
        execution = approve_execution(
            self.get_object(),
            request.user,
            reason=str(request.data.get("reason") or ""),
        )
        serializer = self.get_serializer(execution)
        return Response(serializer.data)

    @extend_schema(responses={200: RPCExecutionSerializer})
    @action(detail=True, methods=["post"], url_path="reject")
    def reject(self, request: Request, pk: str | None = None) -> Response:
        execution = reject_execution(
            self.get_object(),
            request.user,
            reason=str(request.data.get("reason") or ""),
        )
        serializer = self.get_serializer(execution)
        return Response(serializer.data)

    @extend_schema(responses={200: RPCExecutionEventSerializer(many=True)})
    @action(detail=True, methods=["get"], url_path="events")
    def events(self, request: Request, pk: str | None = None) -> Response:
        execution = self.get_object()
        qs = execution_events(execution)
        page = self.paginate_queryset(qs)
        serializer = RPCExecutionEventSerializer(
            page if page is not None else qs,
            many=True,
            context={"request": request},
        )
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class RPCExecutionEventViewSet(NetBoxReadOnlyModelViewSet):
    queryset = models.RPCExecutionEvent.objects.select_related(
        "execution"
    ).prefetch_related("tags")
    serializer_class = RPCExecutionEventSerializer
