from __future__ import annotations

import jsonschema
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import serializers as drf_serializers
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from .. import models
from ..jobs import RPCExecutionJob
from .serializers import (
    RPCLinuxServiceAllowlistSerializer,
    RPCExecutionEventSerializer,
    RPCExecutionSerializer,
    RPCProcedureSerializer,
)


class RPCProcedureViewSet(NetBoxModelViewSet):
    queryset = models.RPCProcedure.objects.prefetch_related("tags")
    serializer_class = RPCProcedureSerializer

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["get"], url_path="available")
    def available(self, request):
        from django.db.models import Q

        target_type = (request.query_params.get("target_type") or "").strip().lower()
        qs = models.RPCProcedure.objects.filter(enabled=True).prefetch_related("tags")
        if target_type:
            # Include procedures with no target restriction (empty list) or those
            # that explicitly allow the requested target type.
            qs = qs.filter(Q(target_models=[]) | Q(target_models__contains=[target_type]))
        page = self.paginate_queryset(qs)
        serializer = self.get_serializer(page if page is not None else qs, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class RPCLinuxServiceAllowlistViewSet(NetBoxModelViewSet):
    queryset = models.RPCLinuxServiceAllowlist.objects.prefetch_related("tags")
    serializer_class = RPCLinuxServiceAllowlistSerializer


class RPCExecutionViewSet(NetBoxModelViewSet):
    queryset = models.RPCExecution.objects.select_related(
        "procedure",
        "assigned_object_type",
        "requested_by",
        "backend",
    ).prefetch_related("tags")
    serializer_class = RPCExecutionSerializer

    def create(self, request, *args, **kwargs):
        if not request.user.has_perm("netbox_rpc.execute_rpcprocedure"):
            raise PermissionDenied("execute_rpcprocedure permission is required.")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        procedure = serializer.validated_data["procedure"]
        if not procedure.enabled:
            raise drf_serializers.ValidationError(
                {"procedure_id": "This procedure is disabled."}
            )
        if procedure.approval_required:
            if not request.user.has_perm("netbox_rpc.approve_rpcprocedure"):
                raise PermissionDenied(
                    "This procedure requires approval (approve_rpcprocedure permission)."
                )
        params = serializer.validated_data.get("params") or {}
        if procedure.params_schema:
            try:
                jsonschema.validate(params, procedure.params_schema)
            except jsonschema.ValidationError as exc:
                raise drf_serializers.ValidationError(
                    {"params": exc.message}
                ) from exc

        execution = serializer.save(requested_by=request.user)
        try:
            job = RPCExecutionJob.enqueue(
                instance=execution,
                user=request.user,
                name=f"RPC Execution: {execution.procedure.name}",
                backend_pk=execution.backend_id,
            )
        except Exception:
            # Enqueue failed (e.g. Redis unavailable). Mark the execution failed so
            # it doesn't sit permanently in STATUS_QUEUED with no associated job.
            execution.status = models.RPCExecution.STATUS_FAILED
            execution.error_code = "RPC_ENQUEUE_FAILED"
            execution.error_message = (
                "Failed to enqueue RPC job. Check RQ/Redis connectivity."
            )
            execution.save(update_fields=["status", "error_code", "error_message"])
            raise

        execution.job_id = job.pk
        execution.save(update_fields=["job_id"])
        output = self.get_serializer(execution)
        return Response(output.data, status=status.HTTP_201_CREATED)

    @extend_schema(responses={200: RPCExecutionEventSerializer(many=True)})
    @action(detail=True, methods=["get"], url_path="events")
    def events(self, request, pk=None):
        execution = self.get_object()
        qs = execution.events.all()
        page = self.paginate_queryset(qs)
        serializer = RPCExecutionEventSerializer(
            page if page is not None else qs,
            many=True,
            context={"request": request},
        )
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class RPCExecutionEventViewSet(NetBoxModelViewSet):
    queryset = models.RPCExecutionEvent.objects.select_related("execution").prefetch_related("tags")
    serializer_class = RPCExecutionEventSerializer
