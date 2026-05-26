from __future__ import annotations

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from netbox.api.viewsets import NetBoxModelViewSet
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
        target_type = (request.query_params.get("target_type") or "").strip().lower()
        qs = self.queryset.filter(enabled=True)
        items = []
        for procedure in qs:
            allowed = {str(item).lower() for item in procedure.target_models or []}
            if target_type and allowed and target_type not in allowed:
                continue
            items.append(procedure)
        page = self.paginate_queryset(items)
        serializer = self.get_serializer(page if page is not None else items, many=True)
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
        execution = serializer.save(requested_by=request.user)
        job = RPCExecutionJob.enqueue(
            instance=execution,
            user=request.user,
            name=f"RPC Execution: {execution.procedure.name}",
            backend_pk=execution.backend_id,
        )
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
