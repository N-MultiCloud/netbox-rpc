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
from ..application.command_handlers import cancel_execution, create_execution
from ..application.queries import execution_events
from .serializers import (
    RPCBackendSerializer,
    RPCLinuxServiceAllowlistSerializer,
    RPCExecutionEventSerializer,
    RPCExecutionSerializer,
    RPCProcedureSerializer,
)


class RPCBackendViewSet(NetBoxModelViewSet):
    queryset = models.RPCBackend.objects.prefetch_related("tags")
    serializer_class = RPCBackendSerializer


class RPCProcedureViewSet(NetBoxModelViewSet):
    queryset = models.RPCProcedure.objects.prefetch_related("tags")
    serializer_class = RPCProcedureSerializer

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["get"], url_path="available")
    def available(self, request: Request) -> Response:
        from django.db.models import Q

        target_type = (request.query_params.get("target_type") or "").strip().lower()
        qs = models.RPCProcedure.objects.filter(enabled=True).prefetch_related("tags")
        if target_type:
            # Include procedures with no target restriction (empty list) or those
            # that explicitly allow the requested target type.
            qs = qs.filter(
                Q(target_models=[]) | Q(target_models__contains=[target_type])
            )
        page = self.paginate_queryset(qs)
        serializer = self.get_serializer(page if page is not None else qs, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class RPCLinuxServiceAllowlistViewSet(NetBoxModelViewSet):
    queryset = models.RPCLinuxServiceAllowlist.objects.prefetch_related("tags")
    serializer_class = RPCLinuxServiceAllowlistSerializer


class RPCExecutionViewSet(NetBoxModelViewSet):
    http_method_names = ["get", "post", "delete", "head", "options"]
    queryset = models.RPCExecution.objects.select_related(
        "procedure",
        "assigned_object_type",
        "requested_by",
    ).prefetch_related("tags")
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
