from __future__ import annotations


def execution_events(execution: object):
    return execution.events.all()


def ordered_execution_events(execution: object):
    return execution.events.all().order_by("sequence", "created")
