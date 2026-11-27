"""Feature extraction helpers for flow and host-window context."""

from .host_window import HostWindowAggregator, enrich_flow_with_host_context

__all__ = ["HostWindowAggregator", "enrich_flow_with_host_context"]
