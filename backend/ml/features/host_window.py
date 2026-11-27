"""Public flow-window feature builder; implementation is shared with CICIDS preprocessing."""

from ml.preprocessing.cicids_pipeline import HostWindowAggregator, enrich_flow_with_host_context

__all__ = ["HostWindowAggregator", "enrich_flow_with_host_context"]
