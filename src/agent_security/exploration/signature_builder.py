from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.core.cells import CellSignature, cell_signature

from agent_security.config.explorer_settings import ExplorerSettings


class SignatureBuilder:
    """Builds cell signatures from environment traces."""

    def __init__(self, settings: ExplorerSettings) -> None:
        self._settings = settings

    def build(self, trace: Mapping[str, Any]) -> CellSignature:
        kwargs: dict[str, Any] = {
            "egress_data": trace.get("egress", []),
            "use_args": self._settings.use_args_in_signature,
            "use_outputs": self._settings.use_outputs_in_signature,
            "args_count": self._settings.args_count,
        }
        if self._settings.use_intent_hash:
            kwargs["user_messages"] = trace.get("user_messages", [])
        return cell_signature(trace["tool_events"], **kwargs)
