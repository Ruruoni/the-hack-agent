from .base import Tool, ToolRegistry, ToolResult
from .recon import HttpProbeTool, PortScanTool, SubdomainEnumTool
from .sast import SastScanTool, SecretScanTool
from .webscan import WebVulnScanTool


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for tool_cls in (
        PortScanTool,
        SubdomainEnumTool,
        HttpProbeTool,
        WebVulnScanTool,
        SastScanTool,
        SecretScanTool,
    ):
        registry.register(tool_cls())
    return registry


__all__ = [
    "Tool",
    "ToolRegistry",
    "ToolResult",
    "build_default_registry",
]
