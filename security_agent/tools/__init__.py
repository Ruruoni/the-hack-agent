from .ai_redteam import AiAgentRedTeamTool
from .base import Tool, ToolRegistry, ToolResult
from .bruteforce import DirectoryBruteforceTool
from .http_request import HttpRequestTool
from .injection import SqlInjectionTestTool
from .jwt_analysis import JwtAnalyzeTool
from .recon import HttpProbeTool, PortScanTool, SubdomainEnumTool
from .sast import SastScanTool, SecretScanTool
from .tls import TlsScanTool
from .webscan import WebVulnScanTool


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for tool_cls in (
        # passive recon
        PortScanTool,
        SubdomainEnumTool,
        HttpProbeTool,
        TlsScanTool,
        JwtAnalyzeTool,
        # active scanning
        WebVulnScanTool,
        DirectoryBruteforceTool,
        HttpRequestTool,
        SqlInjectionTestTool,  # detect-only unless dump=True (then exploitation, approval-gated)
        AiAgentRedTeamTool,  # prompt-injection/jailbreak probes against an AI agent/LLM target
        # local source analysis
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
