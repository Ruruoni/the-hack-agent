from .ai_redteam import AiAgentRedTeamTool
from .api_fuzz import ApiFuzzTool
from .base import Tool, ToolRegistry, ToolResult
from .bruteforce import DirectoryBruteforceTool
from .cloud_posture import CloudPostureScanTool
from .container_security import ContainerImageScanTool, K8sLiveScanTool
from .http_request import HttpRequestTool
from .injection import SqlInjectionTestTool
from .jwt_analysis import JwtAnalyzeTool
from .recon import HttpProbeTool, PortScanTool, SubdomainEnumTool
from .sast import SastScanTool, SecretScanTool
from .smart_contract import SmartContractScanTool
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
        K8sLiveScanTool,  # live cluster network endpoint
        ApiFuzzTool,  # schema-driven API fuzzing
        # local source / credentialed audit (authorize_local_action, no network target)
        SastScanTool,
        SecretScanTool,
        CloudPostureScanTool,  # audits your own cloud account via local credentials
        ContainerImageScanTool,  # image/IaC scan, read-only inspection
        SmartContractScanTool,  # local Solidity source
    ):
        registry.register(tool_cls())
    return registry


__all__ = [
    "Tool",
    "ToolRegistry",
    "ToolResult",
    "build_default_registry",
]
