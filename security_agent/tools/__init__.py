from .active_directory import ActiveDirectoryReconTool
from .ai_redteam import AiAgentRedTeamTool
from .api_fuzz import ApiFuzzTool
from .base import Tool, ToolRegistry, ToolResult
from .binary_analysis import BinaryAnalysisTool
from .bruteforce import DirectoryBruteforceTool
from .bug_report import FormatBugReportTool, SubmitBugReportTool
from .cloud_posture import CloudPostureScanTool
from .container_security import ContainerImageScanTool, K8sLiveScanTool
from .credential_attacks import CredentialTestTool, HashCrackTool
from .deep_secrets import DeepSecretScanTool
from .fast_scan import FastPortScanTool
from .http_request import HttpRequestTool
from .injection import SqlInjectionTestTool
from .jwt_analysis import JwtAnalyzeTool
from .osint import EmailHarvestTool, UsernameOsintTool
from .packet_capture import PacketCaptureTool
from .phishing_simulation import PhishingSimulationTool
from .recon import HttpProbeTool, PortScanTool, SubdomainEnumTool
from .remediation import ApplyFixToRepoTool, ProposeFixTool
from .sast import SastScanTool, SecretScanTool
from .smart_contract import SmartContractScanTool
from .tls import TlsScanTool
from .traffic_capture import TrafficCaptureTool
from .webscan import WebVulnScanTool


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for tool_cls in (
        # passive recon
        PortScanTool,
        FastPortScanTool,  # RustScan, full-range alternative to port_scan
        SubdomainEnumTool,
        HttpProbeTool,
        TlsScanTool,
        JwtAnalyzeTool,
        EmailHarvestTool,  # domain -> emails/subdomains from public sources
        PacketCaptureTool,  # bounded tcpdump capture on a local interface
        # active scanning
        WebVulnScanTool,
        DirectoryBruteforceTool,
        HttpRequestTool,
        SqlInjectionTestTool,  # detect-only unless dump=True (then exploitation, approval-gated)
        AiAgentRedTeamTool,  # prompt-injection/jailbreak probes against an AI agent/LLM target
        K8sLiveScanTool,  # live cluster network endpoint
        ApiFuzzTool,  # schema-driven API fuzzing
        TrafficCaptureTool,  # bounded reverse-proxy traffic capture
        ActiveDirectoryReconTool,  # BloodHound collector, read-only AD relationship mapping
        # exploitation (always human-approval-gated regardless of scope.yaml)
        CredentialTestTool,  # Hydra, <=25 candidates against one named account
        HashCrackTool,  # Hashcat, offline crack of an already-extracted hash file
        PhishingSimulationTool,  # GoPhish, launches a pre-built/pre-reviewed campaign only
        # remediation (draft is free; applying is a write action, always gated)
        ProposeFixTool,  # drafts a reviewable fix -- never touches the target
        ApplyFixToRepoTool,  # applies a fix to a LOCAL repo clone -- always gated
        # bug reporting (formatting is free; sending is external, always gated)
        FormatBugReportTool,  # drafts a standard report file -- never sent anywhere
        SubmitBugReportTool,  # actually sends it (email/API) -- always gated
        # local source / credentialed audit / subject-scoped OSINT (authorize_local_action)
        SastScanTool,
        SecretScanTool,
        DeepSecretScanTool,  # TruffleHog, complements secret_scan with live verification
        CloudPostureScanTool,  # audits your own cloud account via local credentials
        ContainerImageScanTool,  # image/IaC scan, read-only inspection
        SmartContractScanTool,  # local Solidity source
        BinaryAnalysisTool,  # local binary/firmware triage via Ghidra headless
        UsernameOsintTool,  # username/subject-scoped, not a network host
    ):
        registry.register(tool_cls())
    return registry


__all__ = [
    "Tool",
    "ToolRegistry",
    "ToolResult",
    "build_default_registry",
]
