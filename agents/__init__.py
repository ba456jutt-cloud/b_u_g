from .base_agent import BaseAgent
from .recon_agent import ReconAnalysisAgent
from .cve_agent import CVEResearchAgent
from .code_review_agent import CodeReviewAgent
from .security_knowledge_agent import SecurityKnowledgeAgent
from .vulnerability_analysis_agent import VulnerabilityAnalysisAgent
from .report_agent import ReportAgent
from .master_agent import MasterAgent
from .tool_builder_agent import GeneralToolBuilderAgent
from .attack_chain_agent import AttackChainAgent
from .scope_agent import ScopeManagementAgent
from .passive_dns_agents import PassiveReconAgent, DNSIntelligenceAgent
from .host_port_agents import AliveHostAgent, PortScanAgent
from .web_enum_agents import WebCrawlingAgent, JSAnalysisAgent, ParamDiscoveryAgent, DirectoryEnumAgent
from .support_agents import EvidenceAgent, DeduplicationAgent, NotificationAgent, AuditLogAgent
from .patch_generator_agent import PatchGeneratorAgent
from .poc_agent import PoCVerificationAgent
from .ctf_solver_agent import CTFSolverAgent
from .initial_discovery_agent import InitialDiscoveryAgent
from .ml_scan_agent import MLScanAgent

# Aliases
ToolBuilderAgent = GeneralToolBuilderAgent

ALL_AGENTS = [
    "MasterAgent",
    "MLScanAgent",
    "InitialDiscoveryAgent",
    "ScopeManagementAgent",
    "PassiveReconAgent",
    "DNSIntelligenceAgent",
    "ReconAnalysisAgent",
    "AliveHostAgent",
    "PortScanAgent",
    "WebCrawlingAgent",
    "JSAnalysisAgent",
    "ParamDiscoveryAgent",
    "DirectoryEnumAgent",
    "VulnerabilityAnalysisAgent",
    "CVEResearchAgent",
    "AttackChainAgent",
    "EvidenceAgent",
    "DeduplicationAgent",
    "ReportAgent",
    "NotificationAgent",
    "AuditLogAgent",
    "GeneralToolBuilderAgent",
    "CodeReviewAgent",
    "SecurityKnowledgeAgent",
    "PatchGeneratorAgent",
    "PoCVerificationAgent",
    "CTFSolverAgent",
]

__all__ = ALL_AGENTS + ["BaseAgent", "ToolBuilderAgent"]

