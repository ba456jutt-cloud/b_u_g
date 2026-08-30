import logging
import os
import threading
from typing import Dict, Type
from pydantic import BaseModel
from tools.base import Tool

logger = logging.getLogger(__name__)

class ToolMetadata(BaseModel):
    name: str
    description: str
    parameters: dict
    version: str = "1.0.0"
    author: str = "System"
    status: str = "active"
    usage_count: int = 0

class ToolRegistry:
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ToolRegistry, cls).__new__(cls)
                cls._instance.tools = {}
                cls._instance.metadata = {}
                cls._instance.disabled_tools = set()
                cls._instance._register_default_tools()
            return cls._instance

    def _register_default_tools(self):
        # Register core system tools
        from tools.system import ReadFileTool, WriteFileTool, RunCommandTool, FetchURLTool
        from tools.memory_tools import SaveMemoryTool, RetrieveMemoryTool
        
        self.register_tool(ReadFileTool())
        self.register_tool(WriteFileTool())
        self.register_tool(RunCommandTool())
        self.register_tool(FetchURLTool())
        self.register_tool(SaveMemoryTool())
        self.register_tool(RetrieveMemoryTool())
        
        try:
            from tools.discovery_cache_tool import DiscoveryCacheTool
            self.register_tool(DiscoveryCacheTool())
        except Exception as e:
            logger.warning(f"DiscoveryCacheTool not loaded: {e}")
        
        # Optional redteaming tools
        try:
            from tools.redteaming.nmap_tool import NmapScanTool
            self.register_tool(NmapScanTool())
        except Exception as e:
            logger.warning(f"NmapScanTool not loaded: {e}")

        try:
            from tools.redteaming.zap_tool import ZAPScanTool
            self.register_tool(ZAPScanTool())
        except Exception as e:
            logger.warning(f"ZAPScanTool not loaded: {e}")

        try:
            from tools.redteaming.gobuster_tool import GobusterTool
            self.register_tool(GobusterTool())
        except Exception as e:
            logger.warning(f"GobusterTool not loaded: {e}")

        try:
            from tools.redteaming.nuclei_tool import NucleiTool
            self.register_tool(NucleiTool())
        except Exception as e:
            logger.warning(f"NucleiTool not loaded: {e}")

        try:
            from tools.redteaming.sqlmap_tool import SQLMapTool
            self.register_tool(SQLMapTool())
        except Exception as e:
            logger.warning(f"SQLMapTool not loaded: {e}")

        try:
            from tools.redteaming.whois_tool import WhoisTool
            self.register_tool(WhoisTool())
        except Exception as e:
            logger.warning(f"WhoisTool not loaded: {e}")

        try:
            from tools.redteaming.ssl_tool import SSLCheckerTool
            self.register_tool(SSLCheckerTool())
        except Exception as e:
            logger.warning(f"SSLCheckerTool not loaded: {e}")

        try:
            from tools.redteaming.nvd_cve_tool import NVDCVELookupTool
            self.register_tool(NVDCVELookupTool())
        except Exception as e:
            logger.warning(f"NVDCVELookupTool not loaded: {e}")

        try:
            from tools.redteaming.web_security_audit_tool import WebSecurityAuditTool
            self.register_tool(WebSecurityAuditTool())
        except Exception as e:
            logger.warning(f"WebSecurityAuditTool not loaded: {e}")

        try:
            from tools.redteaming.theharvester_tool import TheHarvesterTool
            self.register_tool(TheHarvesterTool())
        except Exception as e:
            logger.warning(f"TheHarvesterTool not loaded: {e}")

        try:
            from tools.redteaming.nikto_tool import NiktoTool
            self.register_tool(NiktoTool())
        except Exception as e:
            logger.warning(f"NiktoTool not loaded: {e}")

        try:
            from tools.redteaming.httpx_tool import HttpxProbeTool
            self.register_tool(HttpxProbeTool())
        except Exception as e:
            logger.warning(f"HttpxProbeTool not loaded: {e}")

        try:
            from tools.redteaming.ffuf_tool import FfufTool
            self.register_tool(FfufTool())
        except Exception as e:
            logger.warning(f"FfufTool not loaded: {e}")

        try:
            from tools.redteaming.whatweb_tool import WhatWebTool
            self.register_tool(WhatWebTool())
        except Exception as e:
            logger.warning(f"WhatWebTool not loaded: {e}")

        try:
            from tools.redteaming.waf_detect_tool import WafDetectTool
            self.register_tool(WafDetectTool())
        except Exception as e:
            logger.warning(f"WafDetectTool not loaded: {e}")

        try:
            from tools.redteaming.dnsrecon_tool import DnsReconTool
            self.register_tool(DnsReconTool())
        except Exception as e:
            logger.warning(f"DnsReconTool not loaded: {e}")

        try:
            from tools.redteaming.masscan_tool import MasscanTool
            self.register_tool(MasscanTool())
        except Exception as e:
            logger.warning(f"MasscanTool not loaded: {e}")

        try:
            from tools.redteaming.feroxbuster_tool import FeroxbusterTool
            self.register_tool(FeroxbusterTool())
        except Exception as e:
            logger.warning(f"FeroxbusterTool not loaded: {e}")

        try:
            from tools.redteaming.extra_tools import WpScanTool, AmassSubdomainTool, DnsDigTool, CurlHeadersTool
            self.register_tool(WpScanTool())
            self.register_tool(AmassSubdomainTool())
            self.register_tool(DnsDigTool())
            self.register_tool(CurlHeadersTool())
        except Exception as e:
            logger.warning(f"Extra tools not loaded: {e}")

        try:
            from tools.redteaming.subfinder_tool import SubfinderTool
            from tools.redteaming.subdomain_tools import AssetfinderTool, FindomainTool
            self.register_tool(SubfinderTool())
            self.register_tool(AssetfinderTool())
            self.register_tool(FindomainTool())
        except Exception as e:
            logger.warning(f"Subdomain tools not loaded: {e}")

        try:
            from tools.redteaming.dnsx_naabu_tools import DnsxProbeTool, NaabuPortScanTool
            self.register_tool(DnsxProbeTool())
            self.register_tool(NaabuPortScanTool())
        except Exception as e:
            logger.warning(f"DNSX / Naabu tools not loaded: {e}")

        try:
            from tools.redteaming.crawling_tools import KatanaCrawlerTool, GauUrlsTool
            self.register_tool(KatanaCrawlerTool())
            self.register_tool(GauUrlsTool())
        except Exception as e:
            logger.warning(f"Crawling tools not loaded: {e}")

        try:
            from tools.redteaming.advanced_sec_tools import (
                ArjunParamTool, GowitnessScreenshotTool, SemgrepSASTTool, TrivyScannerTool
            )
            self.register_tool(ArjunParamTool())
            self.register_tool(GowitnessScreenshotTool())
            self.register_tool(SemgrepSASTTool())
            self.register_tool(TrivyScannerTool())
        except Exception as e:
            logger.warning(f"Advanced sec tools not loaded: {e}")

        try:
            from tools.redteaming.poc_verifier_tool import PoCVerifierTool
            self.register_tool(PoCVerifierTool())
        except Exception as e:
            logger.warning(f"PoCVerifierTool not loaded: {e}")

        # ============ NEWLY ADDED OSINT & WEB TOOLS ============
        try:
            from tools.redteaming.shodan_tool import ShodanTool
            self.register_tool(ShodanTool())
        except Exception as e:
            logger.warning(f"ShodanTool not loaded: {e}")

        try:
            from tools.redteaming.sublist3r_tool import Sublist3rTool
            self.register_tool(Sublist3rTool())
        except Exception as e:
            logger.warning(f"Sublist3rTool not loaded: {e}")

        try:
            from tools.redteaming.gitleaks_tool import GitleaksTool
            self.register_tool(GitleaksTool())
        except Exception as e:
            logger.warning(f"GitleaksTool not loaded: {e}")

        try:
            from tools.redteaming.dirsearch_tool import DirsearchTool
            self.register_tool(DirsearchTool())
        except Exception as e:
            logger.warning(f"DirsearchTool not loaded: {e}")

        try:
            from tools.redteaming.wfuzz_tool import WfuzzTool
            self.register_tool(WfuzzTool())
        except Exception as e:
            logger.warning(f"WfuzzTool not loaded: {e}")

        try:
            from tools.redteaming.dalfox_tool import DalfoxTool
            self.register_tool(DalfoxTool())
        except Exception as e:
            logger.warning(f"DalfoxTool not loaded: {e}")

        try:
            from tools.redteaming.commix_tool import CommixTool
            self.register_tool(CommixTool())
        except Exception as e:
            logger.warning(f"CommixTool not loaded: {e}")

        try:
            from tools.redteaming.rustscan_tool import RustScanTool
            self.register_tool(RustScanTool())
        except Exception as e:
            logger.warning(f"RustScanTool not loaded: {e}")
        # ============ END NEW TOOLS ============

        try:
            from tools.ctf.ctf_tools import FlagScannerTool, CryptoDecoderTool, StegoForensicsTool, WebCTFSolverTool, AdvancedDecoderTool
            self.register_tool(FlagScannerTool())
            self.register_tool(CryptoDecoderTool())
            self.register_tool(StegoForensicsTool())
            self.register_tool(WebCTFSolverTool())
            self.register_tool(AdvancedDecoderTool())
        except Exception as e:
            logger.warning(f"CTF tools not loaded: {e}")

        try:
            from tools.ctf.web_exploit_tool import SSTIExploiterTool, LFIExploiterTool, LoginBruteforceTool, CommandInjectionTool
            self.register_tool(SSTIExploiterTool())
            self.register_tool(LFIExploiterTool())
            self.register_tool(LoginBruteforceTool())
            self.register_tool(CommandInjectionTool())
        except Exception as e:
            logger.warning(f"CTF web exploit tools not loaded: {e}")

        try:
            from tools.redteaming.security_rag_tool import SecurityRAGTool
            self.register_tool(SecurityRAGTool())
        except Exception as e:
            logger.warning(f"SecurityRAGTool not loaded: {e}")
        
        # Optional RAG/vector search tools
        try:
            from tools.search_tools import VectorSearchTool, CodeSearchTool
            self.register_tool(VectorSearchTool())
            self.register_tool(CodeSearchTool())
        except ImportError:
            logger.warning("VectorSearchTool/CodeSearchTool not loaded: chromadb not installed.")

        # Auto-load dynamically created tools from tools/dynamic/
        self._load_dynamic_tools()

    def _load_dynamic_tools(self):
        """Scans tools/dynamic/ directory and loads any Tool classes found. Validates each tool."""
        import importlib.util
        import inspect
        import ast
        dynamic_dir = os.path.join(os.path.dirname(__file__), "dynamic")
        if not os.path.exists(dynamic_dir):
            return
        for fname in os.listdir(dynamic_dir):
            if fname.endswith(".py") and not fname.startswith("__"):
                fpath = os.path.join(dynamic_dir, fname)
                # Validate syntax first — delete broken files
                try:
                    with open(fpath, 'r') as f:
                        ast.parse(f.read())
                except SyntaxError:
                    logger.warning(f"Deleting broken dynamic tool {fname} (syntax error)")
                    try:
                        os.remove(fpath)
                    except OSError:
                        pass
                    continue
                try:
                    spec = importlib.util.spec_from_file_location(fname[:-3], fpath)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if inspect.isclass(attr) and issubclass(attr, Tool) and attr is not Tool:
                            instance = attr()
                            if instance.name and instance.name not in self.tools:
                                self.register_tool(instance)
                                logger.info(f"Auto-loaded dynamic tool: {instance.name} from {fname}")
                except Exception as e:
                    logger.warning(f"Failed to load dynamic tool {fname}: {e}")

    def register(self, tool_class: Type[Tool], metadata: ToolMetadata):
        self.tools[tool_class.name] = tool_class() if isinstance(tool_class, type) else tool_class
        self.metadata[tool_class.name] = metadata
        logger.info(f"Registered tool: {tool_class.name} v{metadata.version}")

    def register_tool(self, tool_instance: Tool):
        """Register a tool instance directly (auto-generates metadata). Thread-safe."""
        name = tool_instance.name
        with self._lock:
            self.tools[name] = tool_instance
            self.metadata[name] = ToolMetadata(
                name=name,
                description=getattr(tool_instance, 'description', 'No description'),
                parameters=getattr(tool_instance, 'parameters', {}),
            )
        logger.info(f"Registered tool: {name}")

    def disable(self, tool_name: str):
        if tool_name in self.tools:
            self.disabled_tools.add(tool_name)
            self.metadata[tool_name].status = "disabled"
            logger.warning(f"Disabled tool: {tool_name}")

    def enable(self, tool_name: str):
        if tool_name in self.disabled_tools:
            self.disabled_tools.remove(tool_name)
            self.metadata[tool_name].status = "active"
            logger.info(f"Enabled tool: {tool_name}")

    def get_tool(self, tool_name: str) -> Type[Tool]:
        if tool_name in self.disabled_tools:
            raise ValueError(f"Tool {tool_name} is currently disabled.")
        return self.tools.get(tool_name)

    def increment_usage(self, tool_name: str):
        if tool_name in self.metadata:
            self.metadata[tool_name].usage_count += 1

    def get_all_active_tools(self) -> Dict[str, Type[Tool]]:
        return {name: tool for name, tool in self.tools.items() if name not in self.disabled_tools}

# Global registry instance
registry = ToolRegistry()
