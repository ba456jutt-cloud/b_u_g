from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import asyncio
import json
import datetime
from typing import List
from config.settings import settings
from agents import __all__ as available_agents

app = FastAPI(title="Bug Bounty Copilot API")

# Allow Next.js frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── WebSocket Activity Bus ────────────────────────────────────────────────────
class ConnectionManager:
    """Manages all active WebSocket connections and broadcasts agent activity events."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event: dict):
        """Send event to all connected frontend clients."""
        message = json.dumps(event)
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# Global event loop reference for thread-safe publishing from sync agents
_event_loop = None

def get_event_loop():
    global _event_loop
    return _event_loop

@app.on_event("startup")
async def startup_event():
    global _event_loop
    _event_loop = asyncio.get_event_loop()

def publish_activity(event_type: str, **kwargs):
    """
    Thread-safe publish — called from synchronous agent code.
    Sends event to all WebSocket clients.
    Event types: tool_start | tool_output | tool_error | agent_thought | agent_done | agent_step
    """
    loop = get_event_loop()
    if loop is None or not loop.is_running():
        return  # No WS clients yet — skip gracefully
    event = {
        "type": event_type,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        **kwargs
    }
    # Schedule broadcast on the event loop from a thread
    asyncio.run_coroutine_threadsafe(manager.broadcast(event), loop)

# Make publish_activity importable by agents
import builtins
builtins._publish_activity = publish_activity

# ─── WebSocket Endpoint ─────────────────────────────────────────────────────
@app.websocket("/ws/activity")
async def websocket_activity(websocket: WebSocket):
    """Real-time agent activity stream — connects frontend to live tool events."""
    await manager.connect(websocket)
    # Send welcome ping
    await websocket.send_text(json.dumps({
        "type": "connected",
        "message": "Agent Activity Stream connected",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }))
    try:
        while True:
            # Keep connection alive — wait for client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)


class TaskRequest(BaseModel):
    task: str
    workflow: str = None

@app.get("/")
def read_root():
    return {"status": "Active", "system": "Bug Bounty Copilot Phase 3"}

@app.get("/agents")
def list_agents():
    # Dynamically list registered agents from the package
    return {"agents": available_agents}

@app.post("/tasks")
def submit_task(req: TaskRequest):
    import uuid
    from core.queue import process_task_async
    
    task_id = str(uuid.uuid4())
    process_task_async(req.task, req.workflow, task_id)
    
    return {"status": "Task Queued", "task_id": task_id, "task": req.task, "assigned_workflow": req.workflow, "message": "Executing in background"}

@app.get("/tasks/{task_id}/logs")
def get_task_logs(task_id: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, agent_name, log_type, content FROM execution_logs WHERE task_id = ? ORDER BY id ASC", (task_id,))
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"task_id": task_id, "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tasks/{task_id}/resume")
def resume_task(task_id: str):

    """Resume a stopped, cancelled, or failed scan task from its last saved checkpoint."""
    from memory.sqlite_mem import MemoryDB
    from core.queue import process_task_async

    mem = MemoryDB()
    checkpoint = mem.get_checkpoint(task_id)
    if not checkpoint:
        # Check if logs exist to resume
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM execution_logs WHERE task_id = ? AND agent_name = 'System' ORDER BY id ASC LIMIT 1", (task_id,))
        row = cursor.fetchone()
        conn.close()
        task_name = row["content"].replace("Received Task: ", "") if row else f"Resume task {task_id}"
    else:
        task_name = checkpoint["task_name"]

    # 1. Clear cancellation state from DB
    mem.uncancel_task(task_id)

    # 2. Re-dispatch task to queue with existing task_id
    process_task_async(task_name, None, task_id)

    return {
        "status": "Task Resumed",
        "task_id": task_id,
        "task_name": task_name,
        "checkpoint": checkpoint,
        "message": "Task resumed from last saved checkpoint."
    }

@app.get("/tasks/{task_id}/checkpoint")
def get_task_checkpoint(task_id: str):
    """Retrieve saved phase checkpoint data for task."""
    from memory.sqlite_mem import MemoryDB
    mem = MemoryDB()
    cp = mem.get_checkpoint(task_id)
    return {"task_id": task_id, "checkpoint": cp}


@app.get("/memory")
def get_memory_stats():
    # Query actual SQLite DB
    try:
        conn = sqlite3.connect(settings.MEMORY_DB_PATH)
        cursor = conn.cursor()
        
        tables = ["session_logs", "key_findings", "project_memory", "research_memory", "user_notes"]
        stats = {}
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = cursor.fetchone()[0]
            
        conn.close()
        return {"status": "Memory System Online", "record_counts": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/knowledge")
def get_knowledge_base():
    return {"status": "RAG System Online", "vector_db": "ChromaDB available in memory dir"}

def get_db_connection():
    conn = sqlite3.connect(settings.MEMORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/provider-status")
def get_provider_status():
    """
    Returns the live health status of all LLM providers.
    Shows whether a provider is available or if its circuit breaker is open due to quota/errors.
    """
    try:
        from core.model_router import ModelRouter
        router = ModelRouter()
        status = router.get_status()
        return {
            "status": "ok",
            "providers": status,
            "routing_table": router.routing_table,
            "message": "Use DeepSeek for heavy tasks (Recon, Master, ToolBuilder), Gemini for research (CVE, Report)"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/projects")
def list_projects():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM projects ORDER BY created_at DESC")
        projects = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"projects": projects}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/findings")
def list_findings():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings ORDER BY created_at DESC")
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tasks/active")
def list_active_tasks():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT task_id, MIN(timestamp) as started_at, MAX(timestamp) as last_updated, 
                   (SELECT content FROM execution_logs e2 WHERE e2.task_id = e1.task_id AND e2.log_type = 'System' ORDER BY id ASC LIMIT 1) as task_name
            FROM execution_logs e1 
            GROUP BY task_id 
            ORDER BY last_updated DESC LIMIT 5
        ''')
        tasks = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"tasks": tasks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics")
def get_analytics():
    """
    Returns live agent reward scores, efficiency ratings, reflection counts, and tool stats.
    """
    try:
        from memory.sqlite_mem import MemoryDB
        from tools.registry import registry
        memory = MemoryDB()
        
        from agents import ALL_AGENTS
        leaderboard = []
        for agent_name in ALL_AGENTS:
            perf = memory.get_agent_performance_score(agent_name)
            if perf["success_actions"] > 0 or perf["penalties"] > 0:
                leaderboard.append(perf)
        
        leaderboard.sort(key=lambda x: x["total_score"], reverse=True)
        
        all_tools = registry.get_all_active_tools()
        dynamic_tools = [t for t in all_tools.keys() if "http_security" in t or "custom" in t or t not in ["dns_lookup", "nmap_scan", "ssl_check"]]

        return {
            "status": "ok",
            "agent_leaderboard": leaderboard,
            "total_registered_tools": len(all_tools),
            "dynamic_tools_count": len(dynamic_tools),
            "active_tools_list": list(all_tools.keys())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tools/dynamic")
def list_dynamic_tools():
    """
    Returns all dynamically synthesized Python security tools created by ToolBuilderAgent.
    """
    try:
        import os
        tools_dir = os.path.join(os.getcwd(), "tools", "dynamic")
        if not os.path.exists(tools_dir):
            return {"dynamic_tools": []}
        
        files = [f for f in os.listdir(tools_dir) if f.endswith(".py") and not f.startswith("__")]
        tools_info = []
        for file_name in files:
            path = os.path.join(tools_dir, file_name)
            stat = os.stat(path)
            tools_info.append({
                "file_name": file_name,
                "size_bytes": stat.st_size,
                "created_at": stat.st_mtime
            })
        return {"dynamic_tools": tools_info}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── PoC Verifier Endpoint ─────────────────────────────────────────────────────
class PoCRequest(BaseModel):
    target_url: str
    vuln_type: str = "all"          # sqli | xss | ssrf | open_redirect | path_traversal | crlf | cmdi | ssti | idor | all
    param_name: str = ""            # Which query param to inject into
    inject_in_path: bool = False    # Inject into URL path instead of query param
    max_payloads: int = 5           # Max payloads per category (max 10)
    request_delay: float = 0.5     # Delay between requests (seconds)

@app.post("/scan/poc")
def run_poc_verification(req: PoCRequest):
    """
    Direct PoC Verification endpoint.
    Runs the PoCVerifierTool against a target URL with the specified vulnerability type.
    This endpoint does NOT go through the full agent pipeline — it runs the tool directly
    for fast, targeted testing.

    IMPORTANT: Only use on authorized targets within your bug bounty/pentest scope.
    """
    try:
        from tools.redteaming.poc_verifier_tool import PoCVerifierTool
        tool = PoCVerifierTool()
        result = tool.execute(
            target_url=req.target_url,
            vuln_type=req.vuln_type,
            param_name=req.param_name,
            inject_in_path=req.inject_in_path,
            max_payloads=req.max_payloads,
            request_delay=req.request_delay,
        )
        return {
            "status": "ok",
            "target_url": req.target_url,
            "vuln_type": req.vuln_type,
            "result": result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/poc/payloads")
def list_poc_payloads():
    """
    Returns the full payload library — all vulnerability categories with their
    test payloads, descriptions, risk levels, and detection patterns.
    Useful for understanding what the PoC Verifier will test.
    """
    try:
        from tools.redteaming.poc_verifier_tool import PAYLOAD_LIBRARY
        summary = {}
        for category, lib in PAYLOAD_LIBRARY.items():
            summary[category] = {
                "description": lib["description"],
                "risk": lib["risk"],
                "payload_count": len(lib["payloads"]),
                "payloads": [
                    {"name": p[0], "payload": p[1], "expected_evidence": p[2]}
                    for p in lib["payloads"]
                ],
            }
        return {"payload_library": summary, "total_categories": len(summary)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str):
    """Cancel an actively running task."""
    try:
        from memory.sqlite_mem import MemoryDB
        memory = MemoryDB()
        memory.cancel_task(task_id)
        publish_activity("agent_done", result="Task cancelled by user.", task_id=task_id)
        return {"status": "Task cancellation requested", "task_id": task_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/tasks/{task_id}")
def delete_task(task_id: str):

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM execution_logs WHERE task_id = ?", (task_id,))
        conn.commit()
        conn.close()
        return {"status": "Task deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents/{agent_name}/logs")
def get_agent_logs(agent_name: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, task_id, log_type, content FROM execution_logs WHERE agent_name = ? ORDER BY timestamp DESC LIMIT 50", (agent_name,))
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"agent_name": agent_name, "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ChatRequest(BaseModel):
    message: str

@app.post("/agents/{agent_name}/chat")
def chat_with_agent(agent_name: str, req: ChatRequest):
    import uuid
    import agents
    from memory.sqlite_mem import MemoryDB
    from router.task_router import TaskRouter
    from core.model_router import ModelRouter
    from tools.registry import registry
    
    try:
        # Check if agent exists
        if not hasattr(agents, agent_name):
            raise HTTPException(status_code=404, detail="Agent not found")
            
        AgentClass = getattr(agents, agent_name)
        
        # Initialize dependencies
        memory = MemoryDB()
        router = TaskRouter()
        model_router = ModelRouter()
        tools = list(registry.get_all_active_tools().values())
        
        # Initialize the specific agent
        llm_provider = model_router.get_provider(agent_name)
        agent_instance = AgentClass(llm_provider=llm_provider, memory=memory, router=router, tools=tools)
        
        chat_task_id = f"chat-{uuid.uuid4().hex[:8]}"
        memory.log_execution(chat_task_id, "System", "Status", f"Direct chat initiated with {agent_name}")
        
        # Run agent synchronously
        result = agent_instance.run(req.message, task_id=chat_task_id)
        
        return {"status": "success", "agent": agent_name, "response": result, "chat_id": chat_task_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tasks/{task_id}/report")
def generate_report(task_id: str):
    from fastapi.responses import HTMLResponse
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, agent_name, log_type, content FROM execution_logs WHERE task_id = ? ORDER BY id ASC", (task_id,))
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        from tools.report_generator import generate_html_report
        html = generate_html_report(task_id, logs)
        return HTMLResponse(content=html, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total scans (distinct task_ids)
        cursor.execute("SELECT COUNT(DISTINCT task_id) as total FROM execution_logs")
        total_scans = cursor.fetchone()["total"]
        
        # Total findings
        cursor.execute("SELECT COUNT(*) as total FROM key_findings")
        total_findings = cursor.fetchone()["total"]
        
        # Recent scans
        cursor.execute("""
            SELECT task_id, MIN(timestamp) as started_at,
                   (SELECT content FROM execution_logs e2 WHERE e2.task_id = e1.task_id ORDER BY id ASC LIMIT 1) as task_name
            FROM execution_logs e1 GROUP BY task_id ORDER BY started_at DESC LIMIT 7
        """)
        recent_scans = [dict(row) for row in cursor.fetchall()]
        
        # Severity breakdown from findings
        cursor.execute("SELECT value FROM key_findings")
        findings_rows = cursor.fetchall()
        conn.close()
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in findings_rows:
            content = str(row["value"]).lower()
            if "critical" in content:
                severity_counts["critical"] += 1
            elif "high" in content:
                severity_counts["high"] += 1
            elif "medium" in content:
                severity_counts["medium"] += 1
            elif "low" in content:
                severity_counts["low"] += 1
            else:
                severity_counts["info"] += 1
        
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "recent_scans": recent_scans
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─── Burp Suite Integration Endpoint ─────────────────────────────────────────
class BurpScanRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}
    body: str = ""
    vuln_type: str = "all"   # sqli | xss | ssrf | all
    source: str = "burp"     # who triggered this scan

@app.post("/burp/scan")
def burp_scan(req: BurpScanRequest):
    """
    Burp Suite Extension Integration Endpoint.
    Accepts a request from the Burp extension and runs PoC verification on it.
    Returns structured findings for display in Burp's Results tab.
    """
    try:
        publish_activity(
            "tool_start",
            tool="poc_verifier",
            source="burp_extension",
            args={"url": req.url, "vuln_type": req.vuln_type}
        )
        from tools.redteaming.poc_verifier_tool import PoCVerifierTool
        tool = PoCVerifierTool()
        result = tool.execute(
            target_url=req.url,
            vuln_type=req.vuln_type,
            max_payloads=5,
            request_delay=0.3,
        )
        publish_activity(
            "tool_output",
            tool="poc_verifier",
            source="burp_extension",
            output=result[:500]
        )
        return {
            "status": "ok",
            "source": req.source,
            "url": req.url,
            "vuln_type": req.vuln_type,
            "result": result,
        }
    except Exception as e:
        publish_activity("tool_error", tool="poc_verifier", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/burp/status")
def burp_status():
    """Health check endpoint for Burp extension to verify connection."""
    return {
        "status": "connected",
        "system": "Bug Bounty Copilot",
        "ws_endpoint": "ws://localhost:8000/ws/activity",
        "scan_endpoint": "http://localhost:8000/burp/scan",
        "poc_endpoint": "http://localhost:8000/scan/poc",
    }


class SettingsRequest(BaseModel):
    gemini_api_key: str = None
    deepseek_api_key: str = None
    openrouter_api_key: str = None
    default_model: str = None

@app.get("/settings")
def get_settings():
    from config.settings import settings
    return {
        "default_model": settings.DEFAULT_MODEL,
        "gemini_key_set": bool(settings.GEMINI_API_KEY),
        "deepseek_key_set": bool(settings.DEEPSEEK_API_KEY),
        "openrouter_key_set": bool(settings.OPENROUTER_API_KEY),
        "memory_db_path": str(settings.MEMORY_DB_PATH),
    }

@app.post("/settings")
def update_settings(req: SettingsRequest):
    import os
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    try:
        # Read existing .env
        lines = []
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()
        
        updates = {}
        if req.gemini_api_key:
            updates["GEMINI_API_KEY"] = req.gemini_api_key
        if req.deepseek_api_key:
            updates["DEEPSEEK_API_KEY"] = req.deepseek_api_key
        if req.openrouter_api_key:
            updates["OPENROUTER_API_KEY"] = req.openrouter_api_key
        if req.default_model:
            updates["DEFAULT_MODEL"] = req.default_model
        
        # Update or append
        updated_keys = set()
        new_lines = []
        for line in lines:
            key = line.split("=")[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}\n")
                updated_keys.add(key)
            else:
                new_lines.append(line)
        
        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={value}\n")
        
        with open(env_path, "w") as f:
            f.writelines(new_lines)
        
        return {"status": "Settings saved. Restart the backend for changes to take effect."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, ws_ping_interval=20, ws_ping_timeout=20)
