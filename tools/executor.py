import logging
import json
from tools.registry import registry

logger = logging.getLogger(__name__)

class ToolExecutor:
    @staticmethod
    def execute(tool_name: str, kwargs: dict) -> str:
        """
        Standardizes tool execution, validation, and JSON output formatting.
        """
        output = {
            "tool": tool_name,
            "input": kwargs,
            "output": None,
            "status": "pending"
        }
        
        try:
            tool_item = registry.get_tool(tool_name)
            if not tool_item:
                raise ValueError(f"Tool '{tool_name}' not found in registry.")
                
            tool_instance = tool_item() if isinstance(tool_item, type) else tool_item
            result = tool_instance.execute(**kwargs)
            
            output["output"] = result
            output["status"] = "success"
            registry.increment_usage(tool_name)
            
        except Exception as e:
            logger.error(f"Execution failed for {tool_name}: {str(e)}")
            output["output"] = str(e)
            output["status"] = "error"
            
        return json.dumps(output, indent=2)
