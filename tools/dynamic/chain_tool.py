from tools.base import Tool
import subprocess
import time
import json
import importlib

class ChainTool(Tool):
    name = "chain"
    description = "Orchestrates a sequence of security operations against a target."
    parameters = {"target": "IP or hostname", "operations": "List of operations to perform"}

    def execute(self, target: str, operations: list, **kwargs) -> str:
        results = {}
        current_target = target
        
        for operation in operations:
            try:
                # Dynamically import the required tool
                tool_module = importlib.import_module(f"tools.{operation['tool']}")
                tool_class = getattr(tool_module, f"{operation['tool'].capitalize()}Tool")
                tool_instance = tool_class()
                
                # Prepare parameters for the tool
                params = {"target": current_target}
                params.update(operation.get('params', {}))
                
                # Execute the tool
                result = tool_instance.execute(**params)
                
                # Update results and current_target if necessary
                results[operation['tool']] = result
                if 'update_target' in operation and operation['update_target']:
                    current_target = result
                
            except Exception as e:
                results[operation['tool']] = f"Error executing {operation['tool']}: {str(e)}"
                
        return json.dumps(results)