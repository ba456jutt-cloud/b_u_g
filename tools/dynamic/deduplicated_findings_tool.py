from tools.base import Tool

class DeduplicatedFindingsTool(Tool):
    name = "deduplicated_findings"
    description = "Processes a list of security recommendations, removes duplicates, and returns a consolidated list."
    parameters = {
        "target": "Target URL or IP address",
        "stack": "Software stack information",
        "confirmed_vulnerabilities": "List of confirmed vulnerabilities",
        "patches_applied": "List of patches applied",
        "recommendations": "List of security recommendations",
        "total_recommendations_before_dedup": "Total number of recommendations before deduplication",
        "total_recommendations_after_dedup": "Total number of recommendations after deduplication",
        "duplicates_merged": "List of duplicates merged"
    }

    def execute(self, target: str = None, stack: str = None, confirmed_vulnerabilities: str = None, patches_applied: str = None, recommendations: list = None, total_recommendations_before_dedup: int = None, total_recommendations_after_dedup: int = None, duplicates_merged: list = None, **kwargs) -> str:
        try:
            if not recommendations:
                return "Error: No recommendations provided."

            deduplicated_recommendations = []
            seen_categories = set()
            merged_details = []

            for recommendation in recommendations:
                if recommendation['unique'] or recommendation['category'] not in seen_categories:
                    deduplicated_recommendations.append(recommendation)
                    seen_categories.add(recommendation['category'])
                else:
                    merged_details.append({
                        "original_id": recommendation['id'],
                        "merged_into": next((r['id'] for r in deduplicated_recommendations if r['category'] == recommendation['category']), None),
                        "reason": f"Duplicate of {recommendation['category']} recommendation"
                    })

            result = {
                "target": target,
                "stack": stack,
                "confirmed_vulnerabilities": confirmed_vulnerabilities,
                "patches_applied": patches_applied,
                "recommendations": deduplicated_recommendations,
                "total_recommendations_before_dedup": total_recommendations_before_dedup,
                "total_recommendations_after_dedup": len(deduplicated_recommendations),
                "duplicates_merged": merged_details
            }

            return str(result)
        except Exception as e:
            return f"Error: {str(e)}"