from tools.base import Tool
import requests
import os

class WriteFileTool(Tool):
    name = "write_file"
    description = "Writes a file to a WordPress site using the WordPress REST API or other common endpoints."
    parameters = {
        "target": "Target WordPress site URL",
        "username": "WordPress username",
        "password": "WordPress password",
        "file_path": "Local file path to upload",
        "remote_path": "Remote file path on the server"
    }

    def execute(self, target: str, username: str, password: str, file_path: str, remote_path: str, **kwargs) -> str:
        try:
            # Authenticate with the WordPress site
            auth_url = f"{target}/wp-json/jwt-auth/v1/token"
            auth_data = {
                "username": username,
                "password": password
            }
            auth_response = requests.post(auth_url, json=auth_data, timeout=10)
            auth_response.raise_for_status()
            token = auth_response.json().get("token")

            # Upload the file to the WordPress site
            upload_url = f"{target}/wp-json/wp/v2/media"
            headers = {
                "Authorization": f"Bearer {token}"
            }
            files = {
                "file": (os.path.basename(file_path), open(file_path, "rb"), "application/octet-stream")
            }
            upload_response = requests.post(upload_url, headers=headers, files=files, timeout=30)
            upload_response.raise_for_status()

            # Move the file to the desired remote path
            file_id = upload_response.json().get("id")
            move_url = f"{target}/wp-json/wp/v2/media/{file_id}"
            move_data = {
                "title": os.path.basename(remote_path),
                "status": "inherit"
            }
            move_response = requests.post(move_url, headers=headers, json=move_data, timeout=10)
            move_response.raise_for_status()

            return f"File uploaded and moved to {remote_path} successfully."
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Request failed: {str(e)}"
        except Exception as e:
            return f"[ERROR] An unexpected error occurred: {str(e)}"