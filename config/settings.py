import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    # LLM Settings
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    DEFAULT_MODEL = "gemini-2.5-flash"  # Using a fast standard model
    
    # Path Settings
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MEMORY_DB_PATH = os.path.join(BASE_DIR, "memory", "agent_memory.db")
    LOGS_DIR = os.path.join(BASE_DIR, "logs")

settings = Settings()

# Ensure logs directory exists
os.makedirs(settings.LOGS_DIR, exist_ok=True)
