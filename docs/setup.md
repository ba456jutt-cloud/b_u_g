# Developer Setup Guide

## Prerequisites
- Python 3.10+
- An active Gemini API Key (`GEMINI_API_KEY`)

## Installation
1. Clone the repository and navigate into it.
2. Set up the virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install google-genai python-dotenv pydantic
   ```
4. Configure environment variables:
   Copy `.env.example` to `.env` and fill in your Gemini API key.
   ```bash
   cp .env.example .env
   ```

## Running Tests
To ensure the router and agents are functioning correctly:
```bash
python3 -m unittest discover tests/
```

## Adding New Agents
To add a new agent in Phase 3:
1. Create `agents/new_agent.py`.
2. Subclass `BaseAgent`.
3. Override `_build_prompt` to inject custom instructions.
4. Export it in `agents/__init__.py`.
5. Add keyword matching for the new agent in `router/task_router.py`.
