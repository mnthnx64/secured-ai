# SecuredAI Backend

FastAPI backend that exposes CrewAI agents for the SecuredAI Lab webapp.

## Features

- **CrewAI Integration**: Real agent execution with vulnerable and secure agents
- **Policy Enforcement**: OWASP ASI02 mitigations applied in real-time
- **SSE Streaming**: Real-time thinking and logging output
- **BYOK**: Uses your own API key passed from the frontend

## Local Development

### Prerequisites

- Python 3.11+
- uv or pip

### Setup

```bash
# From project root
cd backend

# Install dependencies
pip install -r requirements.txt

# Or with uv
uv pip install -r requirements.txt

# Run the server
uvicorn main:app --reload --port 8080
```

### Test the API

```bash
# Health check
curl http://localhost:8080/api/health

# List attacks
curl http://localhost:8080/api/attacks

# Execute a prompt (replace YOUR_API_KEY)
curl -X POST http://localhost:8080/api/execute \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Look up customer C001",
    "agent_type": "both",
    "provider": "gemini",
    "api_key": "YOUR_GEMINI_API_KEY"
  }'
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root endpoint - returns API info |
| `/api/health` | GET | Health check for deployment monitoring |
| `/api/attacks` | GET | List available attack scenarios |
| `/api/execute` | POST | Execute prompt against CrewAI agent(s) |
| `/api/execute/stream` | POST | Execute with SSE streaming |

## Deployment

### Railway

1. Connect your GitHub repo to Railway
2. Railway will auto-detect the `railway.json` config
3. Set any environment variables if needed
4. Deploy!

### Render

1. Connect your GitHub repo to Render
2. Render will use the `render.yaml` blueprint
3. Deploy!

### Manual (Any Platform)

```bash
# Set PORT environment variable
export PORT=8080

# Run with uvicorn
cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | Server port (default: 8080) | No |
| `GEMINI_API_KEY` | Default Gemini API key | No (uses request key) |
| `OPENAI_API_KEY` | Default OpenAI API key | No (uses request key) |

## CORS Configuration

The backend allows requests from:
- `https://mnthnx64.github.io` (GitHub Pages)
- `http://localhost:8000` and `http://localhost:3000` (local dev)

Update `main.py` if you need to add more origins.

