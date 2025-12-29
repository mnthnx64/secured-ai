# SecuredAI Lab - Web Application

Interactive web application for exploring AI agent security vulnerabilities.

## Features

- 🔐 **Bring Your Own Key (BYOK)**: Uses your API key directly from the browser - nothing is stored on any server
- 🎯 **Attack Demonstrations**: Pre-built attack payloads showcasing different hijacking techniques
- 🛡️ **Real-time Detection**: Pattern-based threat detection with risk scoring
- 📊 **Activity Logging**: Track all interactions and security events
- 🎨 **Beautiful UI**: Cybersecurity-themed interface built for education
- 🤖 **CrewAI Backend Mode**: Connect to backend for real agent execution with policy enforcement

## Modes

### Direct Mode (Default)
- API calls go directly from your browser to the AI provider
- Simulated tool calls and threat detection
- Great for quick demos

### Backend Mode
- Connects to FastAPI backend running CrewAI agents
- Real agent thinking, tool calls, and policy enforcement
- Compare vulnerable vs secure agent behavior
- See OWASP ASI02 mitigations in action

## Supported Providers

- OpenAI (GPT-4, GPT-4o)
- Google Gemini (Gemini 2.0, 1.5)
- Anthropic Claude (Claude 3)

## Local Development

Simply open `index.html` in your browser, or use a local server:

```bash
# Python
python -m http.server 8000

# Node.js
npx serve .

# Then open http://localhost:8000
```

## Deployment

This app is deployed automatically to GitHub Pages when changes are pushed to the `main` branch.

## Security Notes

- Your API key is stored only in browser session storage
- API calls go directly from your browser to the AI provider
- No data is transmitted to any intermediate server
- All processing happens client-side

## Architecture

```
webapp/
├── index.html      # Main HTML structure
├── styles.css      # Cyberpunk-themed styles
├── app.js          # Application logic & API integration
├── 404.html        # Custom 404 page
└── README.md       # This file
```

