import uvicorn
from config import config

missing = [k for k, v in {
    "MICROSOFT_TENANT_ID": config.TENANT_ID,
    "MICROSOFT_CLIENT_ID": config.CLIENT_ID,
    "MICROSOFT_CLIENT_SECRET": config.CLIENT_SECRET,
}.items() if not v]

if missing:
    print(f"❌ Missing required environment variables: {', '.join(missing)}")
    print("   Create a .env file or set them in Replit Secrets.")
    print("   See .env.template for reference.")
    exit(1)

if __name__ == "__main__":
    import os
    azure_endpoint = os.getenv("AZURE_AI_ENDPOINT", "")
    azure_key      = os.getenv("AZURE_AI_KEY", "")
    github_token   = os.getenv("GITHUB_TOKEN", "")

    if azure_endpoint and azure_key:
        print(f"✓ AI backend: Azure AI Foundry (Foundry IQ) — {azure_endpoint.split('/openai/')[0]}")
    elif github_token:
        print(f"✓ AI backend: GitHub Models (fallback) — set AZURE_AI_ENDPOINT + AZURE_AI_KEY to use Foundry IQ")
    else:
        print(f"⚠ AI backend: heuristic fallback — no AI token configured")

    print(f"✓ Starting Phishing Response Agent on port {config.PORT}")
    uvicorn.run("web.app:app", host="0.0.0.0", port=config.PORT, log_level="info")
