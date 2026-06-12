PhishGuard

PS! I got locked out of my hackathon account, so it may still say creative apps as its category. Whivh is also why I couldnt upload the video.

I got tired of running the same manual phishing-response checklist every time an account got compromised — jumping between Entra, Exchange, and Defender for every single incident. So I built this to do it for me. You give it a user's email, it runs the whole forensic investigation, and it cleans up the account in one go.

Hackathon: Agents League (AI Skills Fest) — Reasoning Agents track.

DEMO VIDEO 5 MIN: https://youtu.be/AahdSfgEO-c


WHAT IT DOES
You give it a user's email and it runs a deep dive across the Microsoft 365 tenant:

Investigation — Pulls live data through the Microsoft Graph API: sign-in history with locations and IPs, MFA methods, inbox rules, email forwarding, OAuth app grants (resolved to real app names and risk-scored), registered devices, and file-sharing activity.

AI reasoning — The agent reasons over everything it found and produces a plain-language risk assessment tailored to the user's privilege level. You can also ask it questions about the incident in plain English, and the answers stay grounded in the live data it pulled — not hallucinated.

Remediation — If the account is compromised, it runs an 8-step cleanup through Graph: blocks the account, resets the password to a strong one-time password, wipes all MFA methods, forces re-registration, removes suspicious inbox rules, clears forwarding, revokes all sessions, then re-enables and verifies the account. For privileged accounts it also checks for backdoors — new admin users, Conditional Access changes, and PIM role assignments.

HOW THE AI WORKS
The agent's reasoning layer runs on GPT-4o-mini. For this demo it uses GitHub Models as the backend. I also built in Azure AI Foundry (Foundry IQ) support — if you set AZURE_AI_ENDPOINT and AZURE_AI_KEY, it automatically switches to Foundry. I ran the demo on GitHub Models because I couldn't provision an Azure license in time, but the Foundry path is in the code and ready to use.

If no AI tokens are configured at all, it falls back to a heuristic rule-based analysis, so the app still runs for testing.

SETUP
Use Python 3.12. This matters: on Python 3.14, pydantic-core has no prebuilt wheel yet, so pip tries to compile it from source and fails unless you have the Rust toolchain and C++ build tools installed. Python 3.12 has ready-made wheels and installs cleanly with just pip. If you already installed a newer Python and hit build errors, that's the cause — install 3.12 alongside it.

Clone the repo and open the folder.
Install dependencies:
   pip install -r requirements.txt

If pip isn't recognised as a command, use:

   python -m pip install -r requirements.txt

(On macOS/Linux it may be python3 -m pip.) This pulls in everything the app needs — FastAPI, Uvicorn, aiohttp, Pydantic, and python-dotenv — automatically.


Copy .env.template to .env and fill in your credentials:
   MICROSOFT_TENANT_ID=your-tenant-id
   MICROSOFT_CLIENT_ID=your-app-registration-client-id
   MICROSOFT_CLIENT_SECRET=your-client-secret
   GITHUB_TOKEN=your-github-token-with-models-read
   PORT=8000

Optional — to use Foundry IQ instead of GitHub Models:

   AZURE_AI_ENDPOINT=https://your-resource.openai.azure.com/openai/deployments/gpt-4o-mini
   AZURE_AI_KEY=your-azure-ai-foundry-key

Run it:
   python main.py

Open http://localhost:8000 in your browser.


Azure App Registration permissions

The app authenticates as an Azure AD app registration using client credentials. Grant these Application permissions in Entra -> App registrations -> API permissions, then click Grant admin consent:


User.ReadWrite.All — read user, block/enable, reset password
UserAuthenticationMethod.ReadWrite.All — read and delete MFA methods
Mail.ReadWrite — read and remove inbox rules / forwarding
AuditLog.Read.All — sign-in and audit logs
Directory.Read.All — roles and group memberships


Optional — for the advanced privileged-account checks. The app runs fine without these; it just logs a warning and skips them:


Policy.Read.All — Conditional Access policy checks
RoleManagement.Read.Directory — PIM assignments
SecurityAlert.Read.All — Defender alert checks


KNOWN LIMITATIONS / TODO
Impossible-travel detection currently flags any country change, so legitimate travel can show as a false positive. Needs proper time-vs-distance math.
Defender "Restricted entities" removal has no public Graph API, so it stays a documented manual step.
After remediation the account is re-enabled, but the user has to sign in with the new generated password — entering the old one will fail (this is how Entra's forced-password-change flow works).
Sign-in logs require an Entra ID P1/P2 license on the tenant; on free tenants the sign-in section will be empty.


TECH
Python 3.12 · FastAPI · Microsoft Graph API · GPT-4o-mini (GitHub Models, with Azure AI Foundry support built in) · vanilla JS single-page UI. Works on any Microsoft 365 tenant — no E5 license required for the core features.

Feedback and bug reports welcome.
