"""AI threat analysis — GitHub Models (GPT-4o-mini) with phishing protocol context.
All output is in English.

Note: Falls back to heuristic analysis if no API tokens configured.
"""
import aiohttp, logging
from typing import Dict

logger = logging.getLogger("llm")

PHISHING_PROTOCOL = """
INTERNAL INCIDENT RESPONSE PROTOCOL (use this for all analysis and guidance):

TRIAGE — FIRST: Determine privilege level
- Check Entra directory roles (Global Admin, Exchange Admin, User Admin, SharePoint Admin, Security Admin = PRIVILEGED)
- Check PIM/JIT assignments (active + eligible)
- Check delegated mailbox access (Send As, Full Access = potentially privileged)
- Check Azure subscription IAM (Owner, Contributor = privileged)

PRIVILEGED ROLES (all require full investigation):
  Global Administrator, Exchange Administrator, User Administrator, SharePoint Administrator,
  Security Administrator, Compliance Administrator, Privileged Role Administrator,
  Privileged Authentication Administrator, Authentication Administrator,
  Cloud App Security Administrator, Intune Administrator, Teams Administrator,
  Application Administrator, Conditional Access Administrator, Power Platform Administrator,
  License Administrator, Billing Administrator, Helpdesk Administrator,
  Identity Governance Administrator, Security Operator

IF STANDARD USER: Simplified response (block, reset pw, delete MFA, clear rules, re-enable)
IF PRIVILEGED USER: Full investigation required (all steps below)

CONFIRMATION STEPS:
1. Sign-in logs: Unusual locations, IPs, multiple simultaneous logins, failed MFA
2. Audit logs: CA policy changes, role assignments, new users, MFA method changes
3. CA policy review: Recent modifications, excluded users, disabled policies
4. Defender alerts: Incidents/alerts tied to user

AUTOMATED REMEDIATION (8 steps — all done by the agent):
1. Block account
2. Reset password (strong, forceChangeNextSignIn)
3. Delete ALL MFA methods + verify
4. Force MFA re-registration
5. Remove suspicious inbox rules
6. Clear email forwarding
7. Revoke sessions + force Office sign-out
8. Re-enable account

PRIVILEGED USER EXTRAS (automated checks):
- Check for new backdoor user accounts
- Check CA policy changes in last 7 days
- Check PIM/JIT assignments
- Check delegated mailbox access
- Check restricted sender status in Defender

MANUAL STEPS (always required):
- Verify inbox rules in OWA
- Remove from Defender Restricted Entities if blocked
- Check phishing spread (Defender Email Explorer)
- Notify affected users
- Send password to user
- Document in HaloPSA

PRIVILEGED USER MANUAL EXTRAS:
- Full CA policy review (Entra → Conditional Access)
- Download audit logs CSV
- Review PIM assignments
- Check Exchange mailbox delegation
- Check Azure subscription access
- Review Defender incidents
- Review Teams/SharePoint/OneDrive activity

PHISHING SPREAD DETECTION:
- Search Defender Email Explorer for phishing sender/URL
- Check who else received/clicked the phishing email
- Notify affected users
"""

PRIVILEGED_ROLES = [
    "global administrator", "exchange administrator", "user administrator",
    "sharepoint administrator", "security administrator", "compliance administrator",
    "privileged role administrator", "privileged authentication administrator",
    "authentication administrator", "cloud app security administrator",
    "intune administrator", "teams administrator", "application administrator",
    "conditional access administrator", "power platform administrator",
    "billing administrator", "identity governance administrator", "security operator",
    "license administrator", "helpdesk administrator",
]


def is_privileged_role(role_name: str) -> bool:
    rl = role_name.lower()
    return any(pr in rl for pr in PRIVILEGED_ROLES) or "admin" in rl


class AIAnalyzer:
    def __init__(self, github_token: str):
        import os
        # Azure AI Foundry (competition-compliant, preferred)
        # Set AZURE_AI_ENDPOINT and AZURE_AI_KEY in .env to use Foundry
        azure_endpoint = os.getenv("AZURE_AI_ENDPOINT", "")
        azure_key      = os.getenv("AZURE_AI_KEY", "")
        azure_model    = os.getenv("AZURE_AI_MODEL", "gpt-4o-mini")

        if azure_endpoint and azure_key:
            # Azure AI Foundry / Azure OpenAI
            api_version = os.getenv("AZURE_AI_API_VERSION", "2024-08-01-preview")
            base = azure_endpoint.rstrip("/")
            # Append /chat/completions if not already a full path
            if "/chat/completions" not in base:
                base = base + "/chat/completions"
            # Azure requires the api-version query parameter
            sep = "&" if "?" in base else "?"
            self.endpoint = f"{base}{sep}api-version={api_version}"
            self.token    = azure_key
            self.model    = azure_model
            self.auth_header = "api-key"
            self.using_foundry = True
        else:
            # GitHub Models fallback
            self.endpoint = "https://models.github.ai/inference/chat/completions"
            self.token    = github_token
            self.model    = "openai/gpt-4o-mini"
            self.auth_header = "Authorization"
            self.using_foundry = False

        self.github_token = github_token  # keep for compatibility
        self.session = None

    def _fallback_analysis(self, user_data: dict) -> Dict:
        """Heuristic fallback when no AI token available."""
        roles = user_data.get("roles", [])
        priv_roles = [r for r in roles if is_privileged_role(r)]
        is_priv = len(priv_roles) > 0
        mfa = user_data.get("mfa_methods", [])
        fwd = user_data.get("forwarding")
        rules = user_data.get("mailbox_rules", [])

        lines = ["**📋 Incident Summary**\n"]

        # Privilege
        if is_priv:
            lines.append(f"### 🔐 Access Level\n⚠️ PRIVILEGED — {len(priv_roles)} admin role(s): {', '.join(priv_roles[:3])}\nFull investigation protocol required.\n")
        else:
            lines.append(f"### 🔐 Access Level\nStandard user — {len(roles)} role(s). Simplified response applies.\n")

        # MFA
        if not mfa:
            lines.append("### 🔒 MFA Status\n🚨 CRITICAL — No MFA methods registered. Account had no second factor protection.\n")
        else:
            types = ', '.join([m.get('type', '?') for m in mfa])
            lines.append(f"### 🔒 MFA Status\n{len(mfa)} method(s): {types}\n")

        # Email
        if fwd:
            lines.append(f"### 📧 Email Status\n🚨 Forwarding ACTIVE to: {fwd} — attacker persistence indicator.\n")
        elif rules:
            lines.append(f"### 📧 Email Status\n⚠️ {len(rules)} inbox rule(s) found — review for suspicious forwarding or hiding rules.\n")
        else:
            lines.append("### 📧 Email Status\nNo forwarding or suspicious inbox rules detected.\n")

        # Risk
        score = 90 if not mfa else 70 if (fwd or rules) else 50
        risk = "HIGH" if score >= 80 else "MEDIUM" if score >= 60 else "LOW"
        lines.append(f"### ⚠️ Risk Assessment\n**{risk}** — Score {score}/100\n")

        # Recommended steps
        if is_priv:
            lines.append("### 📋 Recommended Steps\n⚠️ **Privileged account — run full protocol:**\nReview admin forensics and inbox rules first, then run automated remediation. Manual steps include CA policy review, audit log download, PIM review, and Defender investigation.\n")
        else:
            lines.append("### 📋 Recommended Steps\nRun automated remediation. Verify inbox rules in OWA, check Defender restricted entities, and investigate phishing spread.\n")

        threat_score = 90 if not mfa else 75 if (fwd or rules or is_priv) else 50
        return {
            "threat_score": threat_score,
            "indicators": ["No MFA" if not mfa else "MFA present",
                           "Forwarding active" if fwd else "No forwarding"],
            "analysis": "\n".join(lines)
        }

    async def analyze_threat(self, incident_desc: str, user_data: dict) -> Dict:
        """Full AI threat analysis with phishing protocol."""
        if not self.token and not self.github_token:
            return self._fallback_analysis(user_data)

        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            roles = user_data.get("roles", [])
            mfa = user_data.get("mfa_methods", [])
            devices = user_data.get("device_details", [])
            signin_logs = user_data.get("signin_logs", [])
            is_priv = any(is_privileged_role(r) for r in roles)

            signin_summary = ""
            if signin_logs:
                locations = set()
                for s in signin_logs[:10]:
                    loc = s.get("location", {})
                    city = loc.get("city", "")
                    country = loc.get("countryOrRegion", "")
                    if city or country:
                        locations.add(f"{city}, {country}".strip(", "))
                signin_summary = f"{len(signin_logs)} sign-in logs, locations: {', '.join(list(locations)[:5]) or 'unknown'}"

            context = f"""{PHISHING_PROTOCOL}

---
ROLE: You are an IT security analyst responding to a Microsoft 365 phishing/account compromise incident.
LANGUAGE: English only. ALL output must be in English.
FORMAT: Use ### headings, **bold** for key terms. Clear sections, not walls of text.

ACTUAL TENANT DATA FOR THIS USER:
- Email: {user_data.get('email')}
- Roles: {', '.join(roles) if roles else 'No roles (standard user)'}
- Privileged: {is_priv}
- MFA methods: {len(mfa)} — {', '.join([m.get('type','?') for m in mfa]) if mfa else 'NONE REGISTERED'}
- Mailbox rules: {len(user_data.get('mailbox_rules', []))}
- Email forwarding: {user_data.get('forwarding') or 'None'}
- Devices: {len(devices)} registered
- Sign-ins: {signin_summary or 'No data (check AuditLog.Read.All permission)'}
- Victims/affected: {len(user_data.get('victims', []))}

WRITE A CLEAR INCIDENT SUMMARY with exactly these sections:

### 🔐 Access Level
(Role names, is this privileged? What does that mean for risk?)

### 🔒 MFA Status
(What methods are registered? Any concerns?)

### 📧 Email Status
(Forwarding, inbox rules — suspicious?)

### 💻 Devices & Sign-ins
(Devices registered, any suspicious locations or new devices?)

### ⚠️ Risk Assessment
(Overall: LOW/MEDIUM/HIGH/CRITICAL + brief reason — 1-2 sentences)

### 📋 Recommended Next Steps
(Based on protocol: standard or full investigation? What should the analyst do NOW?)

Keep each section to 2-3 lines max. Professional, actionable. Based ONLY on the data above."""

            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": context}],
                "max_tokens": 1000
            }
            headers = self._build_headers()

            async with self.session.post(self.endpoint, headers=headers, json=payload, timeout=30) as r:
                if r.status == 200:
                    data = await r.json()
                    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    score = 70
                    tl = text.lower()
                    if "critical" in tl: score = 90
                    elif "high" in tl: score = 75
                    elif "medium" in tl: score = 55
                    elif "low" in tl: score = 35
                    logger.info(f"✓ AI analysis complete (score: {score})")
                    return {"threat_score": score, "indicators": ["See detailed analysis"], "analysis": text}
                else:
                    logger.warning(f"AI API error {r.status}")
                    return self._fallback_analysis(user_data)

        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
            return self._fallback_analysis(user_data)

    async def analyze_question(self, full_context: str, user_data: dict) -> str:
        """Answer any question about the incident. Always responds in English."""
        if not self.token and not self.github_token:
            return self._answer_fallback(full_context, user_data)

        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            roles = user_data.get("roles", [])
            mfa = user_data.get("mfa_methods", [])
            devices = user_data.get("device_details", [])
            signin_logs = user_data.get("signin_logs", [])
            is_priv = any(is_privileged_role(r) for r in roles)

            signin_detail = ""
            if signin_logs:
                signin_detail = f"Sign-in logs ({len(signin_logs)} entries):\n"
                for s in signin_logs[:15]:
                    loc = s.get("location", {})
                    code = s.get("status", {}).get("errorCode", 0)
                    ok = code == 0 or code is None
                    mfa_req = s.get("authenticationRequirement", "") == "multiFactorAuthentication"
                    signin_detail += f"  {s.get('createdDateTime','?')[:16]}: {loc.get('city','?')}, {loc.get('countryOrRegion','?')} | IP: {s.get('ipAddress','?')} | {'OK' if ok else 'FAIL'} | MFA: {'Yes' if mfa_req else 'No'}\n"

            device_detail = ""
            if devices:
                device_detail = "Devices:\n"
                for d in devices:
                    device_detail += f"  - {d.get('name','?')} | {d.get('type','?')} | {d.get('os','?')} | Registered: {d.get('created','?')} | Last seen: {d.get('lastSignIn','?')}\n"

            system_prompt = f"""You are an expert Microsoft 365 security incident response analyst.

{PHISHING_PROTOCOL}

CURRENT INCIDENT DATA:
Email: {user_data.get('email')}
Roles: {', '.join(roles) if roles else 'None (standard user)'}
Privileged: {is_priv}
MFA methods: {len(mfa)} — {', '.join([m.get('type','?') for m in mfa]) if mfa else 'NONE'}
Mailbox rules: {len(user_data.get('mailbox_rules', []))}
Email forwarding: {user_data.get('forwarding') or 'None'}
Victims/affected users: {len(user_data.get('victims', []))}
{signin_detail}
{device_detail}

INSTRUCTIONS:
- ALWAYS respond in English. Never switch to another language.
- Be specific and practical — reference actual data from above
- If data is missing/unavailable, say so clearly and suggest where to check
- Keep answers concise (3-8 lines typically)
- If relevant, mention what protocol step applies
- For yes/no questions: give a clear Yes/No first, then explain
- For privileged accounts: proactively mention the extra investigation steps required
"""

            question = full_context.split("USER QUESTION:")[-1].strip() if "USER QUESTION:" in full_context else full_context

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question}
                ],
                "max_tokens": 700
            }
            headers = self._build_headers()

            async with self.session.post(self.endpoint, headers=headers, json=payload, timeout=30) as r:
                if r.status == 200:
                    data = await r.json()
                    answer = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    return answer
                else:
                    return self._answer_fallback(full_context, user_data)

        except Exception as e:
            logger.warning(f"AI question error: {e}")
            return f"AI error: {str(e)}"

    def _build_headers(self) -> dict:
        """Build auth headers for Azure AI Foundry or GitHub Models."""
        if self.auth_header == "api-key":
            return {"api-key": self.token, "Content-Type": "application/json"}
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _get_protocol_guidance(self, is_admin: bool) -> str:
        """Return the full response protocol for this user type."""
        if is_admin:
            return """**📋 Full Response Protocol — Privileged User**

**Automated (run Remediation button):**
1. Block account
2. Reset password (strong, forceChangeNextSignIn)
3. Delete ALL MFA methods + verify
4. Force MFA re-registration
5. Remove suspicious inbox rules
6. Clear email forwarding
7. Revoke all sessions + Office sign-out
8. Re-enable account
9. Auto-checks: backdoor users, CA changes, PIM, delegated access, restricted sender

**Manual — Required:**
A. Confirm incident: Review sign-in logs for unusual IPs/locations, download CSV
B. Audit logs: Entra → Monitoring → Audit logs — filter by user + date, download CSV
C. CA policies: Entra → Conditional Access → Policies — sort by Last Modified
D. PIM review: Entra → Identity Governance → PIM → Assignments — check active + eligible
E. Exchange delegation: Exchange Admin → Mailboxes → user → Mailbox delegation
F. Azure subscriptions: Azure Portal → Subscriptions → IAM → Role assignments
G. Defender: Incidents & alerts — filter by user. Email Explorer for sent phishing.
H. Teams/SharePoint/OneDrive activity review
I. OWA rules: Log in as user → Settings → Mail → Rules — verify no suspicious rules
J. Defender Restricted Entities: Remove restriction if blocked from sending
K. Check phishing spread: Defender Email Explorer — who else received/clicked?
L. Notify affected users
M. Send new password to user (SMS or secure channel)
N. Document in HaloPSA"""
        else:
            return """**📋 Response Protocol — Standard User**

**Automated (run Remediation button):**
1. Block account
2. Reset password (strong, forceChangeNextSignIn)
3. Delete ALL MFA methods + verify
4. Force MFA re-registration
5. Remove suspicious inbox rules
6. Clear email forwarding
7. Revoke all sessions + Office sign-out
8. Re-enable account

**Manual — Required:**
A. Verify OWA inbox rules: Outlook Web → Settings → Mail → Rules
B. Defender Restricted Entities: Check if blocked from sending — remove restriction
C. Check phishing spread: Defender Email Explorer — search for phishing sender/URL
D. Notify affected users if spread detected
E. Send new password to user via SMS or secure channel
F. Document in HaloPSA"""

    def _answer_fallback(self, context: str, user_data: dict) -> str:
        """Data-driven fallback when AI unavailable."""
        q = context.lower()
        roles = user_data.get("roles", [])
        is_priv = any(is_privileged_role(r) for r in roles)

        if any(w in q for w in ["protocol", "checklist", "what to do", "steps", "procedure", "guide", "what should"]):
            return self._get_protocol_guidance(is_priv)

        if any(w in q for w in ["mfa", "2fa", "authenticator", "multi-factor"]):
            mfa = user_data.get("mfa_methods", [])
            if not mfa:
                return "**No MFA methods registered** — this is critical. Anyone with the password can sign in. MFA deletion in remediation will be instant (nothing to delete), but force re-registration must be enabled manually."
            return f"**{len(mfa)} MFA method(s):** {', '.join([m.get('type','?') + ((' — ' + m.get('details','')) if m.get('details') else '') for m in mfa])}"

        if any(w in q for w in ["role", "admin", "privilege", "access", "permission"]):
            if not roles:
                return "No directory roles assigned — standard user. Simplified response protocol applies."
            priv_roles = [r for r in roles if is_privileged_role(r)]
            if priv_roles:
                return f"⚠️ **Privileged account** — {len(priv_roles)} privileged role(s): {', '.join(priv_roles)}\nFull investigation protocol required."
            return f"Roles: {', '.join(roles)}"

        if any(w in q for w in ["device", "computer", "laptop", "phone", "mobile"]):
            devs = user_data.get("device_details", [])
            if not devs:
                return "No registered devices found for this user."
            lines = [f"**{len(devs)} device(s) registered:**"]
            for d in devs:
                new_flag = ""
                if d.get("created") and d["created"] != "Unknown":
                    from datetime import datetime
                    try:
                        days = (datetime.utcnow() - datetime.fromisoformat(d["created"].replace("Z",""))).days
                        if days < 14: new_flag = " ⚠️ NEW"
                    except: pass
                lines.append(f"• {d.get('name','?')} ({d.get('type','?')}, {d.get('os','?')}) — Registered: {d.get('created','?')} | Last seen: {d.get('lastSignIn','?')}{new_flag}")
            return "\n".join(lines)

        if any(w in q for w in ["location", "sign-in", "login", "signin", "where", "ip"]):
            signin = user_data.get("signin_logs", [])
            if not signin:
                return "No sign-in logs available. Ensure **AuditLog.Read.All** permission is granted in Azure App Registration."
            lines = [f"**Last {min(8,len(signin))} sign-ins:**"]
            for s in signin[:8]:
                loc = s.get("location", {})
                code = s.get("status", {}).get("errorCode", 0)
                ok = code == 0 or code is None
                lines.append(f"• {s.get('createdDateTime','?')[:16]} — {loc.get('city','?')}, {loc.get('countryOrRegion','?')} | IP: {s.get('ipAddress','?')} | {'✓ OK' if ok else '✗ Failed'}")
            return "\n".join(lines)

        if any(w in q for w in ["forward", "rule", "inbox"]):
            fwd = user_data.get("forwarding")
            rules = user_data.get("suspicious_rules", [])
            parts = []
            if fwd:
                parts.append(f"⚠️ **Email forwarding ACTIVE** to: {fwd} — remove immediately via Exchange Admin or the agent's forwarding API call.")
            if rules:
                parts.append(f"**{len(rules)} suspicious inbox rule(s)** found — review each rule's actions in the Email Rules card and delete suspicious ones in OWA.")
            if not fwd and not rules:
                return "No email forwarding or suspicious inbox rules found."
            return "\n".join(parts)

        return f"I have the incident data loaded. You can ask about: roles & privileges, MFA methods, sign-in locations, devices, inbox rules, protocol steps, or what to do next."

    async def cleanup(self):
        if self.session:
            await self.session.close()
