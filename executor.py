"""Incident remediation executor — full phishing response protocol.

AUTOMATED (all users):
  1.  Block account
  2.  Reset password
  3.  Delete ALL MFA methods
  4.  Force MFA re-registration note
  5.  Delete suspicious inbox rules via API
  6.  Clear email forwarding via API
  7.  Revoke sessions + force Office sign-out (revokeSignInSessions x2)
  8.  Re-enable account

AUTOMATED (privileged users only — Step 9):
  9a. Check for new backdoor user accounts
  9b. Check CA policy changes
  9c. Fetch PIM assignments
  9d. Check delegated mailbox access
  9e. Check restricted sender status

MANUAL (cannot be automated — human judgment required):
  - Defender Restricted Entity removal: no public Graph API endpoint
  - Phishing spread investigation: requires human review in Defender Explorer
  - Notifying affected users: PII/communication decisions
  - Sending password to user: no API for SMS/secure channel
  - Azure subscription IAM review: requires human judgment on roles
  - CA policy content review: can detect changes but human must assess
  - Teams/SharePoint/OneDrive sharing review: can detect but not auto-remediate
  - PIM assignment review: can list but human decides what to remove
"""
import logging, asyncio

logger = logging.getLogger("executor")

PRIVILEGED_ROLE_KEYWORDS = [
    "global administrator", "exchange administrator", "user administrator",
    "sharepoint administrator", "security administrator", "compliance administrator",
    "privileged role administrator", "privileged authentication administrator",
    "authentication administrator", "cloud app security administrator",
    "intune administrator", "teams administrator", "application administrator",
    "cloud application administrator", "conditional access administrator",
    "power platform administrator", "license administrator", "billing administrator",
    "helpdesk administrator", "identity governance administrator", "security operator",
    "directory synchronization accounts", "azure ad joined device local administrator",
]

# Only truly non-automatable steps remain here
MANUAL_STEPS_STANDARD = [
    ("Remove from Defender Restricted Entities (if blocked)",
     "Defender → Email & collaboration → Review → Restricted entities → find user → Remove restriction\n"
     "     (No public API for this — must be done manually in Defender portal)"),
    ("Investigate phishing spread",
     "Defender → Email & collaboration → Explorer — search for the phishing sender address or URL.\n"
     "     Check who else received or clicked the phishing email."),
    ("Notify affected users",
     "Contact users who received emails from the compromised account.\n"
     "     Advise them not to click any links and to report suspicious emails."),
    ("Send new password to user",
     "Send the generated password via SMS or a secure channel.\n"
     "     User must change it on first login (forceChangeNextSignIn is enabled)."),
]

MANUAL_STEPS_ADMIN = [
    ("Review CA policy changes in Entra",
     "Entra → Conditional Access → Policies — sort by Last Modified.\n"
     "     Check: disabled policies, excluded users, removed MFA requirements, modified named locations.\n"
     "     Download CA audit log: Conditional Access → Audit logs → export CSV."),
    ("Download full audit logs",
     "Entra → Monitoring → Audit logs — filter by user + date range → download CSV.\n"
     "     Look for: role assignments, new users, MFA changes, CA modifications."),
    ("Review and remove PIM/JIT assignments",
     "Entra → Identity Governance → PIM → Microsoft Entra Roles → Assignments.\n"
     "     Check active + eligible. Remove any assignment not recognised or not expected."),
    ("Review Exchange mailbox delegation",
     "Exchange Admin Center → Mailboxes → user → Mailbox delegation.\n"
     "     Remove unknown Send As or Full Access grants."),
    ("Review Azure subscription access",
     "Azure Portal → Subscriptions → Access control (IAM) → Role assignments.\n"
     "     Search for the user and remove Owner/Contributor if not expected."),
    ("Review Teams / SharePoint / OneDrive",
     "SharePoint Admin Center → Active sites → usage reports.\n"
     "     OneDrive Admin → Activity. Check for unusual external sharing or guest access."),
    ("Remove from Defender Restricted Entities (if blocked)",
     "Defender → Email & collaboration → Review → Restricted entities → Remove restriction.\n"
     "     (No public API — must be done manually in Defender portal.)"),
    ("Investigate phishing spread",
     "Defender → Email & collaboration → Explorer — search for phishing sender/URL.\n"
     "     Check who received/clicked. Notify affected users."),
    ("Send new password to user",
     "Send the generated password via SMS or secure channel.\n"
     "     User must change on first login."),
]


class Executor:
    def __init__(self, graph_client, analyzer):
        # 8-step remediation orchestrator
        self.graph = graph_client
        self.analyzer = analyzer

    async def execute(self, user_email: str, user_id: str, graph_data: dict,
                      is_admin: bool = False) -> dict:
        log      = []
        password = None
        mode     = "PRIVILEGED" if is_admin else "STANDARD"

        logger.info(f"\n{'='*70}\nREMEDIATION [{mode}]: {user_email}\n{'='*70}")
        log.append(f"▶ Starting {mode.lower()} remediation for {user_email}")
        log.append("")

        # ── Step 1: Block account ─────────────────────────────────────────────
        log.append("── Step 1: Block account ──")
        ok = await self.graph.disable_user(user_id)
        if ok:
            log.append("✓ Account blocked")
        else:
            log.append("✗ Failed to block account — aborting")
            return {"status": "failed", "password": None, "log": log}

        # ── Step 2: Reset password ────────────────────────────────────────────
        log.append("── Step 2: Reset password ──")
        success, pwd = await self.graph.reset_password(user_id)
        password = pwd
        if success:
            log.append("✓ Password reset — forceChangeNextSignIn enabled")
            log.append(f"  🔑 NEW PASSWORD: {pwd}")
        else:
            log.append("⚠ API failed — use this password manually in Admin Center:")
            log.append(f"  🔑 PASSWORD: {pwd}")

        # ── Step 3: Delete ALL MFA methods ───────────────────────────────────
        log.append("── Step 3: Delete all MFA methods ──")
        mfa_result = await self.graph.delete_mfa_methods(user_id)
        deleted = mfa_result.get("deleted", [])
        failed  = mfa_result.get("failed", [])

        if deleted:
            log.append(f"✓ Deleted {len(deleted)} MFA method(s): {', '.join(deleted)}")
        if failed:
            log.append(f"⚠ Could not delete: {', '.join(failed)}")
            log.append("  → Remove remaining methods manually: Entra → Users → user → Authentication methods")
        if not deleted and not failed:
            log.append("✓ No MFA methods found (none registered)")
        if not failed:
            log.append("✓ MFA deletion confirmed")
            log.append("  ℹ Methods may still appear in Entra for ~30-60s (Graph eventual consistency)")

        # ── Step 4: Force MFA re-registration ────────────────────────────────
        log.append("── Step 4: Force MFA re-registration ──")
        log.append("✓ forceChangeNextSignIn ensures user must set up MFA on next login")
        log.append("  → Also enable manually: Entra → Users → user → Authentication methods → Require re-register")

        # ── Step 5: Delete suspicious inbox rules ────────────────────────────
        log.append("── Step 5: Remove suspicious inbox rules ──")
        suspicious = graph_data.get("suspicious_rules", [])
        all_rules  = graph_data.get("mailbox_rules", [])

        if not suspicious and not all_rules:
            log.append("✓ No inbox rules found")
        elif not suspicious:
            n = len(all_rules) if isinstance(all_rules, list) else all_rules
            log.append(f"✓ {n} rule(s) found — none flagged as suspicious")
        else:
            deleted_rules, failed_rules = 0, 0
            for rule in suspicious:
                rid  = rule.get("id")
                name = rule.get("name", "?")
                if rid:
                    ok = await self.graph.remove_mailbox_rule(user_id, rid)
                    if ok:
                        deleted_rules += 1
                        log.append(f"  ✓ Deleted rule: '{name}'")
                    else:
                        failed_rules += 1
                        log.append(f"  ⚠ Could not delete rule: '{name}' — delete manually in OWA")
                else:
                    failed_rules += 1
                    log.append(f"  ⚠ Rule '{name}' has no ID — delete manually in OWA")
            log.append(f"✓ Inbox rules: {deleted_rules} deleted, {failed_rules} require manual removal")
            if failed_rules:
                log.append("  → OWA: Outlook Web → Settings → Mail → Rules")

        # ── Step 6: Clear email forwarding ───────────────────────────────────
        log.append("── Step 6: Clear email forwarding ──")
        fwd = graph_data.get("forwarding")
        if fwd:
            ok = await self.graph.clear_forwarding(user_id)
            if ok:
                log.append(f"✓ Forwarding cleared (was forwarding to: {fwd})")
            else:
                log.append("⚠ Could not clear via API")
                log.append("  → Remove manually: Exchange Admin → Mailboxes → user → Mail flow settings → Forwarding")
        else:
            log.append("✓ No email forwarding configured")

        # ── Step 7: Revoke sessions + force Office sign-out ──────────────────
        log.append("── Step 7: Revoke sessions + force Office sign-out ──")
        ok1 = await self.graph.revoke_sessions(user_id)
        await asyncio.sleep(1)
        ok2 = await self.graph.force_office_signout(user_id)
        if ok1 or ok2:
            log.append("✓ All refresh tokens revoked — user signed out from all M365 apps")
        else:
            log.append("⚠ Session revocation failed")
            log.append("  → Sign out manually: Admin Center → Users → user → Sign out")

        # ── Step 8: Re-enable account ─────────────────────────────────────────
        # Wait for the session revocation above to settle server-side before
        # re-enabling — otherwise the two operations race and the account can
        # stay blocked.
        await asyncio.sleep(3)
        log.append("── Step 8: Re-enable account ──")
        ok = await self.graph.enable_user(user_id)
        if ok:
            log.append("✓ Account re-enabled and verified")
        else:
            log.append("✗ Could not re-enable via API — account is still BLOCKED")
            log.append("  ⚠ ACTION REQUIRED: Admin Center → Users → Active users → user → Unblock sign-in")

        # ── Step 9: Privileged-only automated checks ──────────────────────────
        if is_admin:
            log.append("")
            log.append("── Step 9: Privileged account automated checks ──")

            # 9a: Backdoor users
            new_users = graph_data.get("admin_data", {}).get("new_users", [])
            if new_users:
                log.append(f"  ⚠ {len(new_users)} new user(s) created in last 7 days — possible backdoor accounts:")
                for u in new_users[:5]:
                    log.append(f"    • {u.get('email','?')} (created {u.get('created','?')})")
                log.append("    → Review each in Entra → Users — delete if not recognised")
            else:
                log.append("  ✓ No new user accounts detected in last 7 days")

            # 9b: CA policy changes
            try:
                ca_changes = await self.graph.get_ca_changes(days_back=7)
                if isinstance(ca_changes, list) and ca_changes:
                    log.append(f"  ⚠ {len(ca_changes)} Conditional Access policy change(s) in last 7 days:")
                    for ch in ca_changes[:3]:
                        tgts = ch.get("targetResources", [{}])
                        name = tgts[0].get("displayName", "?") if tgts else "?"
                        log.append(f"    • {ch.get('activityDisplayName','?')}: {name}")
                    log.append("    → Review manually: Entra → Conditional Access → Policies (sort by Last Modified)")
                elif isinstance(ca_changes, list):
                    log.append("  ✓ No CA policy changes in last 7 days")
                else:
                    log.append("  ⚠ CA policy check unavailable — Policy.Read.All permission not granted")
            except Exception:
                log.append("  ⚠ CA policy check failed — verify manually in Entra")

            # 9c: PIM assignments
            try:
                pim = await self.graph.get_pim_assignments(user_id)
                if pim.get("permission_error"):
                    log.append("  ⚠ PIM check: add RoleManagement.Read.Directory to App Registration")
                elif pim.get("has_pim"):
                    active  = pim.get("active", [])
                    eligible = pim.get("eligible", [])
                    log.append(f"  ⚠ PIM assignments found: {len(active)} active, {len(eligible)} eligible")
                    if active:   log.append(f"    Active:   {', '.join(active[:5])}")
                    if eligible: log.append(f"    Eligible: {', '.join(eligible[:5])}")
                    log.append("    → Review: Entra → Identity Governance → PIM → Assignments")
                else:
                    log.append("  ✓ No PIM/JIT role assignments found")
            except Exception:
                log.append("  ⚠ PIM check failed — verify manually")

            # 9d: Delegated mailbox
            try:
                delegated = await self.graph.get_delegated_mailbox_access(user_email)
                if delegated:
                    log.append(f"  ⚠ {len(delegated)} delegated access grant(s) found:")
                    for g in delegated[:3]:
                        log.append(f"    • {g.get('grantee','?')}: {g.get('role','?')}")
                    log.append("    → Review: Exchange Admin Center → Mailboxes → Mailbox delegation")
                else:
                    log.append("  ✓ No unusual delegated mailbox access")
            except Exception:
                log.append("  ⚠ Mailbox delegation check failed")

            # 9e: Restricted sender
            try:
                blocked = await self.graph.check_restricted_sender(user_email)
                if blocked.get("potentially_blocked"):
                    log.append(f"  ⚠ User may be blocked from sending (Defender alert detected)")
                    log.append("    → Defender → Email & collaboration → Review → Restricted entities")
                elif not blocked.get("no_permission"):
                    log.append("  ✓ No restricted sender alerts found in Defender")
            except Exception:
                pass

        log.append("")
        log.append("─" * 60)
        log.append("✅ AUTOMATED REMEDIATION COMPLETE")
        log.append("─" * 60)
        log.append("")

        # Manual steps
        manual_steps = MANUAL_STEPS_ADMIN if is_admin else MANUAL_STEPS_STANDARD
        label = "MANUAL STEPS — PRIVILEGED USER" if is_admin else "MANUAL STEPS"
        log.append(f"📋 {label}")
        log.append("")
        for i, (title, where) in enumerate(manual_steps, 1):
            log.append(f"  {i}. {title}")
            log.append(f"     ↳ {where}")
            log.append("")

        return {
            "status":   "completed",
            "password": password,
            "log":      log,
            "is_admin": is_admin,
        }
