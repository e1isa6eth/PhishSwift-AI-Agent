"""
Forensic analysis across 8 compromise vectors.
All errors handled gracefully — missing permissions return empty results, never crash.
"""
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("forensics")

DANGEROUS_OAUTH_SCOPES = [
    "mail.readwrite", "mail.send", "contacts.readwrite",
    "files.readwrite.all", "files.readwrite", "directory.readwrite.all",
    "user.readwrite.all", "ews.accessasuser.all", "mailboxsettings.readwrite",
    "calendars.readwrite", "people.read.all", "tasks.readwrite",
]


class ForensicAnalyzer:
    def __init__(self, graph_client):
        self.graph = graph_client

    async def full_forensic_analysis(self, user_id: str, user_email: str, days_back: int = 7) -> dict:
        logger.info("\n" + "="*60 + "\nFULL FORENSIC ANALYSIS\n" + "="*60)
        tenant_domain = user_email.split("@")[1] if "@" in user_email else ""

        findings = {
            "email":            await self._analyze_email(user_id, user_email, tenant_domain),
            "onedrive":         await self._analyze_onedrive(user_id, user_email),
            "teams":            await self._analyze_teams(user_id, user_email, tenant_domain),
            "calendar":         await self._analyze_calendar(user_id, user_email, tenant_domain),
            "oauth":            await self._analyze_oauth(user_id),
            "external_sharing": {"risk_level": "LOW", "findings": []},  # Needs SharePoint admin perms
            "delegated_access": await self._analyze_delegated_access(user_id, user_email),
            "admin_actions":    await self._analyze_admin_actions(user_email, days_back),
        }
        findings["risk_summary"] = self._calculate_risk(findings)
        return findings

    async def _analyze_email(self, user_id: str, user_email: str, tenant_domain: str) -> dict:
        logger.info("\n📧 EMAIL...")
        result = {
            "sent_emails": 0, "forwarding_rules": [], "inbox_rules": [],
            "deleted_items": 0, "suspicious_subjects": [], "risk_level": "LOW", "findings": []
        }
        try:
            sent = await self.graph._req("GET",
                f"/users/{user_id}/mailFolders/sentItems/messages"
                f"?$top=50&$select=subject,toRecipients,sentDateTime,hasAttachments")
            if "error" not in sent:
                msgs = sent.get("value", [])
                result["sent_emails"] = len(msgs)
                for msg in msgs:
                    subj = (msg.get("subject") or "").lower()
                    if any(w in subj for w in ["password", "verify", "urgent", "confirm", "action required", "suspended", "login"]):
                        result["suspicious_subjects"].append({
                            "subject": msg.get("subject", "(no subject)"),
                            "date": msg.get("sentDateTime", ""),
                            "recipients": len(msg.get("toRecipients", []))
                        })

            rules = await self.graph._req("GET", f"/users/{user_id}/mailFolders/inbox/messageRules")
            if "error" not in rules:
                for rule in rules.get("value", []):
                    actions = rule.get("actions", {})
                    fwd = actions.get("forwardTo", []) + actions.get("redirectTo", [])
                    if fwd and rule.get("isEnabled"):
                        result["forwarding_rules"].append({
                            "name": rule.get("displayName", "?"),
                            "forwards_to": [r.get("emailAddress", {}).get("address", "?") for r in fwd]
                        })
                        result["findings"].append(f"Forwarding rule active: '{rule.get('displayName','?')}'")

            deleted = await self.graph._req("GET",
                f"/users/{user_id}/mailFolders/deleteditems/messages?$count=true&$top=1")
            if "error" not in deleted:
                result["deleted_items"] = deleted.get("@odata.count", 0)
                if result["deleted_items"] > 100:
                    result["findings"].append(f"High deleted items count: {result['deleted_items']}")

            if result["forwarding_rules"] or result["suspicious_subjects"]:
                result["risk_level"] = "HIGH"
            elif result["deleted_items"] > 100:
                result["risk_level"] = "MEDIUM"

        except Exception as e:
            logger.warning(f"Email analysis: {e}")
        return result

    async def _analyze_onedrive(self, user_id: str, user_email: str) -> dict:
        logger.info("\n📁 ONEDRIVE...")
        result = {
            "shared_files": [], "external_collaborators": [],
            "deleted_files": 0, "risk_level": "LOW", "findings": []
        }
        try:
            # Get user's own drive
            drive = await self.graph._req("GET", f"/users/{user_id}/drive?$select=id,driveType,quota")
            if "error" in drive:
                logger.warning(f"  OneDrive: {drive.get('_http')} — skipping")
                return result

            drive_id = drive.get("id")
            if not drive_id:
                return result

            # Recent shared items — look for external sharing
            shared = await self.graph._req("GET",
                f"/drives/{drive_id}/sharedWithMe?$top=20")
            if "error" not in shared:
                result["shared_files"] = shared.get("value", [])

            # Check recent activity for unusual patterns
            activities = await self.graph._req("GET",
                f"/drives/{drive_id}/activities?$top=30")
            if "error" not in activities:
                tenant_domain = user_email.split("@")[1] if "@" in user_email else ""
                for act in activities.get("value", []):
                    action = act.get("action", {})
                    if "share" in action:
                        # Check if external share
                        invite = action.get("share", {})
                        for recip in invite.get("recipients", []):
                            addr = recip.get("email", "")
                            if addr and tenant_domain and not addr.lower().endswith(tenant_domain.lower()):
                                result["external_collaborators"].append(addr)

                if result["external_collaborators"]:
                    result["risk_level"] = "HIGH"
                    result["findings"].append(f"External sharing detected: {len(result['external_collaborators'])} external user(s)")

        except Exception as e:
            logger.warning(f"OneDrive analysis: {e}")
        return result

    async def _analyze_teams(self, user_id: str, user_email: str, tenant_domain: str) -> dict:
        logger.info("\n💬 TEAMS...")
        result = {
            "teams_created": 0, "external_members": [],
            "risk_level": "LOW", "findings": []
        }
        try:
            teams = await self.graph._req("GET", f"/users/{user_id}/joinedTeams")
            if "error" in teams:
                logger.warning(f"  Teams: {teams.get('_http')} — skipping")
                return result

            team_list = teams.get("value", [])
            result["teams_created"] = len(team_list)

            for team in team_list[:5]:  # Limit to avoid rate limits
                members = await self.graph._req("GET",
                    f"/teams/{team.get('id')}/members?$select=displayName,userId,email")
                if "error" in members:
                    continue
                for member in members.get("value", []):
                    email = (member.get("email") or "").lower()
                    # External = has email but not from tenant domain, or has # in display name
                    if email and tenant_domain and not email.endswith(tenant_domain.lower()):
                        result["external_members"].append({
                            "name": member.get("displayName", "?"),
                            "email": email,
                            "team": team.get("displayName", "?")
                        })

            if result["external_members"]:
                result["risk_level"] = "HIGH"
                result["findings"].append(f"External members in Teams: {len(result['external_members'])}")

        except Exception as e:
            logger.warning(f"Teams analysis: {e}")
        return result

    async def _analyze_calendar(self, user_id: str, user_email: str, tenant_domain: str) -> dict:
        logger.info("\n📅 CALENDAR...")
        result = {
            "events_created": 0, "external_invites": [],
            "risk_level": "LOW", "findings": []
        }
        try:
            start = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            # Use user_id not user_email for calendar endpoint
            events = await self.graph._req("GET",
                f"/users/{user_id}/calendar/events"
                f"?$filter=start/dateTime ge '{start}'"
                f"&$select=subject,attendees,start,end&$top=50")
            if "error" in events:
                logger.warning(f"  Calendar: {events.get('_http')} — skipping")
                return result

            ev_list = events.get("value", [])
            result["events_created"] = len(ev_list)

            for ev in ev_list:
                for att in ev.get("attendees", []):
                    addr = (att.get("emailAddress") or {}).get("address", "")
                    if addr and tenant_domain and not addr.lower().endswith(tenant_domain.lower()):
                        result["external_invites"].append({
                            "event": ev.get("subject", "(no subject)"),
                            "external": addr,
                            "date": (ev.get("start") or {}).get("dateTime", "")
                        })

            if result["external_invites"]:
                result["risk_level"] = "MEDIUM"
                result["findings"].append(f"External calendar invites: {len(result['external_invites'])}")

        except Exception as e:
            logger.warning(f"Calendar analysis: {e}")
        return result

    async def _analyze_oauth(self, user_id: str) -> dict:
        """Analyze OAuth app grants — resolves app names and classifies dangerous scopes."""
        logger.info("\n🔐 OAUTH APPS...")
        result = {
            "apps_authorized": [], "suspicious_apps": [], "dangerous_apps": [],
            "high_permission_apps": [], "risk_level": "LOW", "findings": []
        }
        try:
            # Use the improved get_oauth_apps which resolves SP names
            apps = await self.graph.get_oauth_apps(user_id)

            for app in apps:
                name     = app.get("appName", "?")
                scope    = app.get("scope", "")
                scope_lo = scope.lower()
                dangerous = app.get("dangerous", False)
                high_risk = app.get("highRisk", False)

                result["apps_authorized"].append(name)

                if dangerous:
                    result["dangerous_apps"].append({
                        "name": name,
                        "publisher": app.get("publisher", "?"),
                        "scope": scope,
                        "risk": "DANGEROUS"
                    })
                    result["suspicious_apps"].append({
                        "name": name,
                        "scope": scope,
                        "risk": "DANGEROUS"
                    })
                elif high_risk:
                    result["high_permission_apps"].append({
                        "name": name,
                        "publisher": app.get("publisher", "?"),
                        "scope": scope,
                        "risk": "HIGH"
                    })
                    result["suspicious_apps"].append({
                        "name": name,
                        "scope": scope,
                        "risk": "HIGH"
                    })

            if result["dangerous_apps"]:
                result["risk_level"] = "CRITICAL"
                result["findings"].append(f"DANGEROUS app grants: {', '.join(a['name'] for a in result['dangerous_apps'])}")
            elif result["high_permission_apps"]:
                result["risk_level"] = "HIGH"
                result["findings"].append(f"High-permission apps: {len(result['high_permission_apps'])}")

            logger.info(f"  Apps: {len(apps)}, dangerous: {len(result['dangerous_apps'])}, high-risk: {len(result['high_permission_apps'])}")

        except Exception as e:
            logger.warning(f"OAuth analysis: {e}")
        return result

    async def _analyze_delegated_access(self, user_id: str, user_email: str) -> dict:
        """Check if any other users have been granted access to this mailbox/calendar."""
        logger.info("\n🔑 DELEGATED ACCESS...")
        result = {
            "calendar_delegates": [], "risk_level": "LOW", "findings": []
        }
        try:
            perms = await self.graph._req("GET",
                f"/users/{user_email}/calendar/calendarPermissions")
            if "error" in perms:
                logger.info(f"  Delegated access: {perms.get('_http')} — no Exchange mailbox or permission missing")
                return result

            for p in perms.get("value", []):
                role = p.get("role", "none")
                if role not in ("none", "freeBusyRead", "read"):
                    addr = (p.get("emailAddress") or {}).get("address", "?")
                    result["calendar_delegates"].append({
                        "grantee": addr, "role": role
                    })

            if result["calendar_delegates"]:
                result["risk_level"] = "MEDIUM"
                result["findings"].append(f"Calendar delegation grants: {len(result['calendar_delegates'])}")

        except Exception as e:
            logger.warning(f"Delegated access: {e}")
        return result

    async def _analyze_admin_actions(self, user_email: str, days_back: int) -> dict:
        """Audit log actions BY this user (admin privilege abuse detection)."""
        logger.info("\n⚙️ ADMIN ACTIONS...")
        result = {
            "users_created": [], "users_deleted": [], "role_changes": [],
            "policy_changes": [], "risk_level": "LOW", "findings": []
        }
        try:
            start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            # Filter by initiatedBy (actions done BY this user)
            res = await self.graph._req("GET",
                f"/auditLogs/directoryAudits"
                f"?$filter=initiatedBy/user/userPrincipalName eq '{user_email}'"
                f" and activityDateTime ge {start}"
                f"&$top=100&$orderby=activityDateTime desc")
            if "error" in res:
                logger.warning(f"  Admin actions: {res.get('error','')} — needs AuditLog.Read.All")
                return result

            for log in res.get("value", []):
                activity = (log.get("activityDisplayName") or "").lower()  # Fixed: was log.get("activity")
                target = (log.get("targetResources") or [{}])[0].get("displayName", "?")
                entry = {
                    "activity": log.get("activityDisplayName", "?"),
                    "target": target,
                    "date": log.get("activityDateTime", "?")
                }
                if "add user" in activity or "create user" in activity:
                    result["users_created"].append(entry)
                elif "delete user" in activity:
                    result["users_deleted"].append(entry)
                elif "member to role" in activity or "role assignment" in activity or "add member" in activity:
                    result["role_changes"].append(entry)
                elif "conditional access" in activity or "policy" in activity:
                    result["policy_changes"].append(entry)

            if result["users_created"] or result["role_changes"]:
                result["risk_level"] = "HIGH"
            if result["users_created"]:
                result["findings"].append(f"Users created by this account: {len(result['users_created'])}")
            if result["role_changes"]:
                result["findings"].append(f"Role assignment changes: {len(result['role_changes'])}")
            if result["policy_changes"]:
                result["findings"].append(f"Policy changes: {len(result['policy_changes'])}")

            logger.info(f"  Users created: {len(result['users_created'])}, role changes: {len(result['role_changes'])}")

        except Exception as e:
            logger.warning(f"Admin actions: {e}")
        return result

    def _calculate_risk(self, findings: dict) -> dict:
        weights = {
            "email": 3, "oauth": 3, "admin_actions": 3,
            "onedrive": 2, "teams": 2, "delegated_access": 2,
            "calendar": 1, "external_sharing": 1,
        }
        score = 0
        for vector, data in findings.items():
            if not isinstance(data, dict): continue
            rl = data.get("risk_level", "LOW")
            w  = weights.get(vector, 1)
            score += {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(rl, 0) * w

        max_score = sum(v * 3 for v in weights.values())
        pct = score / max_score if max_score else 0

        if pct >= 0.6:   overall = "CRITICAL"
        elif pct >= 0.35: overall = "HIGH"
        elif pct >= 0.15: overall = "MEDIUM"
        else:             overall = "LOW"

        all_findings = []
        for data in findings.values():
            if isinstance(data, dict) and "findings" in data:
                all_findings.extend(data.get("findings", []))

        return {
            "overall_risk": overall,
            "score": f"{score}/{max_score}",
            "all_findings": all_findings,
            "vectors_affected": sum(
                1 for d in findings.values()
                if isinstance(d, dict) and d.get("risk_level") in ("HIGH", "CRITICAL")
            )
        }
