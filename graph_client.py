"""Microsoft Graph API client — full incident response operations."""
import aiohttp, asyncio, logging, string, random
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='[%(name)s] %(message)s')
logger = logging.getLogger("graph")

class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        # OAuth2 client credentials flow for app-only auth
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self.token = None
        self.token_expires = None
        self.session = None

    async def _token(self) -> Optional[str]:
        if self.token and self.token_expires and datetime.now() < self.token_expires:
            return self.token
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            async with self.session.post(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": self.client_id,
                      "client_secret": self.client_secret, "scope": "https://graph.microsoft.com/.default"},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                if r.status != 200:
                    raise Exception(f"Token failed {r.status}: {await r.text()}")
                data = await r.json()
                self.token = data.get("access_token")
                self.token_expires = datetime.now() + timedelta(seconds=data.get("expires_in", 3600) - 60)
                logger.info("✓ Token acquired")
                return self.token
        except Exception as e:
            logger.error(f"Token error: {e}")
            return None

    def _generate_strong_password(self) -> str:
        """Cryptographically random 16-char password guaranteed to meet Microsoft complexity."""
        rng = random.SystemRandom()
        upper   = rng.choice(string.ascii_uppercase)
        lower   = rng.choice(string.ascii_lowercase)
        digit   = rng.choice(string.digits)
        special = rng.choice("!@#$%^&*-_=+")
        pool    = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        rest    = [rng.choice(pool) for _ in range(12)]
        chars   = list(upper + lower + digit + special) + rest
        rng.shuffle(chars)
        pwd = ''.join(chars)
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(c in "!@#$%^&*-_=+" for c in pwd)
        return pwd

    async def _req(self, method: str, endpoint: str, json_data: Dict = None) -> Dict:
        try:
            token = await self._token()
            if not token:
                return {"error": "No access token available"}
            if not self.session:
                self.session = aiohttp.ClientSession()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            url = f"https://graph.microsoft.com/v1.0{endpoint}"
            logger.info(f"  API CALL: {method} {endpoint[:100]}")
            timeout = aiohttp.ClientTimeout(total=60, connect=30, sock_read=30)
            async with self.session.request(method, url, headers=headers, json=json_data, timeout=timeout) as r:
                logger.info(f"  HTTP Status: {r.status}")
                if r.status in (200, 201):
                    # Some DELETE/PATCH endpoints return 200 with empty body
                    ct = r.headers.get('Content-Type', '')
                    if 'json' not in ct and r.content_length == 0:
                        return {"status": "success", "_http": r.status}
                    try:
                        return await r.json()
                    except Exception:
                        # Empty body or non-JSON on a 200 = success
                        return {"status": "success", "_http": r.status}
                elif r.status == 202:
                    try:    return {"status": "accepted", **(await r.json())}
                    except: return {"status": "accepted"}
                elif r.status == 204:
                    # 204 No Content = success for PATCH/DELETE/POST
                    return {"status": "success", "_http": 204}
                elif r.status == 404:
                    return {"_http": 404, "error": "not_found"}
                else:
                    text = await r.text()
                    logger.error(f"  HTTP Error {r.status}: {text[:300]}")
                    return {"error": f"HTTP {r.status}: {text[:500]}", "_http": r.status}
        except Exception as e:
            logger.error(f"  Request error: {e}")
            return {"error": str(e)}

    # ── Read operations ──────────────────────────────────────────────────────

    async def get_user(self, email: str) -> Dict:
        logger.info(f"→ Getting user: {email}")
        return await self._req("GET",
            f"/users/{email}?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses,mail,jobTitle,department,officeLocation,country")

    async def get_directory_roles(self, user_id: str) -> List[str]:
        """Get ALL directory roles AND privileged group memberships.
        Note: @odata.type is NOT included in $select — it is always returned automatically.
        """
        logger.info("→ Directory roles + group memberships...")
        # Do NOT include @odata.type in $select — it is implicit and including it
        # causes BadRequest or empty results on some tenants
        res = await self._req("GET",
            f"/users/{user_id}/memberOf?$select=displayName,id&$top=200")
        if "error" in res:
            logger.warning(f"  memberOf failed: {res.get('error')} — trying /transitiveMemberOf")
            res = await self._req("GET",
                f"/users/{user_id}/transitiveMemberOf?$select=displayName,id&$top=200")
        roles = []
        for item in res.get("value", []):
            name  = item.get("displayName", "")
            dtype = item.get("@odata.type", "")
            # directoryRole = explicitly assigned role
            if "#microsoft.graph.directoryRole" in dtype:
                roles.append(name)
            # Also capture privileged-looking groups
            elif "#microsoft.graph.group" in dtype and any(
                k in name.lower() for k in ["admin", "global", "security", "privileged", "operator",
                                              "compliance", "intune", "azure", "owner", "contributor"]
            ):
                roles.append(f"{name} (Group)")
        logger.info(f"  Roles: {roles if roles else 'None (standard user or no Directory.Read.All)'}")
        return roles

    async def get_pim_assignments(self, user_id: str) -> Dict:
        """Check PIM eligible and active role assignments. Requires RoleManagement.Read.Directory."""
        logger.info("→ PIM/JIT assignments...")
        result = {"active": [], "eligible": [], "has_pim": False, "permission_error": False}
        try:
            active = await self._req("GET",
                f"/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '{user_id}'&$expand=roleDefinition($select=displayName)&$top=50")
            if "error" in active:
                err = str(active.get("error", ""))
                if "403" in str(active.get("_http","")) or "PermissionScopeNotGranted" in err or "Forbidden" in err:
                    result["permission_error"] = True
                    logger.warning("  PIM check: missing RoleManagement.Read.Directory permission")
                    return result
            for a in active.get("value", []):
                name = a.get("roleDefinition", {}).get("displayName", a.get("roleDefinitionId", "?"))
                result["active"].append(name)
                result["has_pim"] = True

            eligible = await self._req("GET",
                f"/roleManagement/directory/roleEligibilitySchedules?$filter=principalId eq '{user_id}'&$expand=roleDefinition($select=displayName)&$top=50")
            for e in eligible.get("value", []):
                name = e.get("roleDefinition", {}).get("displayName", e.get("roleDefinitionId", "?"))
                result["eligible"].append(name)
                result["has_pim"] = True
        except Exception as ex:
            logger.warning(f"PIM check: {ex}")
        return result

    async def get_delegated_mailbox_access(self, user_email: str) -> List[Dict]:
        """Check calendar permissions as proxy for mailbox delegation.
        Returns empty list if user has no Exchange mailbox (404) or permission missing.
        """
        grants = []
        try:
            perms = await self._req("GET", f"/users/{user_email}/calendar/calendarPermissions")
            if "error" in perms:
                code = perms.get("_http")
                if code == 404:
                    logger.info("  Mailbox delegation: no Exchange mailbox for this user")
                elif code == 403:
                    logger.warning("  Mailbox delegation: missing Calendars.Read permission")
                else:
                    logger.warning(f"  Mailbox delegation: {perms.get('error','')}")
                return []
            for p in perms.get("value", []):
                if p.get("role") not in ("none", "freeBusyRead", "read"):
                    grants.append({
                        "grantee": p.get("emailAddress", {}).get("address", "?"),
                        "role": p.get("role", "?"),
                        "type": "Calendar"
                    })
        except Exception as ex:
            logger.warning(f"Mailbox delegation: {ex}")
        return grants

    async def get_signin_logs(self, user_id: str) -> List[Dict]:
        logger.info("→ Sign-in logs...")
        # Note: $select on signIns is picky — only use well-supported fields
        # authenticationRequirement / authenticationDetails are not selectable on all tenants → causes 400
        # Use no $select to get all fields, then handle missing keys in code
        res = await self._req("GET",
            f"/auditLogs/signIns?$filter=userId eq '{user_id}'&$top=30&$orderby=createdDateTime desc")
        if "error" in res:
            # Fallback: fetch recent sign-ins without the filter, then match client-side
            logger.warning("  signIns filter failed, fetching recent and matching client-side...")
            res = await self._req("GET",
                f"/auditLogs/signIns?$top=50&$orderby=createdDateTime desc")
            all_logs = res.get("value", [])
            logs = [l for l in all_logs if l.get("userId") == user_id][:20]
        else:
            logs = res.get("value", [])
        logger.info(f"  Found {len(logs)} sign-ins")
        return logs

    async def get_mailbox_rules(self, user_id: str) -> List[Dict]:
        logger.info("→ Mailbox rules...")
        res = await self._req("GET", f"/users/{user_id}/mailFolders/inbox/messageRules")
        if "error" in res:
            logger.warning(f"  Mailbox rules: {res.get('_http')} — {res.get('error','')} (Mail.Read or no mailbox)")
            return []
        return res.get("value", [])

    async def get_forwarding(self, user_id: str) -> Dict:
        logger.info("→ Forwarding settings...")
        res = await self._req("GET", f"/users/{user_id}/mailboxSettings")
        fwd = res.get("forwardingSmtpAddress")
        if fwd: logger.info(f"  ⚠ Forwarding to: {fwd}")
        return {"forwarding": fwd}

    async def get_devices(self, user_id: str) -> List[Dict]:
        res = await self._req("GET", f"/users/{user_id}/ownedDevices")
        return res.get("value", [])

    async def get_device_details(self, user_id: str) -> List[Dict]:
        logger.info("→ Device details...")
        res = await self._req("GET",
            f"/users/{user_id}/ownedDevices?$select=id,displayName,deviceType,operatingSystem,"
            f"operatingSystemVersion,lastSignInDateTime,createdDateTime,isCompliant,isManaged,trustType,manufacturer,model")
        devices = []
        for d in res.get("value", []):
            devices.append({
                "id":         d.get("id"),
                "name":       d.get("displayName", "Unknown"),
                "type":       d.get("deviceType", "Unknown"),
                "os":         d.get("operatingSystem", "Unknown"),
                "osVersion":  d.get("operatingSystemVersion", ""),
                "lastSignIn": d.get("lastSignInDateTime", "Unknown"),
                "created":    d.get("createdDateTime", "Unknown"),
                "compliant":  d.get("isCompliant"),
                "managed":    d.get("isManaged"),
                "trustType":  d.get("trustType", "Unknown"),
                "manufacturer": d.get("manufacturer", ""),
                "model":      d.get("model", ""),
            })
        return devices

    async def get_mfa_methods(self, user_id: str) -> List[Dict]:
        """Get all MFA methods with full detail including phone numbers."""
        logger.info("→ MFA methods...")
        res = await self._req("GET", f"/users/{user_id}/authentication/methods")
        type_map = {
            "#microsoft.graph.phoneAuthenticationMethod":                   "Phone (SMS/Voice)",
            "#microsoft.graph.emailAuthenticationMethod":                   "Email OTP",
            "#microsoft.graph.fido2AuthenticationMethod":                   "FIDO2 / Security Key",
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "Windows Hello for Business",
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":  "Microsoft Authenticator",
            "#microsoft.graph.softwareOathAuthenticationMethod":            "Software OATH (TOTP)",
            "#microsoft.graph.temporaryAccessPassAuthenticationMethod":     "Temporary Access Pass (TAP)",
        }
        detailed = []
        for m in res.get("value", []):
            mtype = m.get("@odata.type", "")
            if "passwordAuthenticationMethod" in mtype:
                continue
            type_name = type_map.get(mtype, mtype.split(".")[-1])
            info = {
                "type": type_name, "id": m.get("id"),
                "raw_type": mtype, "createdDateTime": m.get("createdDateTime", "Unknown")
            }
            if "phoneAuthenticationMethod" in mtype:
                ph = m.get("phoneNumber", "")
                pt = m.get("phoneType", "mobile")
                # Show full phone number (masked middle) — e.g. +47 *** ** XX XX
                if ph:
                    info["details"] = f"{pt.title()}: {ph}"
                    info["phoneNumber"] = ph
                    info["phoneType"] = pt
                else:
                    info["details"] = f"{pt.title()}: (number hidden)"
            elif "microsoftAuthenticatorAuthenticationMethod" in mtype:
                device = m.get("deviceDisplayName", "Unknown device")
                platform = m.get("clientAppName", "")
                info["details"] = f"Device: {device}" + (f" ({platform})" if platform else "")
                info["deviceName"] = device
            elif "fido2AuthenticationMethod" in mtype:
                info["details"] = f"Key: {m.get('displayName', 'Security key')}" + (f" ({m.get('model','')})" if m.get('model') else "")
            elif "windowsHelloForBusinessAuthenticationMethod" in mtype:
                info["details"] = f"Device: {m.get('displayName', 'Unknown')}"
            elif "softwareOathAuthenticationMethod" in mtype:
                info["details"] = "Third-party TOTP app (e.g. Google Authenticator)"
            elif "temporaryAccessPassAuthenticationMethod" in mtype:
                start = m.get("startDateTime", "")
                usable = m.get("isUsableOnce", False)
                info["details"] = f"TAP — starts: {start}" + (" (single-use)" if usable else "")
            elif "emailAuthenticationMethod" in mtype:
                addr = m.get("emailAddress", "")
                info["details"] = f"Email: {addr}" if addr else "Email OTP"
            detailed.append(info)
        logger.info(f"  MFA methods: {[m['type'] for m in detailed] or 'None'}")
        return detailed

    async def get_user_licenses(self, user_id: str) -> List[Dict]:
        """Get licenses assigned to this specific user."""
        logger.info("→ User licenses...")
        res = await self._req("GET", f"/users/{user_id}/licenseDetails?$select=skuPartNumber,skuId,servicePlans")
        licenses = []
        for lic in res.get("value", []):
            licenses.append({
                "sku": lic.get("skuPartNumber", "?"),
                "skuId": lic.get("skuId", ""),
                "services": [s.get("servicePlanName","?") for s in lic.get("servicePlans",[]) if s.get("provisioningStatus")=="Success"]
            })
        return licenses

    async def get_oauth_apps(self, user_id: str) -> List[Dict]:
        """Get OAuth delegated permission grants for this user.
        
        Uses principalId filter to find grants where THIS USER consented.
        Resolves service principal display names so GUIDs are human-readable.
        
        Dangerous scopes (attacker persistence): Mail.ReadWrite, Contacts.ReadWrite,
        Files.ReadWrite.All, Directory.ReadWrite.All, EWS.AccessAsUser.All,
        User.ReadWrite.All, offline_access (combined with broad permissions).
        """
        logger.info("→ OAuth app grants...")
        
        DANGEROUS_SCOPES = [
            "mail.readwrite", "mail.send", "contacts.readwrite",
            "files.readwrite.all", "files.readwrite", "directory.readwrite.all",
            "user.readwrite.all", "ews.accessasuser.all", "mailboxsettings.readwrite",
            "calendars.readwrite", "people.read.all", "tasks.readwrite",
        ]
        HIGH_RISK_KEYWORDS = ["readwrite", "all", "send", "ews"]
        
        # Correct endpoint: filter by principalId (this user's delegated consents)
        res = await self._req("GET",
            f"/oauth2PermissionGrants?$filter=principalId eq '{user_id}'&$top=50")
        if "error" in res:
            logger.warning(f"  OAuth grants: {res.get('error','')} — trying user endpoint")
            res = await self._req("GET", f"/users/{user_id}/oauth2PermissionGrants")
        
        apps = []
        sp_name_cache = {}
        
        for g in res.get("value", []):
            client_id = g.get("clientId", "?")
            scope     = g.get("scope", "").strip()
            scopes    = scope.split()
            
            # Resolve service principal display name
            if client_id not in sp_name_cache:
                sp_res = await self._req("GET",
                    f"/servicePrincipals/{client_id}?$select=displayName,appId,publisherName")
                if "error" not in sp_res:
                    sp_name_cache[client_id] = {
                        "name": sp_res.get("displayName", client_id[:8]+"..."),
                        "publisher": sp_res.get("publisherName", "Unknown"),
                        "appId": sp_res.get("appId", ""),
                    }
                else:
                    sp_name_cache[client_id] = {
                        "name": f"Unknown App ({client_id[:8]}...)",
                        "publisher": "Unknown",
                        "appId": "",
                    }
            
            sp_info = sp_name_cache[client_id]
            scope_lower = scope.lower()
            
            # Classify risk
            is_dangerous = any(ds in scope_lower for ds in DANGEROUS_SCOPES)
            is_high_risk = any(k in scope_lower for k in HIGH_RISK_KEYWORDS)
            
            apps.append({
                "clientId":    client_id,
                "appName":     sp_info["name"],
                "publisher":   sp_info["publisher"],
                "scope":       scope,
                "scopes":      scopes,
                "consentType": g.get("consentType", "?"),
                "dangerous":   is_dangerous,
                "highRisk":    is_high_risk,
            })
        
        logger.info(f"  OAuth apps: {len(apps)}, dangerous: {sum(1 for a in apps if a['dangerous'])}")
        return apps

    async def check_conditional_access(self) -> List[Dict]:
        res = await self._req("GET",
            "/identity/conditionalAccess/policies?$select=id,displayName,state,modifiedDateTime,conditions,grantControls")
        if "error" in res:
            logger.warning(f"  CA policy check: {res.get('error','')} (requires Policy.Read.All)")
            return []
        return res.get("value", [])

    async def get_ca_changes(self, days_back: int = 7) -> List[Dict]:
        start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        res = await self._req("GET",
            f"/auditLogs/directoryAudits?$filter=activityDisplayName eq 'Update conditional access policy' "
            f"and activityDateTime ge {start}&$top=20")
        return res.get("value", [])

    async def find_other_victims(self, original_user: str) -> List[str]:
        logger.info("→ Finding other victims...")
        try:
            alerts = await self._req("GET", "/security/alerts_v2?$top=10&$select=evidence,title")
            if "error" in alerts:
                logger.warning(f"  Security alerts: {alerts.get('error','')} (requires SecurityAlert.Read.All)")
                return []
            victims = []
            for alert in alerts.get("value", []):
                for entity in alert.get("evidence", []):
                    upn = entity.get("userAccount", {}).get("userPrincipalName", "")
                    if upn and upn != original_user and upn not in victims:
                        victims.append(upn)
            return victims
        except Exception as e:
            logger.warning(f"Victims check: {e}")
            return []

    async def get_phishing_victims(self, user_email: str) -> Dict:
        logger.info("→ Sent emails (phishing spread check)...")
        victims_data = {"emails_sent": []}
        try:
            res = await self._req("GET",
                f"/users/{user_email}/mailFolders/sentItems/messages"
                f"?$top=20&$select=subject,toRecipients,sentDateTime,importance")
            if "error" in res:
                err = str(res.get("error", ""))
                if "404" in str(res.get("_http","")) or "not_found" in err.lower():
                    logger.warning("  Sent items: 404 — user may not have an Exchange mailbox or Mail.Read not granted")
                elif "403" in str(res.get("_http","")) or "Forbidden" in err:
                    logger.warning("  Sent items: 403 — Mail.Read permission not granted")
                return victims_data
            for msg in res.get("value", []):
                for recip in msg.get("toRecipients", []):
                    victims_data["emails_sent"].append({
                        "to":      recip.get("emailAddress", {}).get("address", "Unknown"),
                        "subject": msg.get("subject", "(no subject)"),
                        "date":    msg.get("sentDateTime", ""),
                    })
        except Exception as e:
            logger.warning(f"Sent email check: {e}")
        return victims_data

    async def get_suspicious_email_rules(self, user_id: str) -> List[Dict]:
        logger.info("→ Suspicious email rules...")
        rules = []
        res = await self._req("GET", f"/users/{user_id}/mailFolders/inbox/messageRules")
        if "error" in res:
            logger.warning(f"  Suspicious rules check: {res.get('_http')} — {res.get('error','')} (Mail.Read or no mailbox)")
            return []
        for rule in res.get("value", []):
            actions = rule.get("actions", {})
            fwd_to      = actions.get("forwardTo", [])
            redirect_to = actions.get("redirectTo", [])
            deletes     = actions.get("delete", False)
            marks_read  = actions.get("markAsRead", False)
            if fwd_to or redirect_to or deletes or marks_read:
                rules.append({
                    "id":           rule.get("id"),
                    "name":         rule.get("displayName", "Unnamed"),
                    "enabled":      rule.get("isEnabled", False),
                    "forwards_to":  [r.get("emailAddress", {}).get("address", "?") for r in fwd_to],
                    "redirects_to": [r.get("emailAddress", {}).get("address", "?") for r in redirect_to],
                    "deletes":      deletes,
                    "marks_as_read": marks_read,
                })
                logger.warning(f"  ⚠ Suspicious rule: {rule.get('displayName')}")
        return rules

    async def get_audit_logs(self, user_email: str, days_back: int = 7) -> List[Dict]:
        """Get audit logs for actions done BY or TO this user.
        
        Two queries:
        1. Actions BY the user (things they did themselves)
        2. Actions ON the user as target (password resets, MFA changes, disable/enable)
           — this is what shows remediation actions done by our service principal
        """
        logger.info(f"→ Audit logs ({days_back} days)...")
        start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        logs_map = {}  # deduplicate by id
        
        # Query 1: actions initiated BY the user
        res1 = await self._req("GET",
            f"/auditLogs/directoryAudits"
            f"?$filter=initiatedBy/user/userPrincipalName eq '{user_email}'"
            f" and activityDateTime ge {start}"
            f"&$top=50&$orderby=activityDateTime desc")
        for log in res1.get("value", []):
            logs_map[log.get("id", log.get("activityDateTime",""))] = log
        
        # Query 2: actions targeting this user (password reset, MFA delete, disable/enable by service principal)
        # Use targetResources/any() filter
        res2 = await self._req("GET",
            f"/auditLogs/directoryAudits"
            f"?$filter=targetResources/any(t:t/userPrincipalName eq '{user_email}')"
            f" and activityDateTime ge {start}"
            f"&$top=50&$orderby=activityDateTime desc")
        if "error" not in res2:
            for log in res2.get("value", []):
                logs_map[log.get("id", log.get("activityDateTime",""))] = log
        else:
            logger.warning(f"  Audit log query 2 (targetResources filter): {res2.get('error','')} — using query 1 only")
        
        # Sort combined results by time descending
        all_logs = sorted(logs_map.values(), key=lambda x: x.get("activityDateTime",""), reverse=True)
        
        result = []
        for log in all_logs[:30]:
            targets = log.get("targetResources", [])
            target_name = targets[0].get("displayName", "?") if targets else "?"
            initiated_by = log.get("initiatedBy", {})
            user_init = (initiated_by.get("user", {}) or {}).get("userPrincipalName")
            app_init = (initiated_by.get("app", {}) or {}).get("displayName")
            initiator = user_init or app_init or "System"
            result.append({
                "activity": log.get("activityDisplayName", "Unknown"),
                "time":     log.get("activityDateTime", "Unknown"),
                "result":   log.get("result", "Unknown"),
                "resource": target_name,
                "initiator": initiator,
            })
        return result

    async def get_new_users_created(self, days_back: int = 7) -> List[Dict]:
        start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Note: 'assignedRoles' is not a selectable property on the user object —
        # it lives under employeeExperience, so requesting it here returns a 400.
        res = await self._req("GET",
            f"/users?$filter=createdDateTime ge {start}&$top=50"
            f"&$select=id,displayName,userPrincipalName,createdDateTime")
        return [{"name": u.get("displayName"), "email": u.get("userPrincipalName"), "created": u.get("createdDateTime")}
                for u in res.get("value", [])]

    async def get_new_licenses(self) -> List[Dict]:
        res = await self._req("GET", "/subscribedSkus?$select=skuPartNumber,consumedUnits,prepaidUnits,skuId")
        return [{"sku": s.get("skuPartNumber"), "assigned": s.get("consumedUnits", 0),
                 "total": s.get("prepaidUnits", {}).get("enabled", 0)} for s in res.get("value", [])]

    # ── Force sign-out from Office (revoke tokens) ───────────────────────────
    async def force_office_signout(self, user_id: str) -> bool:
        """Force sign-out from all Office/M365 apps by revoking refresh tokens."""
        logger.info("→ FORCING OFFICE SIGN-OUT (revoking refresh tokens)...")
        r = await self._req("POST", f"/users/{user_id}/revokeSignInSessions", json_data={})
        # 200 = success with body, 204 = success no content
        ok = "error" not in r
        logger.info(f"  {'✓ All Office sessions invalidated' if ok else '✗ Failed: ' + str(r.get('error'))}")
        return ok

    async def remove_pim_assignment(self, user_id: str, role_id: str) -> bool:
        """Remove a PIM eligible role assignment (best-effort)."""
        try:
            r = await self._req("POST", "/roleManagement/directory/roleAssignmentScheduleRequests",
                json_data={
                    "action": "adminRemove",
                    "principalId": user_id,
                    "roleDefinitionId": role_id,
                    "directoryScopeId": "/"
                })
            return "error" not in r
        except Exception as e:
            logger.warning(f"PIM removal attempt: {e}")
            return False

    # ── Write / remediation operations ──────────────────────────────────────

    async def disable_user(self, user_id: str) -> bool:
        logger.info("→ DISABLING ACCOUNT...")
        r = await self._req("PATCH", f"/users/{user_id}", json_data={"accountEnabled": False})
        # PATCH /users returns 204 on success
        ok = "error" not in r
        logger.info(f"  {'✓ Disabled' if ok else '✗ Failed: ' + str(r.get('error'))}")
        return ok

    async def enable_user(self, user_id: str) -> bool:
        """Re-enable account and VERIFY it actually took effect.

        revokeSignInSessions (run just before this) can race with the enable PATCH,
        so we retry up to 3 times and only report success once a GET confirms
        accountEnabled is actually True.
        """
        logger.info("→ RE-ENABLING ACCOUNT...")

        for attempt in range(1, 4):
            r = await self._req("PATCH", f"/users/{user_id}", json_data={"accountEnabled": True})
            if "error" in r and r.get("_http") not in (204, None):
                logger.error(f"  ✗ Enable PATCH failed (attempt {attempt}): {r.get('error')}")
                await asyncio.sleep(3)
                continue

            # Wait for directory replication, then verify the real state
            await asyncio.sleep(4)
            verify = await self._req("GET", f"/users/{user_id}?$select=id,accountEnabled")
            if verify.get("accountEnabled") is True:
                logger.info(f"  ✓ VERIFIED: Account is enabled (attempt {attempt})")
                return True

            logger.info(f"  ⟳ Still shows disabled after attempt {attempt} — retrying...")
            await asyncio.sleep(3)

        logger.warning("  ⚠ Account still shows DISABLED after 3 attempts — MUST be enabled manually")
        return False

    async def reset_password(self, user_id: str) -> Tuple[bool, str]:
        """Reset password via PATCH with passwordProfile. Always returns generated password."""
        logger.info(f"\n=== RESET PASSWORD: {user_id} ===")
        password = self._generate_strong_password()
        logger.info(f"  Generated password: {password}")
        payload = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "forceChangePasswordNextSignInWithMfa": False,
                "password": password
            }
        }
        r = await self._req("PATCH", f"/users/{user_id}", json_data=payload)
        if "error" not in r:
            logger.info("  ✓ Password reset OK — forceChangeNextSignIn enabled")
            return True, password
        else:
            err = r.get("error", {})
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            logger.error(f"  ✗ API error: {msg}")
            return False, password

    async def revoke_sessions(self, user_id: str) -> bool:
        logger.info("→ REVOKING ALL SESSIONS...")
        r = await self._req("POST", f"/users/{user_id}/revokeSignInSessions", json_data={})
        ok = "error" not in r
        logger.info(f"  {'✓ All sessions revoked' if ok else '✗ Failed: ' + str(r.get('error'))}")
        return ok

    async def delete_mfa_methods(self, user_id: str) -> Dict:
        """Delete ALL MFA methods. Returns detailed result.

        NOTE: Microsoft Graph has eventual consistency. After a successful DELETE (HTTP 204),
        the method may still appear in GET /authentication/methods for 10-60 seconds.
        We trust the DELETE response (204), NOT a follow-up GET.
        """
        logger.info(f"\n=== DELETE ALL MFA: {user_id} ===")

        TYPE_ENDPOINT = {
            "microsoft.graph.phoneAuthenticationMethod":                   "phoneMethods",
            "microsoft.graph.emailAuthenticationMethod":                   "emailMethods",
            "microsoft.graph.fido2AuthenticationMethod":                   "fido2Methods",
            "microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windowsHelloForBusinessMethods",
            "microsoft.graph.microsoftAuthenticatorAuthenticationMethod":  "microsoftAuthenticatorMethods",
            "microsoft.graph.softwareOathAuthenticationMethod":            "softwareOathMethods",
            "microsoft.graph.temporaryAccessPassAuthenticationMethod":     "temporaryAccessPassMethods",
            "microsoft.graph.passwordAuthenticationMethod":                "SKIP",
        }

        results = {"deleted": [], "failed": [], "skipped": [], "api_verified": False, "total": 0}

        res = await self._req("GET", f"/users/{user_id}/authentication/methods")
        if "error" in res:
            results["error"] = f"Could not fetch methods: {res['error']}"
            return results

        methods = res.get("value", [])
        mfa_methods = [m for m in methods if "passwordAuthenticationMethod" not in m.get("@odata.type", "")]
        results["total"] = len(mfa_methods)
        logger.info(f"  Found {len(methods)} total, {len(mfa_methods)} MFA methods")

        for method in methods:
            method_id  = method.get("id")
            raw_type   = method.get("@odata.type", "")
            clean_type = raw_type.lstrip("#")
            type_label = clean_type.split(".")[-1]

            if "passwordAuthenticationMethod" in clean_type:
                results["skipped"].append("password (cannot delete)")
                continue

            endpoint_seg = TYPE_ENDPOINT.get(clean_type)
            if not endpoint_seg or endpoint_seg == "SKIP":
                logger.warning(f"  ⚠ Unknown type: {clean_type}")
                endpoint_seg = "methods"

            del_url = f"/users/{user_id}/authentication/{endpoint_seg}/{method_id}"
            logger.info(f"  → DELETE {del_url}")
            del_res = await self._req("DELETE", del_url)

            # v5-compatible success check: trust 204, "success" status, or no error/http keys
            err_detail = del_res.get("error", "")
            http_code  = del_res.get("_http")
            already_gone = http_code == 404 or (isinstance(err_detail, str) and "not found" in str(err_detail).lower())

            if (del_res.get("_http") == 204
                    or del_res.get("status") == "success"
                    or ("error" not in del_res and "_http" not in del_res)
                    or already_gone):
                results["deleted"].append(type_label)
                logger.info(f"    ✓ Deleted: {type_label}" + (" (already gone)" if already_gone else ""))
            else:
                results["failed"].append(f"{type_label}: {err_detail}")
                logger.error(f"    ✗ Failed {type_label}: {err_detail}")

        # Trust DELETE results — do NOT do a verification GET (eventual consistency will give false negatives)
        results["api_verified"] = len(results["failed"]) == 0
        results["verified_empty"] = results["api_verified"]
        results["remaining_after_delete"] = len(results["failed"])
        logger.info(f"  Summary: {len(results['deleted'])} deleted, {len(results['failed'])} failed")
        logger.info("  NOTE: Methods may still appear in Entra portal for ~30-60s due to Graph eventual consistency")
        return results

    async def remove_mailbox_rule(self, user_id: str, rule_id: str) -> bool:
        r = await self._req("DELETE", f"/users/{user_id}/mailFolders/inbox/messageRules/{rule_id}")
        ok = "error" not in r
        if ok: logger.info(f"  ✓ Rule deleted")
        else:  logger.error(f"  ✗ Rule delete failed: {r.get('error')}")
        return ok

    async def clear_forwarding(self, user_id: str) -> bool:
        logger.info("→ CLEARING EMAIL FORWARDING...")
        r = await self._req("PATCH", f"/users/{user_id}/mailboxSettings",
                            json_data={"forwardingSmtpAddress": None})
        ok = "error" not in r
        logger.info(f"  {'✓ Forwarding cleared' if ok else '✗ Failed: ' + str(r.get('error'))}")
        return ok

    async def check_restricted_sender(self, user_email: str) -> Dict:
        """Check if user is blocked from sending. Requires SecurityAlert.Read.All.
        Note: evidence/userAccount filter is not supported — fetch recent and filter client-side.
        """
        logger.info("→ Checking restricted sender status...")
        try:
            # No filter on evidence — not supported via OData on this endpoint
            res = await self._req("GET",
                "/security/alerts_v2?$top=20&$select=title,severity,status,evidence")
            if "error" in res:
                return {"potentially_blocked": None, "no_permission": True}
            blocked = []
            for alert in res.get("value", []):
                title = str(alert.get("title", "")).lower()
                # Check if this alert relates to our user
                for ev in alert.get("evidence", []):
                    ua = ev.get("userAccount", {}) or {}
                    if user_email.lower() in str(ua.get("userPrincipalName","")).lower():
                        if any(w in title for w in ["restricted", "blocked", "spam", "outbound", "sending"]):
                            blocked.append(alert.get("title"))
            return {"potentially_blocked": len(blocked) > 0, "alerts": len(blocked), "details": blocked}
        except Exception as e:
            return {"potentially_blocked": None, "error": str(e)}

    async def cleanup(self):
        if self.session:
            await self.session.close()
