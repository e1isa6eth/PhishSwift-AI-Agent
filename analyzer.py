"""Analyzer - Threat analysis and privilege detection"""
import logging
logger = logging.getLogger("analyzer")

class Analyzer:
    def analyze(self, graph_data: dict) -> dict:
        """Analyze suspicious activity"""
        logger.info("\n=== THREAT ANALYSIS ===")
        
        findings = {
            "rules": False,
            "forwarding": False,
            "signin": False,
            "devices": False,
            "threat_score": 60,
            "details": []
        }
        
        # Check mailbox rules for forwarding or blocking
        if graph_data.get("mailbox_rules"):
            findings["rules"] = True
            logger.info(f"⚠ MAILBOX RULES: {len(graph_data['mailbox_rules'])} suspicious rules")
            for r in graph_data['mailbox_rules']:
                rule_name = r.get('displayName', 'Unknown')
                findings["details"].append(f"Rule: {rule_name}")
                logger.info(f"  • {rule_name}")
        
        # Check forwarding
        if graph_data.get("forwarding"):
            findings["forwarding"] = True
            fwd = graph_data['forwarding']
            logger.info(f"⚠ EMAIL FORWARDING: {fwd}")
            findings["details"].append(f"Forwarding to: {fwd}")
        
        # Check device count
        devices = graph_data.get("devices", [])
        if len(devices) > 5:
            findings["devices"] = True
            logger.info(f"⚠ MULTIPLE DEVICES: {len(devices)} registered")
            findings["details"].append(f"{len(devices)} devices found")
        
        # Calculate threat score
        threat_indicators = sum([
            findings["rules"],
            findings["forwarding"],
            findings["devices"] * 0.5  # Slight weight
        ])
        
        if threat_indicators >= 2:
            findings["threat_score"] = 85
        elif threat_indicators >= 1:
            findings["threat_score"] = 75
        else:
            findings["threat_score"] = 60
        
        logger.info(f"\n✓ Threat Score: {findings['threat_score']}/100")
        return findings
    
    
    def analyze_signin_logs(self, signin_logs: list) -> dict:
        """Analyze sign-in logs for suspicious activity"""
        logger.info("=== SIGN-IN LOG ANALYSIS ===")
        
        suspicious = {
            "unusual_locations": [],
            "impossible_travel": [],
            "failed_mfa": [],
            "risk_level": "low"
        }
        
        if not signin_logs:
            logger.info("No sign-in logs found")
            return suspicious
        
        # Convert to sorted list by timestamp (newest first)
        sorted_logs = sorted(signin_logs, key=lambda x: x.get("createdDateTime", ""), reverse=True)
        
        last_location = None
        last_country = None
        last_time = None
        
        for log in sorted_logs[:10]:  # Check last 10 logins
            location = log.get("location", {})
            city = location.get("city", "Unknown")
            country = location.get("countryOrRegion", "Unknown")
            created = log.get("createdDateTime", "Unknown")
            status = log.get("status", {}).get("additionalDetails", "Unknown")
            
            # Check for unusual locations (high-risk countries, VPN, etc)
            if country.lower() in ["north korea", "iran", "syria", "unknown"]:
                suspicious["unusual_locations"].append({
                    "location": f"{city}, {country}",
                    "time": created,
                    "risk": "HIGH"
                })
                logger.warning(f"⚠️ HIGH-RISK location: {city}, {country}")
            
            # Check for impossible travel — only flag if COUNTRY changes
            # (city-level changes are normal, e.g. mobile users, VPN, CDN)
            current_country = country.lower()
            if last_country and last_time and last_country not in ("unknown", "") and current_country not in ("unknown", ""):
                if last_country != current_country:
                    suspicious["impossible_travel"].append({
                        "from": last_location,
                        "to": f"{city}, {country}",
                        "time": created
                    })
                    logger.warning(f"⚠️ Country change: {last_location} → {city}, {country}")
            
            # Check for failed MFA
            if "mfa" in status.lower() and "fail" in status.lower():
                suspicious["failed_mfa"].append({
                    "time": created,
                    "detail": status
                })
                logger.warning(f"⚠️ Failed MFA: {created}")
            
            last_location = f"{city}, {country}"
            last_country = current_country
            last_time = created
        
        # Set risk level
        if suspicious["unusual_locations"] or suspicious["impossible_travel"]:
            suspicious["risk_level"] = "HIGH"
        elif suspicious["failed_mfa"]:
            suspicious["risk_level"] = "MEDIUM"
        
        return suspicious
    
    def detect_privilege(self, roles: list) -> dict:
        """Detect if user is privileged - check ALL admin role types"""
        logger.info("\n=== PRIVILEGE DETECTION ===")
        
        # ALL admin role types from documentation
        # Only actual privileged roles — not readers or job titles
        admin_keywords = [
            "global administrator",
            "exchange administrator",
            "user administrator",
            "sharepoint administrator",
            "security administrator",
            "compliance administrator",
            "teams administrator",
            "power platform administrator",
            "application administrator",
            "cloud application administrator",
            "directory synchronization accounts",
            "privileged role administrator",
            "privileged authentication administrator",
            "authentication administrator",
            "conditional access administrator",
            "intune administrator",
            "license administrator",
            "service support administrator",
            "billing administrator",
            "helpdesk administrator",
            "identity governance administrator",
            "security operator",
            "cloud app security administrator",
            # Generic catch for any admin role not listed above
            "administrator",
        ]
        
        admin_roles = []
        for role in roles:
            role_lower = str(role).lower()
            if any(keyword in role_lower for keyword in admin_keywords):
                admin_roles.append(role)
                logger.warning(f"  ⚠️  ADMIN ROLE: {role}")
        
        is_priv = len(admin_roles) > 0
        
        if is_priv:
            logger.warning(f"⚠️  PRIVILEGED USER - {len(admin_roles)} admin role(s)")
        else:
            logger.info(f"✓ Standard user")
        
        return {
            "is_privileged": is_priv,
            "admin_roles": admin_roles,
            "all_roles": roles
        }
