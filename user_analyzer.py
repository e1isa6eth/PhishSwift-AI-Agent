"""User activity analyzer — surface what actually happened during compromise."""
import logging

logger = logging.getLogger("user_analyzer")

class UserAnalyzer:
    async def analyze_user_activity(self, graph_client, user_id: str, user_email: str) -> dict:
        """Analyze sign-in activity for the user."""
        logger.info(f"\n=== ANALYZING USER ACTIVITY ({user_email}) ===")
        findings = {
            "suspicious_activities": [],
            "timeline": [],
            "risk_indicators": [],
            "likely_actions": []
        }
        try:
            signin = await graph_client.get_signin_logs(user_id)
            if signin:
                last = signin[0]
                last_time = last.get("createdDateTime", "")
                loc = last.get("location", {})
                city = loc.get("city", "?")
                country = loc.get("countryOrRegion", "?")
                if last_time:
                    findings["timeline"].append(f"Last sign-in: {last_time} from {city}, {country}")

                # Check for failed logins
                failed = [s for s in signin if s.get("status", {}).get("errorCode", 0) != 0]
                if failed:
                    findings["risk_indicators"].append(f"{len(failed)} failed login attempt(s)")

                # Check for multiple countries
                countries = set(s.get("location", {}).get("countryOrRegion", "") for s in signin if s.get("location"))
                countries.discard("")
                if len(countries) > 1:
                    findings["risk_indicators"].append(f"Sign-ins from {len(countries)} countries: {', '.join(countries)}")

        except Exception as e:
            logger.warning(f"Sign-in analysis: {e}")

        logger.info("✓ User activity analysis complete")
        if not findings["likely_actions"]:
            findings["likely_actions"] = ["No suspicious user activity detected"]
        return findings

    async def find_affected_users(self, graph_client, original_user: str) -> dict:
        """Find other users potentially affected by same attack campaign."""
        logger.info(f"\n=== FINDING AFFECTED USERS ===")
        affected = {
            "phishing_victims": [],
            "forwarding_targets": [],
            "suspicious_activity": []
        }
        try:
            # Use find_other_victims which already handles 403 gracefully
            victims = await graph_client.find_other_victims(original_user)
            affected["phishing_victims"] = victims
            logger.info(f"  Found {len(victims)} potential victims")
        except Exception as e:
            logger.warning(f"Affected users check: {e}")

        logger.info(f"✓ Found {len(affected['phishing_victims'])} potential victims")
        return affected
