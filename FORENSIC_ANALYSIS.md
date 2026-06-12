# Comprehensive Forensic Analysis

## What Gets Checked

The agent now performs a **complete forensic analysis** of ALL possible compromise vectors:

### 1. **📧 EMAIL**
- Emails sent by compromised user (phishing spread)
- Forwarding rules (attacker's email addresses)
- Inbox rules (hiding/redirecting mails)
- Suspicious subject keywords ("password", "verify", "urgent")
- Deleted items count (evidence destruction)

**Risk indicators:**
- 🔴 HIGH: Active forwarding rules to external addresses
- 🟡 MEDIUM: Many deleted emails (>100)
- 🟢 LOW: Normal email activity

**Questions to ask AI:** 
- "Who did this user send suspicious emails to?"
- "What forwarding rules were set up?"
- "Are there deleted emails that need recovery?"

---

### 2. **📁 ONEDRIVE & SHAREPOINT**
- Files shared externally
- External collaborators (who has access)
- New folders created
- Recent file activity

**Risk indicators:**
- 🔴 HIGH: Files shared with external users
- 🟡 MEDIUM: Unusual number of shares
- 🟢 LOW: No external sharing

**Questions to ask AI:**
- "What files were shared externally?"
- "Who has access to sensitive data?"
- "Were any folders shared to external users?"

---

### 3. **💬 TEAMS**
- New Teams created by user
- Channels created
- External members added
- Messages sent

**Risk indicators:**
- 🔴 HIGH: External users in private teams
- 🟡 MEDIUM: Multiple new teams created
- 🟢 LOW: Normal team usage

**Questions to ask AI:**
- "Were external users added to Teams?"
- "What Teams were created recently?"
- "Is this team activity normal?"

---

### 4. **📅 CALENDAR**
- Events created in last 7 days
- External attendees invited
- Calendar sharing
- Meeting patterns

**Risk indicators:**
- 🔴 HIGH: Inviting external users to sensitive meetings
- 🟡 MEDIUM: Multiple calendar invites to external addresses
- 🟢 LOW: Normal meeting activity

**Questions to ask AI:**
- "Were any external users invited to meetings?"
- "What meetings were created during compromise?"

---

### 5. **🔐 OAUTH & APPS**
- Apps authorized/granted permissions
- Suspicious app permissions
- Broad permission grants
- Admin apps (if user is admin)

**Risk indicators:**
- 🔴 HIGH: Mail/Calendar/Admin apps authorized
- 🟡 MEDIUM: Unknown apps with broad permissions
- 🟢 LOW: Limited scope permissions

**Questions to ask AI:**
- "What apps were granted access?"
- "Which apps have suspicious permissions?"
- "Are there any admin-level apps authorized?"

---

### 6. **🔧 ADMIN ACTIONS** (If user is admin)
- New users created (backdoor accounts)
- Users deleted
- Role assignments changed
- Policy modifications

**Risk indicators:**
- 🔴 HIGH: New admin users created
- 🟡 MEDIUM: Role changes on sensitive accounts
- 🟢 LOW: Normal admin activity

**Questions to ask AI:**
- "What new users were created?"
- "Were any admin roles assigned?"
- "What policies were changed?"

---

### 7. **🌐 EXTERNAL SHARING**
- External collaborators and their access level
- Link shares (anyone with link)
- Access duration/permissions

---

### 8. **🔑 DELEGATED ACCESS**
- Send As permissions (who can impersonate)
- Send On Behalf permissions
- Full mailbox access

---

## How to Use in Chat

### Example 1: Ask about email compromise
```
You: "Was there any email forwarding?"
AI: "Yes, I found 2 forwarding rules:
    1. Rule: 'Archive emails' forwards to attacker@evil.com
    2. Rule: 'Backup' forwards to suspicious@gmail.com
    
    These should be deleted immediately and emails at those 
    addresses should be investigated."
```

### Example 2: Ask about data exfiltration
```
You: "What files were shared externally?"
AI: "Found 5 external shares:
    1. Contracts folder shared with john.doe@external.com
    2. Q3 Reports shared with anyone with link
    3. Customer list shared with contractor@company.com
    
    Recommend: Check access logs, revoke shares, 
    notify data owner."
```

### Example 3: Ask about lateral movement
```
You: "Were any Teams or accounts created?"
AI: "Yes:
    - 1 new Team created: 'Emergency Access'
    - 2 new users created (potential backdoor accounts)
    - External user added to Admin team
    
    These are HIGH RISK indicators of persistence."
```

---

## Risk Scoring

Overall risk = Sum of all vectors

```
CRITICAL (15+/18):
- Multiple HIGH risk areas
- Evidence of data exfiltration
- Admin compromise with new users/roles

HIGH (10-14/18):
- 1-2 HIGH risk areas
- External sharing or forwarding detected
- Significant compromise scope

MEDIUM (5-9/18):
- Email compromise only
- Limited external exposure
- Suspicious activity but contained

LOW (0-4/18):
- No suspicious activity
- Normal usage patterns
- No evidence of compromise
```

---

## What Happens With Each Finding

| Finding | What it means | Action |
|---------|---------------|--------|
| Forwarding rule | Attacker forwarding mails | Delete rule, check forwarded emails |
| External share | Data exfiltration | Revoke share, audit who accessed |
| New Teams | Lateral movement | Check members, delete if suspicious |
| New user (admin) | Backdoor account | Delete user, check actions they took |
| OAuth app | Persistent access | Revoke app, check what it accessed |
| Calendar invite external | Social engineering | Notify recipient, warn about phishing |

---

## Chat Commands

Ask the AI agent anything about the compromise:

- "What was compromised?" → Full summary
- "How bad is this?" → Risk assessment
- "Was data stolen?" → External sharing analysis
- "Can they still access?" → OAuth/app permissions
- "Who else was affected?" → Affected users
- "What do we do?" → Remediation recommendations
- "Show me emails sent" → Email activity
- "Check Teams access" → Teams compromise
- "What admin actions?" → Admin activity (if admin user)

---

## Advanced Questions

```
"What happened during the compromise window?"
→ Shows timeline of all activities

"Who can still access the account?"
→ Shows OAuth apps, delegated access, active sessions

"What persistence mechanisms were set up?"
→ Shows forwarding rules, backdoor users, OAuth apps

"Which departments were targeted?"
→ Shows recipients of emails, Teams with external users

"How much data was accessed?"
→ Shows files shared, external collaborators, download activity
```

---

## Next Steps After Analysis

1. **Immediate:** Block account (already done in remediation)
2. **Emails:** Check forwarded email addresses, recover deleted items
3. **Sharing:** Revoke external access, notify data owners
4. **Teams/Orgs:** Remove external users, check channels
5. **Apps:** Revoke suspicious OAuth apps
6. **Admin:** Delete backdoor users, audit role changes
7. **Notify:** Contact recipients of phishing emails
8. **Monitor:** Watch for re-compromise using same vectors

