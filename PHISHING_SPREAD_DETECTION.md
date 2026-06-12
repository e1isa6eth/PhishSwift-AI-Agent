# Phishing Spread Detection

## What Gets Checked

### 1. **Emails Sent by Compromised User** 📧
When a user is compromised, attackers often:
- Send phishing emails to other users
- Spread malware links
- Forward sensitive data
- Impersonate the user

**The agent now shows:**
- All emails sent by compromised user (last 20)
- Recipients (who got phishing)
- Subject lines
- Send dates

**Action:** Check these emails - any suspicious ones?

---

### 2. **Suspicious Email Rules** ⚠️
Attackers often set up inbox rules to:
- **Forward** emails to attacker's email
- **Redirect** emails away from victim
- **Mark as read** so victim doesn't see them
- **Delete** sensitive emails automatically

**The agent now shows:**
- All rules that forward/redirect/hide emails
- Rule names and status (enabled/disabled)
- Where they forward to
- Dates they were created

**Action items:**
- Delete these rules immediately
- Check forwarded emails at external addresses
- Restore deleted emails from Deleted Items

---

### 3. **Other Affected Users** 👥
From analysis, agent also shows:
- Users in same department (might be targeted)
- Users who received emails from this user
- Recommended for notification

---

## How Phishing Spreads

```
1. User A gets phishing email
   ↓
2. User A clicks link / opens malware
   ↓
3. Account compromised
   ↓
4. Attacker sends from User A's email to:
   - User B, C, D, E... (coworkers)
   - Managers (trust = higher click rate)
   - External addresses (data exfiltration)
   ↓
5. Rules hide the emails (marks as read, forwards away)
   ↓
6. Multiple users compromised (chain reaction)
```

---

## What You Should Do

### During Incident Response:

1. **Check emails sent list**
   - Are subjects legitimate?
   - Do recipients look right?
   - Any suspicious domains?

2. **Delete suspicious rules**
   - Remove forward rules
   - Remove redirect rules
   - Remove "mark as read" rules
   - Check the 8-step remediation handles this

3. **Notify recipients**
   - Send message to all recipients in "Emails Sent"
   - Warning: check for phishing/malware
   - Example: "Check emails from [user] between [date1-date2] for phishing"

4. **Check other users**
   - Look at "Affected Users" list
   - Run same analysis on them
   - Break the chain early

### After Incident:

5. **Email trace**
   - In Exchange Admin Center > Mail flow > Message trace
   - Search for subject keywords
   - See who else got the phishing mail

6. **Defender Explorer**
   - In Microsoft Defender > Email & collaboration > Explorer
   - Search by sender, URL, or keyword
   - Find all mailboxes affected

---

## Red Flags to Watch For

🚨 **HIGH RISK:**
- Rules forwarding to external email addresses
- Multiple rules set up at same time
- Rules marked as read (hiding emails)
- Rules that delete emails
- Large number of emails sent in short time

⚠️ **MEDIUM RISK:**
- Rules moving emails to other folders
- Rules with complex filters (hiding the real target)
- Sent emails with urgent-sounding subjects
- Emails to distribution lists or managers

---

## Example Scenarios

### Scenario 1: Business Email Compromise (BEC)
```
Attacker compromises CFO's account
Sets up rule: Forward to attacker.com
Victim gets payment requests
CFO's team doesn't see the forwarded emails
$50k transferred before anyone notices
```

**Prevention:** Check for forward rules daily!

### Scenario 2: Lateral Movement
```
Junior employee compromised
Attacker sends fake "password reset" email to all finance team
3 more employees compromised
Now attacker has 4 accounts
```

**Prevention:** Notify recipients quickly!

### Scenario 3: Data Exfiltration
```
Marketing manager compromised
Attacker sets rule: Forward emails with "contract" to external email
Customer contracts forwarded for 2 weeks
```

**Prevention:** Check external forwards in rules!

---

## Next Steps in Agent

The agent will eventually check:
- ✅ Emails sent by user (DONE)
- ✅ Suspicious forwarding rules (DONE)
- ⚠️ Defender email trace (need Defender license)
- ⚠️ Who clicked same phishing link (need Defender explorer)
- ⚠️ Data exfiltration via Teams/SharePoint (future)

