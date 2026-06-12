# Microsoft Graph API Permissions Required

## Quick Setup

Your Azure AD app registration needs these **Application** permissions (not Delegated):

### CRITICAL PERMISSIONS (Required)
- ✅ `User.Read.All` - Read user profiles
- ✅ `Mail.Read` - Read mailbox rules and forwarding
- ✅ `Directory.Read.All` - Read directory (audit logs, roles)
- ✅ `AuditLog.Read.All` - Read audit logs and sign-in logs
- ✅ `Organization.Read.All` - Read organization (licenses)
- ✅ `Device.Read.All` - Read device information

### ADMIN OPERATIONS (Required for remediation)
- ✅ `UserAuthenticationMethod.ReadWrite.All` - Reset password, delete MFA
- ✅ `User.ReadWrite.All` - Disable/enable accounts
- ✅ `Mail.ReadWrite` - Modify mailbox rules and forwarding
- ✅ `AuditLog.Read.All` - Read audit logs during remediation

### OPTIONAL (Future features)
- `DelegatedPermissionGrant.ReadWrite.All` - OAuth app analysis
- `Policy.Read.All` - Conditional Access policy check
- `SecurityEvents.Read.All` - Defender incidents/alerts

---

## How to Add Permissions in Azure Portal

1. **Go to Azure Portal**
   - https://portal.azure.com
   - Entra ID > App registrations > Your app

2. **Click "API permissions"**

3. **Click "Add a permission"**
   - Select "Microsoft Graph"
   - Select "Application permissions"

4. **Add these permissions:**
   ```
   AuditLog.Read.All
   Device.Read.All
   Directory.Read.All
   Mail.Read
   Mail.ReadWrite
   Organization.Read.All
   User.Read.All
   User.ReadWrite.All
   UserAuthenticationMethod.ReadWrite.All
   ```

5. **Click "Grant admin consent"**
   - MUST be done by tenant admin
   - Status should show "Granted"

---

## What Each Permission Does

### User.Read.All
- List all users
- Get user details (name, email, roles)
- Required: Always

### User.ReadWrite.All
- Disable/enable user accounts
- Reset passwords
- Update user properties
- Required: For remediation steps

### Mail.Read
- Read mailbox rules
- Read forwarding settings
- Required: For analysis

### Mail.ReadWrite
- Delete mailbox rules
- Clear email forwarding
- Required: For remediation step 5-6

### UserAuthenticationMethod.ReadWrite.All
- Delete MFA methods (phone, authenticator, etc)
- Reset password via authentication methods
- Required: For remediation step 2-3

### Directory.Read.All
- Read directory roles (admin roles)
- Read organizational structure
- Required: For admin detection

### AuditLog.Read.All
- Read audit logs (admin activity)
- Read sign-in logs (suspicious locations)
- Required: For admin forensics

### Organization.Read.All
- Read subscribed licenses
- Read organization info
- Required: For admin license check

### Device.Read.All
- Read device information (registered devices)
- Get device creation dates
- Required: For device analysis

---

## Verification

After adding permissions, verify they work by checking logs:

```
If you see these in logs:
✓ Response: Success (200/201)
✓ Deleted MFA methods: ...
✓ Found X audit logs

Then permissions are working!

If you see:
✗ HTTP Error 403: accessDenied
✗ HTTP Error 401: unauthorized

Then check:
1. Permissions are added
2. Admin consent was granted (not just user consent)
3. Client secret is valid
4. Permissions have been refreshed (may take 5 min)
```

---

## For Your Azure AD Setup

Minimum scope in your app registration:
```
https://graph.microsoft.com/.default
```

This scope includes ALL permissions you've granted to the app.

---

## Questions?

If you get permission errors:
1. Check Azure Portal > App registrations > API permissions
2. Look for status "Granted" (green checkmark)
3. If not granted, click "Grant admin consent" button
4. Wait 5 minutes for refresh
5. Retry analysis

