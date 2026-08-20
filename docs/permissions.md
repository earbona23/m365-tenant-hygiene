# Permissions reference

Every delegated permission this module requests, the endpoint that needs it, and why
that particular permission rather than a broader one.

Each entry was checked against the Microsoft Graph API reference page for the specific
endpoint — the "Permissions" table on that page — rather than carried over from another
script. Where Microsoft documents a "least privileged" permission, that is the one used.

## Summary

| Scope | Type | Used by | Admin consent |
|---|---|---|---|
| `User.Read` | Read | Always (tenant identity) | Yes |
| `AuditLog.Read.All` | Read | MFA registration, inactive accounts | Yes |
| `User.Read.All` | Read | Inactive accounts, mail forwarding | Yes |
| `RoleManagement.Read.Directory` | Read | Privileged role assignments | Yes |
| `Application.Read.All` | Read | Risky applications | Yes |
| `Directory.Read.All` | Read | Risky applications (delegated grants) | Yes |
| `MailboxSettings.Read` | Read | Mail forwarding | Yes |
| `DeviceManagementManagedDevices.Read.All` | Read | Device compliance | Yes |

No `.ReadWrite` permission is requested. `tests/ReadOnly.Tests.ps1` asserts that every
scope in the registry matches a read pattern, so this table cannot silently drift.

---

## `User.Read` — tenant identity

**Endpoint:** `GET /organization?$select=id,displayName,verifiedDomains`
**Reference:** [Get organization](https://learn.microsoft.com/graph/api/organization-get)

The module needs three things about the tenant: its id, its display name for the report
header, and its **verified domains** — which is how the mail forwarding check decides
whether a recipient is external.

Microsoft documents the delegated permissions for this endpoint as
`User.Read, Organization.Read.All, Directory.Read.All, …`, and notes that an app granted
only `User.Read` can read the **id**, **displayName** and **verifiedDomains** properties,
with everything else returning null. Those are exactly the three properties needed, so
`User.Read` is sufficient and `Organization.Read.All` would be over-asking.

If this call fails, the mail forwarding check reports `Skipped` rather than guessing what
counts as external.

---

## `AuditLog.Read.All` — MFA registration and sign-in activity

**Endpoints:**
- `GET /reports/authenticationMethods/userRegistrationDetails`
- `GET /users?$select=…,signInActivity`

**References:**
[List userRegistrationDetails](https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails) ·
[user resource type](https://learn.microsoft.com/graph/api/resources/user)

For the registration report, `AuditLog.Read.All` is the **only** delegated permission
accepted; Microsoft's table lists no higher-privileged alternative and no narrower one.

For `signInActivity`, Microsoft's documentation is explicit: the property "requires a
Microsoft Entra ID P1 or P2 licence and the `AuditLog.Read.All` permission." It is also
only returned when explicitly selected with `$select`, and selecting it caps the page
size at 500 — both behaviours the module accounts for.

Microsoft additionally requires the signed-in user to hold a supporting directory role.
For the registration report the least-privileged options are **Reports Reader**,
**Security Reader**, **Security Administrator** or **Global Reader**.

Despite the name, this permission does not give the module access to sign-in log
contents in this design; it reads a registration summary and a per-user timestamp.

---

## `User.Read.All` — directory user attributes

**Endpoint:** `GET /users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses,signInActivity`
**Reference:** [List users](https://learn.microsoft.com/graph/api/user-list)

Reads the attributes the checks reason about: whether an account is enabled, whether it
is a guest, when it was created, and whether it holds a licence. The mail forwarding
check also uses this list to know which mailboxes to try.

The read-only variant is deliberate: `User.ReadWrite.All` would satisfy the same
endpoint and is never requested.

---

## `RoleManagement.Read.Directory` — privileged role assignments

**Endpoints:**
- `GET /roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn`
- `GET /roleManagement/directory/roleAssignments?$expand=principal`

**Reference:** [List unifiedRoleAssignments](https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignments)

Microsoft lists `RoleManagement.Read.Directory` first as the least-privileged option for
the directory RBAC provider. `Directory.Read.All` also satisfies these endpoints but
grants far more, so it is not used here.

Supporting directory roles, least-privileged first: **Directory Readers**,
**Global Reader**, **Privileged Role Administrator**.

`$expand=principal` returns the user, group or service principal behind each assignment
in the same request, which is what lets the check distinguish a guest administrator from
a member one without a second round trip per assignment.

**Coverage limit:** this endpoint returns *active* assignments. Privileged Identity
Management *eligible* assignments are not included.

---

## `Application.Read.All` — application identities and app roles

**Endpoints:**
- `GET /servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId`
- `GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=…,appRoles`
- `GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo`

**Reference:** [List appRoleAssignments granted for a service principal](https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignedto)

`Application.Read.All` is Microsoft's least-privileged delegated permission for reading
app role assignments; `Directory.Read.All` and the `.ReadWrite` variants are listed as
higher-privileged alternatives and are not used for this purpose.

`00000003-0000-0000-c000-000000000000` is the well-known application id of the Microsoft
Graph API, identical in every tenant. Querying `appRoleAssignedTo` on it returns every
principal granted an application permission on Microsoft Graph in a single request,
instead of one request per service principal.

The service principal list is also read so the report can name the applications and tell
first-party from externally published ones, using `appOwnerOrganizationId`.

---

## `Directory.Read.All` — tenant-wide delegated grants

**Endpoint:** `GET /oauth2PermissionGrants`
**Reference:** [List oauth2PermissionGrants](https://learn.microsoft.com/graph/api/oauth2permissiongrant-list)

This is the one place the module asks for a broad directory read, and it is deliberate.

Microsoft's permissions table for this endpoint lists exactly two delegated options:
`Directory.Read.All` as least-privileged, and `DelegatedPermissionGrant.ReadWrite.All`
or `Directory.ReadWrite.All` as higher-privileged. The narrower-sounding
`DelegatedPermissionGrant.*` permission exists only in a `ReadWrite` form — it is a
**write** permission. Requesting it to perform a read would grant this module the ability
to modify consent grants across the tenant, which contradicts the entire design.

`Directory.Read.All` is therefore the least-privileged *read* option available, and it is
requested only when the `RiskyApplication` check is selected.

Supporting directory roles include **Directory Readers** and **Global Reader**.

---

## `MailboxSettings.Read` — inbox rules

**Endpoint:** `GET /users/{id}/mailFolders/inbox/messageRules`
**Reference:** [List rules](https://learn.microsoft.com/graph/api/mailfolder-list-messagerules)

Microsoft lists `MailboxSettings.Read` as the least-privileged permission, with no
higher-privileged alternative. It reads mailbox configuration, not mail: this module
never requests `Mail.Read` and never reads a message body, subject or attachment.

**Coverage limit — read this before relying on a clean result.** Delegated permissions
grant the intersection of the app's consent and what the signed-in user is themselves
allowed to do. Holding a Microsoft Entra administrative role does not, by itself, grant
the right to open another user's mailbox; that is an Exchange Online access grant. In
practice this check reaches:

- the signed-in user's own mailbox, and
- any mailbox on which they hold Full Access.

Graph returns `403` for the rest. The check counts those refusals, and if every mailbox
was refused it reports `Skipped` rather than reporting no findings. Tenant-wide coverage
requires application permissions — a different consent model, with a stored credential —
which this module deliberately does not use.

---

## `DeviceManagementManagedDevices.Read.All` — Intune device compliance

**Endpoint:** `GET /deviceManagement/managedDevices`
**Reference:** [List managedDevices](https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list)

Microsoft lists `DeviceManagementManagedDevices.Read.All` as the least-privileged
delegated permission, with `.ReadWrite.All` as the alternative.

Two prerequisites beyond consent:

1. **An active Intune licence on the tenant.** Microsoft notes that the Graph API for
   Intune requires one. Without it the endpoint is unavailable and the check reports
   `Skipped`, not zero non-compliant devices.
2. **An Intune role for the signed-in account.** Intune applies its own role-based
   access control on top of Microsoft Entra roles. If the check reports `Skipped` with
   an access error, assign a read-only Intune role such as **Read Only Operator**.

---

## Verifying what was actually granted

Consent can end up narrower than what was requested — an administrator may approve part
of a request, or tenant policy may restrict it. Check before a long run:

```powershell
Test-M365HygienePermission | Where-Object { -not $_.Satisfied }
```

This compares the access token's scope claim against each check's requirements. It
cannot see the other half of delegated access — whether your directory role permits the
underlying read — which only surfaces at call time. When that happens, the affected
check reports `Skipped` with the Graph error attached, and the report states the gap
above the findings.
