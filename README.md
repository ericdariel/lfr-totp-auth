# TOTP Liferay — Google Authenticator MFA

Full two-factor authentication (2FA) implementation via Google Authenticator
for Liferay users in a configurable regular role (default: Administrator),
using OSGi services only (no ServiceUtil).

---

## Module structure

```
lfr-totp-auth/
├── totp-authenticator/   ← Login interceptor, filter, TOTP logic, tests
├── totp-rest/            ← JAX-RS OSGi REST endpoints
└── totp-fragments/       ← Liferay fragments (setup + verify)
```

All three modules are declared in the parent POM `lfr-totp-auth/pom.xml`.

---

## Modules

### totp-authenticator
- `TotpLoginMVCActionCommand` — Intercepts `/login/login` before the LNE hook
- `TotpTwoFactorLoginService` — Step 1: validates password without creating a session
- `TOTPLoginFilter` — Servlet filter (setup, verify, MFA login completion)
- `TotpPendingLoginUtil` — Challenge and pending session between the two steps
- `TotpSessionUtil` / `TotpRedirectUtil` — TOTP state and post-login redirect
- `TotpLogoutAction` — Cleanup on logout
- `TotpRoleChecker` — Reads system configuration and checks the MFA role
- `TOTPService` — TOTP logic: generation, verification, Expando
- Mockito unit tests + Arquillian integration tests

### totp-rest
- `TOTPRestApplication` — JAX-RS OSGi application (`/o/totp/api`): setup + verify
- `TotpRestUtil` — User resolution and redirect helpers for REST endpoints

Depends on `totp-authenticator` (exported services and utilities).

### totp-fragments
- Fragment `totp-setup`  — QR code setup page (3 steps)
- Fragment `totp-verify` — Login code entry page (+ backup codes)

Depends on `totp-authenticator` (exported services and utilities).

---

## System configuration

Control Panel → Configuration → System Settings → **Security** →
**TOTP Authentication**

| Setting | Description | Default |
|---------|-------------|---------|
| Required role name | Regular role whose members must configure and verify TOTP | `Administrator` |

Use the exact role name as defined in Liferay (for example `Administrator`,
`Power User`, or a custom regular role). If the role does not exist, TOTP
enforcement is disabled until a valid name is configured.

---

## REST endpoints

| Method | URL                          | Description                          |
|--------|------------------------------|--------------------------------------|
| GET    | /o/totp/api/ping             | Health check                         |
| GET    | /o/totp/api/setup/init       | Generates QR code + backup codes     |
| POST   | /o/totp/api/setup/confirm    | Validates and saves the secret       |
| POST   | /o/totp/api/setup/reset      | Deletes and resets TOTP              |
| POST   | /o/totp/api/verify/code      | Verifies TOTP code (step 2)          |
| POST   | /o/totp/api/verify/backup    | Verifies a backup code               |

---

## Main dependencies

- `com.warrenstrange:googleauth:1.5.0`
- `com.google.zxing:javase:3.5.1`
- `org.mindrot:jbcrypt:0.4`
- Liferay Portal Kernel 7.4.x

---

## Build

```bash
cd modules/totp-auth
mvn clean install
```

Generated OSGi bundles are under `target/` in each module.
Deploy all three JARs to `[LIFERAY_HOME]/deploy/`:
- `com.monapp.totp.authenticator-*.jar`
- `com.monapp.totp.rest-*.jar`
- `com.monapp.totp.fragments-*.jar`

---

## Administrator flow (2 steps)

```
1. Login email + password
        ↓
   TotpLoginMVCActionCommand → TotpTwoFactorLoginService
        ↓
   TOTP configured?
   ┌── No ──→ Password validated WITHOUT session
   │           → /web/guest/totp-setup?challenge=...
   │           → GET /o/totp/api/setup/init
   │           → POST /o/totp/api/setup/confirm
   │           → GET /c/portal/totp-complete-login?challenge=...
   │           → TOTPLoginFilter creates the session
   │
   └── Yes ─→ Password validated WITHOUT session
              → /web/guest/totp-verify?challenge=...
              → POST /o/totp/api/verify/code (or /verify/backup)
              → GET /c/portal/totp-complete-login?challenge=...
              → TOTPLoginFilter creates the session → site redirect
```

For an already signed-in administrator without TOTP configured, `TOTPLoginFilter`
also redirects to `/web/guest/totp-setup`.

---

## Storage

Secrets and backup codes are stored via **Expando** (Liferay Custom Fields):
- `totpSecret`      — Base32 secret
- `totpBackupCodes` — Hashed backup codes (BCrypt), 5 single-use codes in `XXXX-XXXX-XXXX-XXXX` format (alphanumeric, no ambiguous characters)

Create the columns in: Control Panel → Users → Custom Fields → User
