# Authentication System

Adds user authentication to CipherFlag with JWT tokens in HTTP-only cookies, two roles (admin/viewer), bcrypt password hashing, and a first-visit admin registration flow. Backward compatible — existing deployments without users continue to work without auth.

## Database Schema

New migration `005_auth.sql`:

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);
```

Roles: `admin` (manage users, change settings) and `viewer` (read-only access to all data).

## Authentication Flow

1. User visits any page → SvelteKit checks for `cipherflag_token` cookie
2. No cookie → redirect to `/login`
3. User submits email + password → `POST /api/v1/auth/login`
4. Backend validates credentials via bcrypt, returns `Set-Cookie: cipherflag_token=<JWT>; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
5. JWT payload: `{ user_id, email, role, exp }` — 24-hour expiry
6. All subsequent API requests include the cookie automatically (same-origin)
7. Auth middleware validates JWT on every API request, injects user context into request context
8. Logout → `POST /api/v1/auth/logout` sets cookie with `Max-Age=0` to clear it

### Backward Compatibility

If no users exist in the `users` table, the auth middleware is bypassed entirely. All API endpoints remain open. This preserves backward compatibility for existing deployments that haven't set up users yet.

When the first user is created (via `/setup-admin` or the CLI), auth enforcement begins immediately.

### First-Visit Registration

When no users exist:
- `GET /api/v1/auth/status` returns `{ has_users: false }`
- The frontend shows a registration page at `/setup-admin` instead of redirecting to `/login`
- `POST /api/v1/auth/setup-admin` creates the first admin user (only works when no users exist)
- After creation, the user is automatically logged in and redirected to the dashboard

## API Endpoints

### Public (no auth required)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Authenticate with email + password, returns JWT cookie |
| GET | `/api/v1/auth/status` | Returns `{ has_users: bool }` — frontend routing decision |
| POST | `/api/v1/auth/setup-admin` | Create first admin user (only when no users exist) |
| GET | `/healthz` | Health check (already exists) |

### Authenticated (any role)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/logout` | Clear JWT cookie |
| GET | `/api/v1/auth/me` | Current user profile (id, email, display_name, role) |
| PUT | `/api/v1/auth/me/password` | Change own password (requires current_password + new_password) |

### Admin only

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/auth/users` | List all users |
| POST | `/api/v1/auth/users` | Create new user (email, password, display_name, role) |
| PUT | `/api/v1/auth/users/{id}` | Update user (display_name, role) |
| DELETE | `/api/v1/auth/users/{id}` | Delete user (cannot delete self) |

### Request/Response Shapes

**POST /auth/login**

Request:
```json
{ "email": "admin@example.com", "password": "secret" }
```

Response (200):
```json
{ "user": { "id": "uuid", "email": "admin@example.com", "display_name": "Admin", "role": "admin" } }
```
Plus `Set-Cookie` header.

Response (401):
```json
{ "error": "invalid email or password" }
```

**POST /auth/setup-admin**

Request:
```json
{ "email": "admin@example.com", "password": "secret", "display_name": "Admin" }
```

Response (201): same as login response (auto-login).

Response (403):
```json
{ "error": "admin already exists" }
```

**GET /auth/me**

Response (200):
```json
{ "id": "uuid", "email": "admin@example.com", "display_name": "Admin", "role": "admin", "last_login_at": "2026-03-28T10:00:00Z" }
```

**PUT /auth/me/password**

Request:
```json
{ "current_password": "old", "new_password": "new" }
```

**POST /auth/users**

Request:
```json
{ "email": "analyst@example.com", "password": "secret", "display_name": "Analyst", "role": "viewer" }
```

**PUT /auth/users/{id}**

Request:
```json
{ "display_name": "New Name", "role": "admin" }
```

## JWT Details

- **Algorithm:** HS256 (HMAC-SHA256)
- **Secret:** Random 32-byte key generated on first startup, stored in the database (or config). For simplicity, derived from the PostgreSQL password hash — no additional secret management needed.
- **Payload:** `{ sub: user_id, email, role, iat, exp }`
- **Expiry:** 24 hours
- **Cookie name:** `cipherflag_token`
- **Cookie attributes:** `HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
- In production with HTTPS, add `Secure` flag

## Password Hashing

- **Algorithm:** bcrypt via `golang.org/x/crypto/bcrypt`
- **Cost factor:** 12 (default)
- **Minimum password length:** 8 characters
- Passwords are never logged or returned in API responses

## Auth Middleware

New middleware in the chi router chain, placed after CORS but before route handlers.

**Logic:**
1. Check if any users exist (cached — refreshed every 60 seconds)
2. If no users → skip auth, set a "no-auth" context flag
3. If users exist:
   a. Read `cipherflag_token` cookie
   b. Parse and validate JWT (signature, expiry)
   c. Extract user claims, set `UserContext` in request context
   d. If invalid/missing → return 401
4. Public routes are excluded from auth check

**Route protection:**
- Auth middleware applies to all `/api/v1/` routes except `/auth/login`, `/auth/status`, `/auth/setup-admin`
- Admin-only routes check `UserContext.Role == "admin"` in the handler

**UserContext type:**
```go
type UserContext struct {
    ID    string
    Email string
    Role  string // "admin" or "viewer"
}
```

Stored in request context via `context.WithValue`. Retrieved via `auth.GetUser(ctx)`.

## Frontend

### Auth State

`frontend/src/lib/auth.ts` — Svelte store holding current user state:

```typescript
interface AuthUser {
    id: string;
    email: string;
    display_name: string;
    role: 'admin' | 'viewer';
}

// Reactive store
let currentUser: AuthUser | null = $state(null);
let authChecked: boolean = $state(false);
```

### Layout Auth Check

`+layout.svelte` calls `GET /api/v1/auth/me` on mount:
- 200 → set `currentUser`, proceed
- 401 → check `GET /api/v1/auth/status`
  - `has_users: false` → redirect to `/setup-admin`
  - `has_users: true` → redirect to `/login`

### Login Page (`/login`)

Simple form: email, password, submit button. On success, redirect to `/` (or the original destination).

### Setup Admin Page (`/setup-admin`)

Registration form: email, password, confirm password, display name. Only accessible when no users exist. On success, auto-login and redirect to dashboard.

### Nav Bar Changes

When authenticated, show in the top bar:
- User email/name (right side)
- Role badge (Admin/Viewer)
- Logout button

When role is `admin`, show a gear icon linking to settings (Sub-project B).

## File Map

### Backend

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/store/migrations/005_auth.sql` | Create | Users table |
| `internal/model/user.go` | Create | User type, UserContext, login/create request types |
| `internal/auth/jwt.go` | Create | JWT sign, verify, cookie helpers |
| `internal/auth/password.go` | Create | Bcrypt hash, verify, validate |
| `internal/api/middleware/auth.go` | Create | Auth middleware |
| `internal/api/handler/auth.go` | Create | Login, logout, me, password, user CRUD |
| `internal/store/store.go` | Modify | Add user methods to CertStore interface |
| `internal/store/users.go` | Create | User query implementations |
| `internal/api/server.go` | Modify | Wire auth middleware, register auth routes |
| `go.mod` | Modify | Add `golang.org/x/crypto` |

### Frontend

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/src/lib/auth.ts` | Create | Auth state, API helpers |
| `frontend/src/routes/login/+page.svelte` | Create | Login form |
| `frontend/src/routes/setup-admin/+page.svelte` | Create | First admin registration |
| `frontend/src/routes/+layout.svelte` | Modify | Auth check on mount, user menu in nav |

## Dependencies

- `golang.org/x/crypto` — bcrypt password hashing
- No frontend dependencies needed

## Security Considerations

- JWT in HTTP-only cookie prevents XSS token theft
- `SameSite=Strict` prevents CSRF
- Bcrypt with cost 12 for password hashing
- No plaintext passwords in logs, responses, or error messages
- Admin cannot delete their own account
- Setup-admin endpoint is disabled once any user exists
- Rate limiting on login is deferred (can be added via middleware later)

## Out of Scope

- OAuth2/SSO/SAML (external identity provider integration)
- Multi-factor authentication
- Password reset via email
- API key authentication (for programmatic access)
- Rate limiting on login endpoint
- Session revocation (JWT is stateless — logout is client-side cookie clear)
- Settings UI (Sub-project B)
