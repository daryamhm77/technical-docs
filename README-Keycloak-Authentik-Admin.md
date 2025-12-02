# Keycloak & Authentik: Admin Panel, User Management, and Access Control Guide

This guide explains how to set up and manage admin panels, users, roles, and access control in Keycloak and Authentik.

## Table of Contents

1. [Keycloak Admin Panel](#keycloak-admin-panel)
2. [Authentik Admin Panel](#authentik-admin-panel)
3. [User Management](#user-management)
4. [Access Control & Permissions](#access-control--permissions)
5. [UI Handling for Restricted Access](#ui-handling-for-restricted-access)
6. [Database Storage](#database-storage)

---

## Keycloak Admin Panel

### Accessing Admin Console

1. **Start Keycloak Server:**
   ```bash
   docker run -d \
     --name keycloak \
     -p 8080:8080 \
     -e KEYCLOAK_ADMIN=admin \
     -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:latest \
     start-dev
   ```

2. **Access Admin Console:**
   - URL: `http://localhost:8080`
   - Click "Administration Console"
   - Login: `admin` / `admin` (default)

### Admin Panel Features

Keycloak Admin Console provides:

- **Realm Management:** Create and manage realms
- **User Management:** Create, edit, delete users
- **Role Management:** Define roles and permissions
- **Client Management:** Configure OAuth2/OIDC clients
- **Identity Providers:** Configure SSO providers
- **Authentication Flows:** Customize login flows
- **Themes:** Customize UI appearance
- **Events:** Monitor authentication events
- **Sessions:** View active user sessions

### Creating Admin User

#### Method 1: Using Default Admin (Development)

The default admin user is created automatically:
- Username: `admin`
- Password: `admin` (set via `KEYCLOAK_ADMIN_PASSWORD`)

#### Method 2: Creating Custom Admin User

1. Go to "Users" → "Add user"
2. Fill in:
   - Username: `superadmin`
   - Email: `admin@example.com`
   - First Name: `Super`
   - Last Name: `Admin`
3. Click "Create"
4. Go to "Credentials" tab → "Set password"
5. Set password and toggle "Temporary" to OFF
6. Go to "Role mapping" tab
7. Click "Assign role" → Filter by "realm-management"
8. Assign roles:
   - `realm-admin` (full realm administration)
   - `manage-users` (user management)
   - `view-users` (view users)
   - `manage-clients` (client management)
   - `view-clients` (view clients)

### Managing Access Control

#### Step 1: Create Roles

1. Go to "Realm roles" → "Create role"
2. Create roles:
   ```
   docs:all          (full documentation access)
   docs:flowcharts   (flowcharts only)
   docs:backend      (backend docs only)
   admin             (administrator)
   viewer            (read-only)
   ```

#### Step 2: Create Users

1. Go to "Users" → "Add user"
2. Fill user details:
   - Username: `john.doe`
   - Email: `john@example.com`
   - First Name: `John`
   - Last Name: `Doe`
3. Click "Create"
4. Set password in "Credentials" tab
5. Assign roles in "Role mapping" tab:
   - Click "Assign role"
   - Select `docs:flowcharts` → "Assign"

#### Step 3: Configure Client Scopes (Optional)

For fine-grained permissions:

1. Go to "Client scopes" → "Create"
2. Name: `docs-permissions`
3. Go to "Mappers" tab → "Add mapper" → "By configuration"
4. Select "User Realm Role" mapper
5. Configure:
   - Name: `docs-roles`
   - Token Claim Name: `docs_permissions`
   - Add to access token: ON
   - Add to ID token: ON

#### Step 4: Map Roles to Token

1. Go to "Clients" → Select your client
2. Go to "Client scopes" tab
3. Add `docs-permissions` to "Default Client Scopes"
4. Roles will now appear in JWT token as `docs_permissions` claim

---

## Authentik Admin Panel

### Accessing Admin Panel

1. **Start Authentik Server:**
   ```bash
   # Using Docker Compose
   curl -o docker-compose.yml https://raw.githubusercontent.com/goauthentik/authentik/version/2024.2.0/docker-compose.example.yml
   docker-compose up -d
   ```

2. **Get Admin Password:**
   ```bash
   docker-compose exec authentik authentik bootstrap
   # Note the password shown
   ```

3. **Access Admin Panel:**
   - URL: `http://localhost:9000/if/admin/`
   - Username: `akadmin`
   - Password: (from bootstrap command)

### Admin Panel Features

Authentik Admin Panel provides:

- **Applications:** Manage OAuth2/OIDC applications
- **Providers:** Configure authentication providers
- **Users:** User management
- **Groups:** Group management with permissions
- **Policies:** Access control policies
- **Flows:** Authentication and authorization flows
- **Sources:** User sources (LDAP, OAuth, etc.)
- **Events:** Audit logs
- **Core:** System settings

### Creating Admin User

#### Method 1: Using Bootstrap Admin

The bootstrap admin is created automatically:
- Username: `akadmin`
- Password: Generated during bootstrap

#### Method 2: Creating Custom Admin User

1. Go to "Directory" → "Users" → "Create"
2. Fill in:
   - Username: `superadmin`
   - Name: `Super Admin`
   - Email: `admin@example.com`
3. Click "Create"
4. Go to "Directory" → "Groups"
5. Create group: `admins`
6. Add user to `admins` group
7. Go to "Core" → "Groups" → Select `admins`
8. Assign permissions:
   - `authentik_core.view_user`
   - `authentik_core.add_user`
   - `authentik_core.change_user`
   - `authentik_core.delete_user`
   - `authentik_core.view_group`
   - `authentik_core.add_group`
   - `authentik_core.change_group`
   - `authentik_core.delete_group`

### Managing Access Control

#### Step 1: Create Groups

1. Go to "Directory" → "Groups" → "Create"
2. Create groups:
   ```
   docs-all          (full documentation access)
   docs-flowcharts   (flowcharts only)
   docs-backend      (backend docs only)
   admins            (administrators)
   viewers           (read-only)
   ```

#### Step 2: Create Users

1. Go to "Directory" → "Users" → "Create"
2. Fill user details:
   - Username: `john.doe`
   - Name: `John Doe`
   - Email: `john@example.com`
3. Click "Create"
4. Set password: Go to user → "Password" tab → "Set password"
5. Assign to group: Go to user → "Groups" tab → Add to `docs-flowcharts`

#### Step 3: Create Application with Policies

1. Go to "Applications" → "Applications" → "Create"
2. Fill in:
   - Name: `docs-app`
   - Slug: `docs-app`
3. Create Provider:
   - Go to "Applications" → "Providers" → "Create"
   - Type: "OAuth2/OpenID Provider"
   - Name: `docs-provider`
   - Client type: "Confidential"
   - Redirect URIs: `http://localhost:3001/*`
4. Create Policy:
   - Go to "Policies" → "Policies" → "Create"
   - Type: "Group membership"
   - Name: `docs-flowcharts-policy`
   - Group: `docs-flowcharts`
5. Bind Policy to Application:
   - Go to Application → "Policies" tab
   - Add `docs-flowcharts-policy`

---

## User Management

### Keycloak User Management

#### Creating Users

```bash
# Via Admin Console (UI)
1. Users → Add user
2. Fill details → Create
3. Set password in Credentials tab
4. Assign roles in Role mapping tab

# Via Admin REST API
curl -X POST http://localhost:8080/admin/realms/your-realm/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "enabled": true
  }'
```

#### Assigning Roles

1. Go to user → "Role mapping" tab
2. Click "Assign role"
3. Filter by realm or client
4. Select roles → "Assign"

#### Bulk User Import

1. Go to "Users" → "Import users"
2. Upload CSV file:
   ```csv
   username,email,firstName,lastName,enabled
   user1,user1@example.com,User,One,true
   user2,user2@example.com,User,Two,true
   ```

### Authentik User Management

#### Creating Users

```bash
# Via Admin Panel (UI)
1. Directory → Users → Create
2. Fill details → Create
3. Set password in Password tab
4. Add to groups in Groups tab

# Via API
curl -X POST http://localhost:9000/api/v3/core/users/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john@example.com",
    "name": "John Doe"
  }'
```

#### Assigning Groups

1. Go to user → "Groups" tab
2. Click "Add" → Select group → "Add"

#### Bulk User Import

1. Go to "Directory" → "Sources"
2. Create "CSV Source" or "LDAP Source"
3. Configure import settings
4. Run import

---

## Access Control & Permissions

### How Access Control Works

#### Keycloak Flow

```
User Request → Express Server → Keycloak Middleware
                                    ↓
                            Check Token
                                    ↓
                            Extract Roles/Permissions
                                    ↓
                            Check Route Permission
                                    ↓
                    ✅ Allowed → Serve Files
                    ❌ Denied → 403 Forbidden
```

#### Authentik Flow

```
User Request → Express Server → Authentik OIDC
                                    ↓
                            Check Token
                                    ↓
                            Extract Groups/Permissions
                                    ↓
                            Check Policy
                                    ↓
                    ✅ Allowed → Serve Files
                    ❌ Denied → 403 Forbidden
```

### Example: User Without Flowcharts Access

#### Scenario

User `john.doe` has:
- ✅ Role: `docs:flowcharts` (in Keycloak)
- ✅ Group: `docs-flowcharts` (in Authentik)
- ❌ No access to `/flowcharts/*` routes

#### Keycloak Implementation

**Express Server Code:**
```typescript
function checkKeycloakPermissions(req: Request, res: Response, next: NextFunction) {
  const token = (req as any).kauth?.grant?.access_token;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const roles = token.content?.realm_access?.roles || [];
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts');
  
  // Check permissions
  const canAccessAll = roles.includes('docs:all') || roles.includes('admin');
  const canAccessFlowcharts = roles.includes('docs:flowcharts') || roles.includes('viewer');
  
  if (isFlowcharts && !canAccessAll && !canAccessFlowcharts) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to flowcharts',
      required: 'docs:flowcharts or docs:all role',
    });
  }
  
  next();
}
```

**What Happens:**
1. User tries to access `/flowcharts/laser-detection`
2. Express extracts roles from Keycloak token
3. Checks if user has `docs:flowcharts` or `docs:all`
4. If not → Returns `403 Forbidden` with error message

#### Authentik Implementation

**Express Server Code:**
```typescript
function checkAuthentikPermissions(req: Request, res: Response, next: NextFunction) {
  const user = (req.session as any).user;
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const groups = user.groups || [];
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts');
  
  // Check permissions
  const canAccessAll = groups.includes('docs-all') || groups.includes('admins');
  const canAccessFlowcharts = groups.includes('docs-flowcharts') || groups.includes('viewers');
  
  if (isFlowcharts && !canAccessAll && !canAccessFlowcharts) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to flowcharts',
      required: 'docs-flowcharts or docs-all group',
    });
  }
  
  next();
}
```

---

## UI Handling for Restricted Access

### How UI Handles Restricted Access

#### Scenario: User Without Flowcharts Permission

When a user without `docs:flowcharts` permission tries to access `/flowcharts/*`:

#### 1. Server-Side Handling

**Express Response:**
```typescript
// Returns 403 Forbidden
{
  "error": "Forbidden - You do not have access to flowcharts",
  "required": "docs:flowcharts or docs:all role"
}
```

#### 2. Client-Side Handling (React/Docusaurus)

**Option A: Error Page**

Create `src/pages/403.tsx`:
```typescript
import React from 'react';
import Layout from '@theme/Layout';

export default function Forbidden() {
  return (
    <Layout title="Access Denied">
      <div style={{ padding: '2rem', textAlign: 'center' }}>
        <h1>403 - Access Denied</h1>
        <p>You do not have permission to access this page.</p>
        <p>Required permissions: <code>docs:flowcharts</code> or <code>docs:all</code></p>
        <a href="/">Go to Home</a>
      </div>
    </Layout>
  );
}
```

**Option B: Redirect to Login**

```typescript
// In Express middleware
if (!canAccessFlowcharts) {
  // Redirect to Keycloak login
  return res.redirect(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth?...`);
}
```

**Option C: Hide Restricted Content**

```typescript
// In React component
import { useKeycloak } from '@react-keycloak/web';

function FlowchartsPage() {
  const { keycloak } = useKeycloak();
  const roles = keycloak.tokenParsed?.realm_access?.roles || [];
  const canAccess = roles.includes('docs:flowcharts') || roles.includes('docs:all');
  
  if (!canAccess) {
    return (
      <div>
        <h1>Access Denied</h1>
        <p>You need the <code>docs:flowcharts</code> role to view this content.</p>
      </div>
    );
  }
  
  return <FlowchartsContent />;
}
```

#### 3. Keycloak UI Customization

**Custom Error Pages:**

1. Go to "Realm settings" → "Themes"
2. Create custom theme:
   ```bash
   # Create theme directory
   themes/my-theme/login/
   themes/my-theme/email/
   ```
3. Add custom error pages:
   - `403.ftl` - Forbidden page
   - `error.ftl` - General error page
4. Select theme in "Realm settings" → "Themes"

**Custom Error Messages:**

1. Go to "Realm settings" → "Localization"
2. Add custom messages:
   ```properties
   # messages_en.properties
   accessDenied=You do not have access to this resource
   requiredRole=Required role: {0}
   ```

#### 4. Authentik UI Customization

**Custom Flows:**

1. Go to "Flows" → "Flows"
2. Create custom flow:
   - Name: `docs-access-flow`
   - Stages: Add "Policy binding" stage
3. Configure policy:
   - Policy: `docs-flowcharts-policy`
   - If denied: Show error page

**Custom Error Pages:**

1. Go to "Flows" → "Stages"
2. Create "User login" stage
3. Configure error handling:
   - On access denied: Redirect to custom page
   - Error message: Custom message

---

## Database Storage

### Keycloak Database

#### Default Database (H2 - Development)

Keycloak uses H2 in-memory database by default (development mode):
- **Type:** H2 (in-memory)
- **Location:** Memory only (data lost on restart)
- **Use case:** Development/testing only

#### Production Database Setup

Keycloak supports multiple databases:

**PostgreSQL:**
```bash
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e DB_VENDOR=postgres \
  -e DB_ADDR=postgres \
  -e DB_DATABASE=keycloak \
  -e DB_USER=keycloak \
  -e DB_PASSWORD=password \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

**MySQL:**
```bash
-e DB_VENDOR=mysql \
-e DB_ADDR=mysql \
-e DB_DATABASE=keycloak \
-e DB_USER=keycloak \
-e DB_PASSWORD=password
```

**Database Schema:**

Keycloak stores:
- **Users:** `user_entity` table
- **Roles:** `keycloak_role` table
- **Clients:** `client` table
- **Sessions:** `client_session` table
- **Tokens:** `offline_user_session` table
- **Events:** `event_entity` table

**Viewing Database:**
```bash
# Connect to PostgreSQL
psql -h localhost -U keycloak -d keycloak

# List tables
\dt

# View users
SELECT username, email, enabled FROM user_entity;

# View roles
SELECT name FROM keycloak_role WHERE realm_id = 'your-realm-id';
```

### Authentik Database

#### Default Database (PostgreSQL)

Authentik uses PostgreSQL by default:
- **Type:** PostgreSQL
- **Container:** `authentik-db` (in Docker Compose)
- **Database:** `authentik`
- **User:** `authentik`
- **Password:** (set in `.env` or `docker-compose.yml`)

#### Database Configuration

**docker-compose.yml:**
```yaml
services:
  postgresql:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: ${PG_PASS:?database password required}
      POSTGRES_USER: authentik
      POSTGRES_DB: authentik
    volumes:
      - database:/var/lib/postgresql/data
```

**Database Schema:**

Authentik stores:
- **Users:** `authentik_core_user` table
- **Groups:** `authentik_core_group` table
- **Applications:** `authentik_providers_oauth2provider` table
- **Policies:** `authentik_policies_policybinding` table
- **Events:** `authentik_events_event` table
- **Sessions:** `authentik_core_usersession` table

**Viewing Database:**
```bash
# Connect to PostgreSQL
docker-compose exec postgresql psql -U authentik -d authentik

# List tables
\dt

# View users
SELECT username, email, is_active FROM authentik_core_user;

# View groups
SELECT name FROM authentik_core_group;
```

### Database Backup & Restore

#### Keycloak Backup

```bash
# Export realm
docker exec keycloak /opt/keycloak/bin/kc.sh export \
  --file /tmp/realm-export.json \
  --realm your-realm

# Backup database
pg_dump -h localhost -U keycloak keycloak > keycloak_backup.sql
```

#### Authentik Backup

```bash
# Backup database
docker-compose exec postgresql pg_dump -U authentik authentik > authentik_backup.sql

# Backup media files
docker-compose exec authentik tar -czf /tmp/authentik-media.tar.gz /media
```

#### Restore

```bash
# Keycloak
psql -h localhost -U keycloak keycloak < keycloak_backup.sql

# Authentik
docker-compose exec -T postgresql psql -U authentik authentik < authentik_backup.sql
```

---

## Summary

### Keycloak

- ✅ **Admin Panel:** `http://localhost:8080` - Full-featured admin console
- ✅ **User Management:** Via UI or REST API
- ✅ **Access Control:** Role-based (RBAC)
- ✅ **Database:** H2 (dev) or PostgreSQL/MySQL (prod)
- ✅ **UI Customization:** Themes and custom pages
- ✅ **Token Claims:** Roles included in JWT token

### Authentik

- ✅ **Admin Panel:** `http://localhost:9000/if/admin/` - Modern admin interface
- ✅ **User Management:** Via UI or REST API
- ✅ **Access Control:** Group and policy-based
- ✅ **Database:** PostgreSQL (default)
- ✅ **UI Customization:** Custom flows and stages
- ✅ **Token Claims:** Groups included in OIDC token

### Access Control Flow

1. **User Login:** Redirected to Keycloak/Authentik login page
2. **Authentication:** User credentials verified
3. **Token Issued:** JWT/OIDC token with roles/groups
4. **Request:** User accesses protected route
5. **Validation:** Express validates token and checks permissions
6. **Response:**
   - ✅ **Allowed:** Serve content
   - ❌ **Denied:** 403 Forbidden or redirect to error page

### Best Practices

1. **Use Production Database:** Never use H2 in production
2. **Regular Backups:** Schedule database backups
3. **Role Hierarchy:** Use role inheritance for better management
4. **Audit Logging:** Enable event logging for security
5. **Token Expiration:** Set reasonable token expiration times
6. **HTTPS:** Always use HTTPS in production
7. **Rate Limiting:** Implement rate limiting on Express server

---

## Additional Resources

- **Keycloak Documentation:** https://www.keycloak.org/documentation
- **Keycloak Admin REST API:** https://www.keycloak.org/docs-api/latest/rest-api/
- **Authentik Documentation:** https://goauthentik.io/docs/
- **Authentik API:** https://goauthentik.io/api/v3/

