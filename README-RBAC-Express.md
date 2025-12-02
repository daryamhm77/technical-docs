# RBAC Implementation with Express Wrapper

This guide explains how to implement Role-Based Access Control (RBAC) for Docusaurus documentation using a Node.js/Express wrapper server.

## Overview

Instead of running Docusaurus directly, we create an Express server that validates JWT tokens and permissions before serving static files from the `build/` directory. This approach is simpler than Nginx and keeps everything in Node.js.

## Architecture

```
User Request → Express Server → JWT Validation → Check Permissions → Serve Static Files (if allowed)
                                                      ↓
                                              403 Forbidden (if denied)
```

## Prerequisites

- Node.js 16+ installed
- Docusaurus project built (`npm run build`)
- NestJS backend with JWT authentication

## Recommended Open-Source Libraries

Here are the best open-source libraries for implementing RBAC with Express:

### 1. **express-jwt** ⭐ Recommended
- **Purpose:** JWT validation middleware for Express
- **Why:** Simplifies JWT token extraction and validation
- **GitHub:** [auth0/express-jwt](https://github.com/auth0/express-jwt)
- **Stars:** 2.5k+
- **Best for:** Simple JWT authentication

### 2. **CASL** ⭐⭐⭐ Best for Complex Permissions
- **Purpose:** Isomorphic authorization library
- **Why:** Powerful permission-based access control with great TypeScript support
- **GitHub:** [stalniy/casl](https://github.com/stalniy/casl)
- **Stars:** 5.5k+
- **Best for:** Complex permission rules, attribute-based access control

### 3. **AccessControl** ⭐⭐ Best for RBAC
- **Purpose:** Role and attribute based access control
- **Why:** Simple API for RBAC, supports role hierarchies
- **GitHub:** [onury/accesscontrol](https://github.com/onury/accesscontrol)
- **Stars:** 2.8k+
- **Best for:** Role-based access control with roles and resources
- **Install:** `npm install accesscontrol`

### 4. **helmet**
- **Purpose:** Security headers middleware
- **Why:** Sets various HTTP headers to help secure your app
- **GitHub:** [helmetjs/helmet](https://github.com/helmetjs/helmet)
- **Stars:** 10k+
- **Best for:** Security hardening

### 5. **express-rate-limit**
- **Purpose:** Rate limiting middleware
- **Why:** Prevents brute force attacks
- **GitHub:** [express-rate-limit/express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)
- **Stars:** 3.5k+
- **Best for:** Rate limiting and DDoS protection

### 6. **cookie-parser**
- **Purpose:** Parse HTTP cookies
- **Why:** Essential for cookie-based authentication
- **GitHub:** [expressjs/cookie-parser](https://github.com/expressjs/cookie-parser)
- **Stars:** 2.5k+
- **Best for:** Cookie-based token storage

### 7. **Keycloak** ⭐⭐⭐ Enterprise IAM Solution
- **Purpose:** Open-source Identity and Access Management (IAM)
- **Why:** Complete IAM solution with SSO, user federation, fine-grained authorization
- **GitHub:** [keycloak/keycloak](https://github.com/keycloak/keycloak)
- **Stars:** 20k+
- **Best for:** Enterprise applications, SSO, complex IAM requirements
- **Install:** `npm install keycloak-connect express-session`
- **Note:** Requires separate Keycloak server

### 8. **Casbin** ⭐⭐⭐ Powerful Authorization Engine
- **Purpose:** Authorization library supporting ACL, RBAC, ABAC models
- **Why:** Flexible policy engine, supports multiple access control models
- **GitHub:** [casbin/node-casbin](https://github.com/casbin/node-casbin)
- **Stars:** 16k+
- **Best for:** Complex authorization rules, policy-based access control
- **Install:** `npm install casbin`

### 9. **Authintick** ⭐ Lightweight Auth Library
- **Purpose:** Lightweight authentication and authorization library
- **Why:** Simple API for basic auth needs
- **GitHub:** [authintick/authintick](https://github.com/authintick/authintick)
- **Best for:** Simple authentication needs
- **Install:** `npm install authintick`

### 10. **Authentik** ⭐⭐⭐ Alternative to Keycloak
- **Purpose:** Open-source Identity Provider (alternative to Keycloak)
- **Why:** Modern UI, easy setup, good documentation
- **GitHub:** [goauthentik/authentik](https://github.com/goauthentik/authentik)
- **Stars:** 6k+
- **Best for:** Modern IAM solution, alternative to Keycloak
- **Install:** `npm install openid-client express-session`
- **Note:** Requires separate Authentik server (like Keycloak)
- **UI:** ✅ آماده دارد (نیازی به React نیست)

### Recommended Stack

For this documentation server, we recommend:

**Option A: Simple Setup (Recommended for most cases)**
- `express-jwt` - JWT validation
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `cookie-parser` - Cookie support

**Option B: Advanced Setup (For complex permission rules)**
- `express-jwt` - JWT validation
- `@casl/ability` - Permission engine
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `cookie-parser` - Cookie support

**Option C: RBAC with AccessControl (Simple RBAC)**
- `express-jwt` - JWT validation
- `accesscontrol` - RBAC library
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `cookie-parser` - Cookie support

**Option D: RBAC with easy-rbac (Hierarchical RBAC)**
- `express-jwt` - JWT validation
- `easy-rbac` - Hierarchical RBAC
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `cookie-parser` - Cookie support

**Option E: Keycloak Integration (Enterprise IAM)**
- `keycloak-connect` - Keycloak adapter
- `express-session` - Session management
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- **Note:** Requires separate Keycloak server

**Option F: Casbin Authorization (Policy-Based)**
- `express-jwt` - JWT validation (optional, can use Keycloak tokens)
- `casbin` - Authorization engine
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `cookie-parser` - Cookie support

**Option G: Authintick (Lightweight)**
- `authintick` - Authentication library
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting

**Option H: Authentik Integration (Modern IAM)**
- `openid-client` - OIDC client for Authentik
- `express-session` - Session management
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- **Note:** Requires separate Authentik server
- **UI:** ✅ آماده دارد (نیازی به React نیست)

## Setup Steps

### 1. Install Dependencies

**Option A: Simple Setup (Recommended)**
```bash
cd /var/www/docs/technical
npm install express express-jwt helmet express-rate-limit cookie-parser
npm install --save-dev @types/express @types/cookie-parser
```

**Option B: Advanced Setup (with CASL)**
```bash
cd /var/www/docs/technical
npm install express express-jwt @casl/ability @casl/express helmet express-rate-limit cookie-parser
npm install --save-dev @types/express @types/cookie-parser
```

**Option C: RBAC with AccessControl**
```bash
cd /var/www/docs/technical
npm install express express-jwt accesscontrol helmet express-rate-limit cookie-parser
npm install --save-dev @types/express @types/cookie-parser
```

**Option D: RBAC with easy-rbac**
```bash
cd /var/www/docs/technical
npm install express express-jwt easy-rbac helmet express-rate-limit cookie-parser
npm install --save-dev @types/express @types/cookie-parser
```

**Option E: Keycloak Integration**
```bash
cd /var/www/docs/technical
npm install express keycloak-connect express-session helmet express-rate-limit
npm install --save-dev @types/express @types/express-session
```

**Option F: Casbin Authorization**
```bash
cd /var/www/docs/technical
npm install express express-jwt casbin helmet express-rate-limit cookie-parser
npm install --save-dev @types/express @types/cookie-parser
```

**Option G: Authintick**
```bash
cd /var/www/docs/technical
npm install express authintick helmet express-rate-limit
npm install --save-dev @types/express
```

**Option H: Authentik Integration**
```bash
cd /var/www/docs/technical
npm install express openid-client express-session helmet express-rate-limit
npm install --save-dev @types/express @types/express-session
```

### 2. Create Express Server

Create a new file for the Express server using open-source libraries:

**File: `server.ts` (Option A: Simple Setup with express-jwt)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { expressjwt } from 'express-jwt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Use same secret as NestJS

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Disable if Docusaurus needs it
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Cookie parser
app.use(cookieParser());

// JWT authentication middleware
// express-jwt automatically extracts token from Authorization header or cookie
const jwtMiddleware = expressjwt({
  secret: JWT_SECRET,
  algorithms: ['HS256'],
  requestProperty: 'auth', // Attach payload to req.auth
  getToken: (req: Request) => {
    // Check Authorization header first
    if (req.headers.authorization?.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    }
    // Fallback to cookie
    return req.cookies?.token || null;
  },
});

// Permission check middleware
function checkPermissions(req: Request, res: Response, next: NextFunction) {
  const permissions: string[] = req.auth?.permissions || [];
  const urlPath = req.path;

  const canAccessAll = permissions.includes('docs:all');
  const canAccessFlowcharts =
    permissions.includes('docs:flowcharts') &&
    (urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts'));

  if (!canAccessAll && !canAccessFlowcharts) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to this resource',
      required: 'docs:all or docs:flowcharts',
    });
  }

  next();
}

// Apply JWT and permission middleware
app.use(jwtMiddleware);
app.use(checkPermissions);

// Serve static files from build directory
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing (fallback to index.html for client-side routes)
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Error handling middleware
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with RBAC running on http://localhost:${PORT}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Set' : 'NOT SET (using default)'}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
});
```

**File: `server-casl.ts` (Option B: Advanced Setup with CASL)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { expressjwt } from 'express-jwt';
import { defineAbility } from '@casl/ability';
import { abilitiesPlugin } from '@casl/express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Cookie parser
app.use(cookieParser());

// JWT authentication
const jwtMiddleware = expressjwt({
  secret: JWT_SECRET,
  algorithms: ['HS256'],
  requestProperty: 'auth',
  getToken: (req: Request) => {
    if (req.headers.authorization?.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    }
    return req.cookies?.token || null;
  },
});

// CASL ability factory
function defineAbilityFor(user: any) {
  const permissions: string[] = user?.permissions || [];
  
  return defineAbility((can) => {
    if (permissions.includes('docs:all')) {
      can('read', 'all');
    }
    if (permissions.includes('docs:flowcharts')) {
      can('read', 'flowcharts');
    }
  });
}

// CASL permission middleware
const caslMiddleware = abilitiesPlugin(defineAbilityFor);

// Apply middleware
app.use(jwtMiddleware);
app.use(caslMiddleware);

// Permission check using CASL
function checkCaslPermissions(req: Request, res: Response, next: NextFunction) {
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  
  // Check if user can read all or specific resource
  if (req.ability.can('read', 'all')) {
    return next();
  }
  
  if (isFlowcharts && req.ability.can('read', 'flowcharts')) {
    return next();
  }
  
  return res.status(403).json({
    error: 'Forbidden - You do not have access to this resource',
    required: 'docs:all or docs:flowcharts',
  });
}

app.use(checkCaslPermissions);

// Serve static files
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with RBAC (CASL) running on http://localhost:${PORT}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Set' : 'NOT SET (using default)'}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
  console.log(`🎯 Authorization: CASL enabled`);
});
```

**File: `server-accesscontrol.ts` (Option C: RBAC with AccessControl)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { expressjwt } from 'express-jwt';
import { AccessControl } from 'accesscontrol';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Cookie parser
app.use(cookieParser());

// JWT authentication
const jwtMiddleware = expressjwt({
  secret: JWT_SECRET,
  algorithms: ['HS256'],
  requestProperty: 'auth',
  getToken: (req: Request) => {
    if (req.headers.authorization?.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    }
    return req.cookies?.token || null;
  },
});

// Define AccessControl grants
const ac = new AccessControl();

// Grant permissions based on roles
ac.grant('viewer')
  .read('flowcharts');

ac.grant('admin')
  .extend('viewer')
  .read('all');

// Permission check middleware using AccessControl
function checkAccessControlPermissions(req: Request, res: Response, next: NextFunction) {
  const permissions: string[] = req.auth?.permissions || [];
  const urlPath = req.path;
  
  // Determine user role from permissions
  let userRole = 'guest';
  if (permissions.includes('docs:all')) {
    userRole = 'admin';
  } else if (permissions.includes('docs:flowcharts')) {
    userRole = 'viewer';
  }
  
  // Check resource type
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  const resource = isFlowcharts ? 'flowcharts' : 'all';
  
  // Check permission
  const permission = ac.can(userRole).read(resource);
  
  if (!permission.granted) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to this resource',
      required: 'docs:all or docs:flowcharts',
    });
  }
  
  next();
}

// Apply middleware
app.use(jwtMiddleware);
app.use(checkAccessControlPermissions);

// Serve static files
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with RBAC (AccessControl) running on http://localhost:${PORT}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Set' : 'NOT SET (using default)'}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
  console.log(`🎯 Authorization: AccessControl enabled`);
});
```

**File: `server-easy-rbac.ts` (Option D: RBAC with easy-rbac)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { expressjwt } from 'express-jwt';
import RBAC from 'easy-rbac';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Cookie parser
app.use(cookieParser());

// JWT authentication
const jwtMiddleware = expressjwt({
  secret: JWT_SECRET,
  algorithms: ['HS256'],
  requestProperty: 'auth',
  getToken: (req: Request) => {
    if (req.headers.authorization?.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    }
    return req.cookies?.token || null;
  },
});

// Define easy-rbac roles and permissions
const rbac = RBAC.create({
  admin: {
    can: ['docs:all', 'docs:flowcharts'],
    inherits: ['viewer'],
  },
  viewer: {
    can: ['docs:flowcharts'],
  },
});

// Permission check middleware using easy-rbac
async function checkEasyRbacPermissions(req: Request, res: Response, next: NextFunction) {
  const permissions: string[] = req.auth?.permissions || [];
  const urlPath = req.path;
  
  // Determine user role from permissions
  let userRole = 'guest';
  if (permissions.includes('docs:all')) {
    userRole = 'admin';
  } else if (permissions.includes('docs:flowcharts')) {
    userRole = 'viewer';
  }
  
  // Check resource type
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  const requiredPermission = isFlowcharts ? 'docs:flowcharts' : 'docs:all';
  
  try {
    // Check permission using easy-rbac
    const canAccess = await rbac.can(userRole, requiredPermission);
    
    if (!canAccess) {
      return res.status(403).json({
        error: 'Forbidden - You do not have access to this resource',
        required: 'docs:all or docs:flowcharts',
      });
    }
    
    next();
  } catch (error) {
    console.error('RBAC error:', error);
    return res.status(403).json({
      error: 'Forbidden - Permission check failed',
    });
  }
}

// Apply middleware
app.use(jwtMiddleware);
app.use(checkEasyRbacPermissions);

// Serve static files
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with RBAC (easy-rbac) running on http://localhost:${PORT}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Set' : 'NOT SET (using default)'}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
  console.log(`🎯 Authorization: easy-rbac enabled`);
});
```

**File: `server-keycloak.ts` (Option E: Keycloak Integration)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import session from 'express-session';
import Keycloak from 'keycloak-connect';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Session configuration
const memoryStore = new session.MemoryStore();
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: true,
  store: memoryStore,
}));

// Keycloak configuration
// Create keycloak.json file in project root with your Keycloak server settings
// Or configure programmatically:
const keycloakConfig = {
  'realm': process.env.KEYCLOAK_REALM || 'your-realm',
  'auth-server-url': process.env.KEYCLOAK_URL || 'http://localhost:8080',
  'ssl-required': 'external',
  'resource': process.env.KEYCLOAK_CLIENT_ID || 'your-client-id',
  'public-client': true,
  'confidential-port': 0,
};

const keycloak = new Keycloak({ store: memoryStore }, keycloakConfig);

// Keycloak middleware
app.use(keycloak.middleware());

// Permission check middleware
function checkKeycloakPermissions(req: Request, res: Response, next: NextFunction) {
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  
  // Check if user has required role/permission
  // Keycloak provides req.kauth.grant.access_token.content
  const token = (req as any).kauth?.grant?.access_token;
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - No token' });
  }
  
  const permissions = token.content?.realm_access?.roles || [];
  const canAccessAll = permissions.includes('docs:all') || permissions.includes('admin');
  const canAccessFlowcharts = permissions.includes('docs:flowcharts') || permissions.includes('viewer');
  
  if (!canAccessAll && (!canAccessFlowcharts || !isFlowcharts)) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to this resource',
      required: 'docs:all or docs:flowcharts role',
    });
  }
  
  next();
}

// Protect all routes with Keycloak
app.use(keycloak.protect());
app.use(checkKeycloakPermissions);

// Serve static files
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with Keycloak running on http://localhost:${PORT}`);
  console.log(`🔐 Keycloak URL: ${keycloakConfig['auth-server-url']}`);
  console.log(`🏛️  Realm: ${keycloakConfig.realm}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
});
```

**Keycloak Setup Instructions:**

1. **Install Keycloak Server:**
   ```bash
   # Using Docker (recommended)
   docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
   ```

2. **Access Admin Console:**
   - Open `http://localhost:8080`
   - Login with admin credentials

3. **Create Realm:**
   - Go to "Create Realm"
   - Name it (e.g., "docs-realm")

4. **Create Client:**
   - Go to "Clients" → "Create client"
   - Client ID: `your-client-id`
   - Client authentication: OFF (public client)
   - Valid redirect URIs: `http://localhost:3001/*`

5. **Create Roles:**
   - Go to "Realm roles" → "Create role"
   - Create roles: `docs:all`, `docs:flowcharts`, `admin`, `viewer`

6. **Create Users and Assign Roles:**
   - Go to "Users" → "Add user"
   - Set password in "Credentials" tab
   - Assign roles in "Role mapping" tab

**File: `server-casbin.ts` (Option F: Casbin Authorization)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { expressjwt } from 'express-jwt';
import { newEnforcer } from 'casbin';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Cookie parser
app.use(cookieParser());

// JWT authentication
const jwtMiddleware = expressjwt({
  secret: JWT_SECRET,
  algorithms: ['HS256'],
  requestProperty: 'auth',
  getToken: (req: Request) => {
    if (req.headers.authorization?.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    }
    return req.cookies?.token || null;
  },
});

// Initialize Casbin enforcer
let enforcer: any = null;

async function initCasbin() {
  // Create model.conf file in project root
  const model = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
  `;

  // Create policy.csv file in project root
  const policy = `
p, admin, all, read
p, viewer, flowcharts, read
g, docs:all, admin
g, docs:flowcharts, viewer
  `;

  // For file-based storage (create these files in your project)
  // enforcer = await newEnforcer('model.conf', 'policy.csv');
  
  // For in-memory storage (for this example)
  const { newModel, newAdapter } = require('casbin');
  const modelInstance = newModel();
  modelInstance.loadModelFromText(model);
  
  // Simple in-memory adapter
  const adapter = {
    loadPolicy: async (model: any) => {
      const lines = policy.trim().split('\n').filter(line => line.trim());
      for (const line of lines) {
        const parts = line.split(',').map(p => p.trim());
        if (parts[0] === 'p') {
          model.addPolicy('p', 'p', parts.slice(1));
        } else if (parts[0] === 'g') {
          model.addPolicy('g', 'g', parts.slice(1));
        }
      }
    },
    savePolicy: async () => {},
    addPolicy: async () => {},
    removePolicy: async () => {},
    removeFilteredPolicy: async () => {},
  };
  
  enforcer = await newEnforcer(modelInstance, adapter);
  await enforcer.loadPolicy();
  
  console.log('✅ Casbin enforcer initialized');
}

// Permission check middleware using Casbin
async function checkCasbinPermissions(req: Request, res: Response, next: NextFunction) {
  if (!enforcer) {
    return res.status(500).json({ error: 'Casbin not initialized' });
  }
  
  const permissions: string[] = req.auth?.permissions || [];
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  
  // Determine user role from permissions
  let userRole = 'guest';
  if (permissions.includes('docs:all')) {
    userRole = 'admin';
  } else if (permissions.includes('docs:flowcharts')) {
    userRole = 'viewer';
  }
  
  // Check resource
  const resource = isFlowcharts ? 'flowcharts' : 'all';
  const action = 'read';
  
  try {
    // Check permission using Casbin
    const allowed = await enforcer.enforce(userRole, resource, action);
    
    if (!allowed) {
      return res.status(403).json({
        error: 'Forbidden - You do not have access to this resource',
        required: 'docs:all or docs:flowcharts',
      });
    }
    
    next();
  } catch (error) {
    console.error('Casbin error:', error);
    return res.status(500).json({ error: 'Permission check failed' });
  }
}

// Initialize Casbin and start server
initCasbin().then(() => {
  // Apply middleware
  app.use(jwtMiddleware);
  app.use(checkCasbinPermissions);
  
  // Serve static files
  app.use(express.static(BUILD_DIR, {
    index: 'index.html',
    extensions: ['html'],
  }));
  
  // Handle SPA routing
  app.get('*', (req: Request, res: Response) => {
    res.sendFile(path.join(BUILD_DIR, 'index.html'));
  });
  
  // Error handling
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.name === 'UnauthorizedError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
  });
  
  app.listen(PORT, () => {
    console.log(`📚 Documentation server with Casbin running on http://localhost:${PORT}`);
    console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Set' : 'NOT SET (using default)'}`);
    console.log(`🛡️  Security: Helmet enabled`);
    console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
    console.log(`🎯 Authorization: Casbin enabled`);
  });
});
```

**Casbin Configuration Files:**

Create `model.conf` in project root:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

Create `policy.csv` in project root:
```csv
p, admin, all, read
p, viewer, flowcharts, read
g, docs:all, admin
g, docs:flowcharts, viewer
```

**File: `server-authintick.ts` (Option G: Authintick)**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import Authintick from 'authintick';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Initialize Authintick
const auth = new Authintick({
  secret: process.env.AUTHINTICK_SECRET || 'your-secret-key',
  // Additional configuration
  tokenExpiration: '24h',
});

// Permission check middleware
function checkAuthintickPermissions(req: Request, res: Response, next: NextFunction) {
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  
  // Get user from request (set by Authintick middleware)
  const user = (req as any).user;
  
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const permissions = user.permissions || [];
  const canAccessAll = permissions.includes('docs:all');
  const canAccessFlowcharts = permissions.includes('docs:flowcharts');
  
  if (!canAccessAll && (!canAccessFlowcharts || !isFlowcharts)) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to this resource',
      required: 'docs:all or docs:flowcharts',
    });
  }
  
  next();
}

// Apply Authintick authentication middleware
// Note: Authintick API may vary, adjust based on actual library documentation
app.use(auth.authenticate());
app.use(checkAuthintickPermissions);

// Serve static files
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with Authintick running on http://localhost:${PORT}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 100 requests per 15 minutes`);
  console.log(`🎯 Authorization: Authintick enabled`);
});
```

**Note:** Authintick API may vary. Check the [official documentation](https://github.com/authintick/authintick) for the exact API.

### 3. Create Environment File

**File: `.env`**

```env
PORT=3001
JWT_SECRET=your-actual-jwt-secret-from-nestjs
NODE_ENV=production

# For Keycloak (Option E)
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client-id
SESSION_SECRET=your-session-secret

# For Authintick (Option G)
AUTHINTICK_SECRET=your-authintick-secret

# For Authentik (Option H)
AUTHENTIK_URL=http://localhost:9000
AUTHENTIK_CLIENT_ID=your-client-id
AUTHENTIK_CLIENT_SECRET=your-client-secret
SESSION_SECRET=your-session-secret
```

**Important:** 
- Use the same `JWT_SECRET` as your NestJS backend (for Options A-D, F)
- Configure Keycloak settings if using Option E
- Set AUTHINTICK_SECRET if using Option G
- Configure Authentik settings if using Option H

### 4. Update package.json

Add a script to run the server:

**File: `package.json`**

```json
{
  "scripts": {
    "start": "docusaurus start",
    "build": "docusaurus build",
    "serve": "docusaurus serve",
    "serve:rbac": "ts-node server.ts",
    "serve:rbac:prod": "node dist/server.js",
    "serve:rbac:casl": "ts-node server-casl.ts",
    "serve:rbac:casl:prod": "node dist/server-casl.js",
    "serve:rbac:ac": "ts-node server-accesscontrol.ts",
    "serve:rbac:ac:prod": "node dist/server-accesscontrol.js",
    "serve:rbac:easy": "ts-node server-easy-rbac.ts",
    "serve:rbac:easy:prod": "node dist/server-easy-rbac.js",
    "serve:rbac:keycloak": "ts-node server-keycloak.ts",
    "serve:rbac:keycloak:prod": "node dist/server-keycloak.js",
    "serve:rbac:casbin": "ts-node server-casbin.ts",
    "serve:rbac:casbin:prod": "node dist/server-casbin.js",
    "serve:rbac:authintick": "ts-node server-authintick.ts",
    "serve:rbac:authintick:prod": "node dist/server-authintick.js",
    "serve:rbac:authentik": "ts-node server-authentik.ts",
    "serve:rbac:authentik:prod": "node dist/server-authentik.js"
  }
}
```

If using TypeScript, you'll need to compile it first or use `ts-node`:

```bash
npm install --save-dev ts-node typescript @types/node
```

### 5. Build Docusaurus

```bash
npm run build
```

This creates the `build/` directory with static files.

### 6. Run the Server

**Development (with ts-node):**
```bash
npm run serve:rbac
```

**Production (compiled):**
```bash
# Compile TypeScript first
npx tsc server.ts --outDir dist --esModuleInterop --resolveJsonModule

# Run compiled version
npm run serve:rbac:prod
```

**With PM2:**
```bash
# For Option A (simple setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:prod

# For Option B (CASL setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:casl:prod

# For Option C (AccessControl setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:ac:prod

# For Option D (easy-rbac setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:easy:prod

# For Option E (Keycloak setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:keycloak:prod

# For Option F (Casbin setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:casbin:prod

# For Option G (Authintick setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:authintick:prod

# For Option H (Authentik setup)
pm2 start npm --name "technical-docs" -- run serve:rbac:authentik:prod

pm2 save
```

## Usage

### 1. Get JWT Token from NestJS

First, authenticate with your NestJS backend to get a JWT token:

```bash
curl -X POST http://your-nestjs-backend/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'
```

Response should include a token:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "123",
    "permissions": ["docs:flowcharts"]
  }
}
```

### 2. Access Documentation

**With curl:**
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://18.199.29.228:3001/
```

**In Browser:**
You'll need to implement a login page or use a browser extension to add the token to requests. Alternatively, store the token in a cookie (requires cookie-parser middleware).

### 3. Permission Examples

- **User with `docs:all`:** Can access all documentation pages
- **User with `docs:flowcharts`:** Can only access `/flowcharts/*` pages
- **User without permissions:** Gets `403 Forbidden`

## Library Comparison

| Library | Use Case | Complexity | Best For | Stars | TypeScript |
|---------|----------|------------|----------|-------|------------|
| **express-jwt** | JWT validation | Low | Simple JWT authentication | 2.5k+ | ✅ |
| **CASL** | Permission engine | Medium | Complex permission rules, ABAC | 5.5k+ | ✅ |
| **AccessControl** | RBAC | Low | Role-based access control, role hierarchies | 2.8k+ | ✅ |
| **easy-rbac** | Hierarchical RBAC | Low | Simple hierarchical RBAC | 200+ | ✅ |
| **Keycloak** | Enterprise IAM | High | SSO, user federation, enterprise features | 20k+ | ✅ |
| **Authentik** | Modern IAM | High | Modern alternative to Keycloak, easy setup | 6k+ | ✅ |
| **Casbin** | Authorization engine | Medium | Policy-based access control, multiple models | 16k+ | ✅ |
| **Authintick** | Lightweight auth | Low | Simple authentication | - | ⚠️ |
| **helmet** | Security headers | Low | Security hardening | 10k+ | ✅ |
| **express-rate-limit** | Rate limiting | Low | DDoS protection | 3.5k+ | ✅ |

### Choosing the Right Library

- **express-jwt**: Use for JWT validation (required for all options)
- **CASL**: Best for complex permission rules, attribute-based access control (ABAC), and when you need fine-grained permissions
- **AccessControl**: Best for simple RBAC with role hierarchies, clean API, good TypeScript support
- **easy-rbac**: Best for hierarchical RBAC with simple configuration, promise-based API
- **Simple Setup (Option A)**: Use when you have basic permission checks (recommended for most cases)
- **CASL (Option B)**: Use when you need complex permission rules or ABAC
- **AccessControl (Option C)**: Use when you want clean RBAC with role hierarchies
- **easy-rbac (Option D)**: Use when you prefer hierarchical RBAC with simple async API
- **Keycloak (Option E)**: Use for enterprise applications requiring SSO, user federation, and comprehensive IAM features. Requires separate Keycloak server. **✅ UI آماده دارد - نیازی به React نیست**
- **Authentik (Option H)**: Modern alternative to Keycloak with easier setup. **✅ UI آماده دارد - نیازی به React نیست**
- **Casbin (Option F)**: Use when you need flexible policy-based authorization with support for ACL, RBAC, ABAC models. Great for complex authorization rules.
- **Authintick (Option G)**: Use for lightweight authentication needs. Check official documentation for latest API.

## Complete Implementation Guides

### Keycloak Full Setup Guide

#### Step 1: Install and Run Keycloak Server

**Using Docker (Recommended):**
```bash
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

**Using Standalone:**
1. Download from [keycloak.org/downloads](https://www.keycloak.org/downloads)
2. Extract and run: `bin/kc.sh start-dev` (Linux/Mac) or `bin/kc.bat start-dev` (Windows)

#### Step 2: Access Admin Console

1. Open `http://localhost:8080`
2. Click "Administration Console"
3. Login with `admin` / `admin`

#### Step 3: Create Realm

1. Hover over "Master" realm → Click "Create Realm"
2. Name: `docs-realm`
3. Click "Create"

#### Step 4: Create Client

1. Go to "Clients" → "Create client"
2. Client type: `OpenID Connect`
3. Client ID: `docs-client`
4. Click "Next"
5. Client authentication: `OFF` (public client)
6. Valid redirect URIs: `http://localhost:3001/*`
7. Web origins: `http://localhost:3001`
8. Click "Save"

#### Step 5: Create Roles

1. Go to "Realm roles" → "Create role"
2. Create roles:
   - `docs:all` (for admin access)
   - `docs:flowcharts` (for viewer access)
   - `admin` (optional, for compatibility)
   - `viewer` (optional, for compatibility)

#### Step 6: Create Users

1. Go to "Users" → "Add user"
2. Username: `testuser`
3. Email: `test@example.com`
4. Click "Create"
5. Go to "Credentials" tab → Set password → "Set password"
6. Go to "Role mapping" tab → "Assign role" → Select `docs:flowcharts` → "Assign"

#### Step 7: Configure Express Server

Update `.env`:
```env
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=docs-realm
KEYCLOAK_CLIENT_ID=docs-client
SESSION_SECRET=your-random-session-secret-here
```

#### Step 8: Test Keycloak Integration

```bash
# Start Keycloak server (if not running)
docker start keycloak

# Start Express server
npm run serve:rbac:keycloak

# Access documentation (will redirect to Keycloak login)
curl -L http://localhost:3001/
```

#### Step 9: UI آماده Keycloak (نیازی به React نیست!)

**✅ Keycloak خودش UI آماده دارد:**

- **صفحه لاگین:** Keycloak خودش صفحه لاگین زیبا و قابل سفارشی‌سازی دارد
- **صفحه ثبت‌نام:** صفحه ثبت‌نام کاربر جدید
- **صفحه فراموشی رمز:** بازیابی رمز عبور
- **صفحه تنظیمات حساب:** مدیریت پروفایل کاربر
- **Admin Console:** پنل مدیریت کامل

**نحوه کار:**
1. کاربر به `http://localhost:3001/` می‌رود
2. Express server تشخیص می‌دهد که کاربر لاگین نیست
3. کاربر به صفحه لاگین Keycloak هدایت می‌شود (`http://localhost:8080/realms/docs-realm/protocol/openid-connect/auth`)
4. بعد از لاگین موفق، Keycloak کاربر را به `http://localhost:3001/` برمی‌گرداند با token
5. Express server token را validate می‌کند و فایل‌ها را serve می‌کند

**سفارشی‌سازی UI Keycloak:**

می‌توانید تم و استایل صفحه لاگین Keycloak را تغییر دهید:
1. در Admin Console → "Realm settings" → "Themes"
2. می‌توانید تم‌های سفارشی اضافه کنید
3. یا از تم‌های آماده استفاده کنید

**نتیجه:** **نیازی به ساخت React app برای لاگین نیست!** Keycloak همه چیز را آماده دارد.

### Authentik Full Setup Guide

**Authentik** نیز یک راه‌حل IAM متن‌باز مشابه Keycloak است که UI آماده دارد.

#### Step 1: Install and Run Authentik

**Using Docker Compose (Recommended):**
```bash
# Download docker-compose.yml from Authentik GitHub
curl -o docker-compose.yml https://raw.githubusercontent.com/goauthentik/authentik/version/2024.2.0/docker-compose.example.yml

# Start Authentik
docker-compose up -d
```

**Access Authentik:**
- Admin Panel: `http://localhost:9000/if/admin/`
- Default credentials: `akadmin` / (check logs for password)

#### Step 2: Create Application

1. Go to "Applications" → "Applications"
2. Click "Create"
3. Name: `docs-app`
4. Provider: Create new OAuth2/OpenID Provider
5. Redirect URIs: `http://localhost:3001/*`
6. Click "Create"

#### Step 3: Create Users and Groups

1. Go to "Directory" → "Users"
2. Create users and assign to groups
3. Create groups with permissions (e.g., `docs:all`, `docs:flowcharts`)

#### Step 4: Configure Express Server

**File: `server-authentik.ts`**

```typescript
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Issuer, Strategy } from 'openid-client';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: true,
}));

// Authentik OIDC configuration
const AUTHENTIK_URL = process.env.AUTHENTIK_URL || 'http://localhost:9000';
const CLIENT_ID = process.env.AUTHENTIK_CLIENT_ID || 'your-client-id';
const CLIENT_SECRET = process.env.AUTHENTIK_CLIENT_SECRET || 'your-client-secret';

// Initialize OIDC client
let client: any = null;

async function initAuthentik() {
  const issuer = await Issuer.discover(`${AUTHENTIK_URL}/application/o/docs-app/`);
  client = new issuer.Client({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uris: [`http://localhost:${PORT}/callback`],
    response_types: ['code'],
  });
  console.log('✅ Authentik OIDC client initialized');
}

// Authentication middleware
async function authenticate(req: Request, res: Response, next: NextFunction) {
  if (!client) {
    await initAuthentik();
  }
  
  if ((req.session as any).user) {
    return next();
  }
  
  // Redirect to Authentik login
  const authUrl = client.authorizationUrl({
    redirect_uri: `http://localhost:${PORT}/callback`,
    scope: 'openid profile email',
  });
  
  res.redirect(authUrl);
}

// Callback handler
app.get('/callback', async (req: Request, res: Response) => {
  const params = client.callbackParams(req.url);
  const tokenSet = await client.callback(`http://localhost:${PORT}/callback`, params);
  const userInfo = await client.userinfo(tokenSet.access_token!);
  
  (req.session as any).user = userInfo;
  res.redirect('/');
});

// Permission check
function checkAuthentikPermissions(req: Request, res: Response, next: NextFunction) {
  const user = (req.session as any).user;
  if (!user) {
    return authenticate(req, res, next);
  }
  
  const urlPath = req.path;
  const isFlowcharts = urlPath.startsWith('/flowcharts') || urlPath.includes('/flowcharts');
  
  // Extract permissions from user groups or claims
  const groups = user.groups || [];
  const canAccessAll = groups.includes('docs:all') || groups.includes('admin');
  const canAccessFlowcharts = groups.includes('docs:flowcharts') || groups.includes('viewer');
  
  if (!canAccessAll && (!canAccessFlowcharts || !isFlowcharts)) {
    return res.status(403).json({
      error: 'Forbidden - You do not have access to this resource',
    });
  }
  
  next();
}

// Apply middleware
app.use(authenticate);
app.use(checkAuthentikPermissions);

// Serve static files
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(BUILD_DIR, 'index.html'));
});

// Initialize and start
initAuthentik().then(() => {
  app.listen(PORT, () => {
    console.log(`📚 Documentation server with Authentik running on http://localhost:${PORT}`);
    console.log(`🔐 Authentik URL: ${AUTHENTIK_URL}`);
    console.log(`🛡️  Security: Helmet enabled`);
  });
});
```

**Install dependencies:**
```bash
npm install openid-client express-session
npm install --save-dev @types/express-session
```

**✅ Authentik هم UI آماده دارد:**
- صفحه لاگین
- صفحه ثبت‌نام
- Admin Panel
- **نیازی به React نیست!**

### مقایسه: Keycloak vs Authentik

| ویژگی | Keycloak | Authentik |
|-------|----------|----------|
| **UI آماده** | ✅ دارد | ✅ دارد |
| **نیاز به React** | ❌ ندارد | ❌ ندارد |
| **سفارشی‌سازی UI** | ✅ آسان | ✅ آسان |
| **Admin Panel** | ✅ کامل | ✅ کامل |
| **SSO** | ✅ پشتیبانی می‌کند | ✅ پشتیبانی می‌کند |
| **Documentation** | ✅ عالی | ✅ خوب |

### استفاده از React (اختیاری)

اگر می‌خواهید در React app خود از Keycloak/Authentik استفاده کنید (نه برای Express server):

**برای Keycloak:**
```bash
npm install keycloak-js @react-keycloak/web
```

**برای Authentik:**
```bash
npm install oidc-client react-oidc-context
```

اما برای Express server که فایل‌های static را serve می‌کند، **نیازی به React نیست** - Keycloak/Authentik خودشان UI دارند!

### Casbin Full Setup Guide

#### Step 1: Create Model Configuration

Create `model.conf` in project root:

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**Explanation:**
- `r = sub, obj, act`: Request format (subject, object, action)
- `p = sub, obj, act`: Policy format
- `g = _, _`: Role definition (user, role)
- `e = some(where (p.eft == allow))`: Policy effect (allow if any policy matches)
- `m = ...`: Matcher (check if user role matches policy)

#### Step 2: Create Policy File

Create `policy.csv` in project root:

```csv
p, admin, all, read
p, viewer, flowcharts, read
g, docs:all, admin
g, docs:flowcharts, viewer
```

**Explanation:**
- `p, admin, all, read`: Policy - admin can read all
- `p, viewer, flowcharts, read`: Policy - viewer can read flowcharts
- `g, docs:all, admin`: Role mapping - permission `docs:all` maps to role `admin`
- `g, docs:flowcharts, viewer`: Role mapping - permission `docs:flowcharts` maps to role `viewer`

#### Step 3: Using Database Adapter (Optional)

For production, use database adapter instead of CSV:

```bash
npm install casbin-typeorm-adapter typeorm
```

Update `server-casbin.ts`:
```typescript
import { TypeORMAdapter } from 'casbin-typeorm-adapter';

const adapter = await TypeORMAdapter.newAdapter({
  type: 'postgres', // or 'mysql', 'sqlite', etc.
  host: 'localhost',
  port: 5432,
  username: 'user',
  password: 'password',
  database: 'casbin',
});

const enforcer = await newEnforcer('model.conf', adapter);
```

#### Step 4: Dynamic Policy Management

Add API endpoints to manage policies:

```typescript
// Add policy
await enforcer.addPolicy('admin', 'new-resource', 'read');

// Remove policy
await enforcer.removePolicy('admin', 'old-resource', 'read');

// Add role
await enforcer.addGroupingPolicy('user123', 'admin');

// Check permission
const allowed = await enforcer.enforce('user123', 'all', 'read');
```

#### Step 5: Advanced Casbin Models

**ABAC (Attribute-Based Access Control) Model:**

Create `model-abac.conf`:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == r.obj.owner || r.sub.role == "admin"
```

**ACL (Access Control List) Model:**

Create `model-acl.conf`:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

### Authintick Setup Guide

**Note:** Authintick is a lightweight library. Check the [official repository](https://github.com/authintick/authintick) for the latest API.

#### Basic Configuration:

```typescript
const auth = new Authintick({
  secret: process.env.AUTHINTICK_SECRET,
  tokenExpiration: '24h',
  refreshTokenExpiration: '7d',
  // Additional options based on library version
});
```

#### Custom Middleware:

If Authintick doesn't provide Express middleware, create custom:

```typescript
function authintickMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = auth.verify(token);
    (req as any).user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
```

## Advanced: Cookie-Based Authentication

The provided implementations already support cookies! The `express-jwt` middleware automatically checks both Authorization header and cookies.

**Set cookie after login (in NestJS or frontend):**
```typescript
res.cookie('token', jwtToken, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
});
```

The server will automatically read the token from the cookie if no Authorization header is present.

## Testing

### Test Server Directly

```bash
# Should return 401 without token
curl http://localhost:3001/

# Should return 403 with token but no permissions
curl -H "Authorization: Bearer TOKEN_WITHOUT_PERMISSIONS" \
     http://localhost:3001/

# Should work with valid token and permissions
curl -H "Authorization: Bearer VALID_TOKEN_WITH_PERMISSIONS" \
     http://localhost:3001/flowcharts/point-creation
```

### Verify JWT Token

Decode your JWT at [jwt.io](https://jwt.io) to check:
- `permissions` array exists
- Token is not expired
- Signature is valid

## Troubleshooting

### Server returns 401 Unauthorized

- Check if JWT token is being sent in `Authorization` header or cookie
- Verify `JWT_SECRET` matches your NestJS backend
- Check if token is expired

### Server returns 403 Forbidden

- Verify `permissions` array exists in JWT payload
- Check if path matches permission rules (e.g., `/flowcharts` for `docs:flowcharts`)
- Decode JWT to inspect payload

### Static files not loading

- Ensure `npm run build` completed successfully
- Check if `build/` directory exists
- Verify file paths in `build/` match requested URLs

### TypeScript compilation errors

- Install TypeScript: `npm install --save-dev typescript @types/node @types/express`
- Check `tsconfig.json` configuration
- Use `ts-node` for development: `npx ts-node server.ts`

## Security Considerations

1. **JWT Secret:** Never commit `JWT_SECRET` to version control. Use environment variables.
2. **HTTPS:** Use HTTPS in production (with reverse proxy like Nginx or Cloudflare)
3. **Token Expiration:** Set reasonable expiration times for JWT tokens
4. **HttpOnly Cookies:** If using cookies, set `httpOnly: true` to prevent XSS attacks
5. **Rate Limiting:** Consider adding rate limiting middleware

## Production Deployment

### With PM2

```bash
# Install PM2 globally
npm install -g pm2

# Start server
pm2 start npm --name "technical-docs" -- run serve:rbac:prod

# Save PM2 configuration
pm2 save

# Setup PM2 to start on system boot
pm2 startup
```

### Environment Variables

Create `.env` file or set environment variables:

```bash
export JWT_SECRET="your-secret-key"
export PORT=3001
export NODE_ENV=production
```

### Behind Reverse Proxy (Nginx)

If you want to use this Express server behind Nginx:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Maintenance

- Monitor server logs: `pm2 logs technical-docs`
- Keep dependencies updated: `npm audit` and `npm update`
- Rotate JWT secrets periodically
- Review and update permission logic as needed


