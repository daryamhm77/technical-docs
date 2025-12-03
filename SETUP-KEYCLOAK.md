# Keycloak Setup Guide

This guide will help you set up Keycloak for this documentation site.

## Prerequisites

- Node.js 20+
- Docker and Docker Compose
- npm or yarn

## Step 1: Install Dependencies

```bash
npm install
```

This will install:
- `express` - Web server
- `keycloak-connect` - Keycloak adapter for Express
- `express-session` - Session management
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting

## Step 2: Start Keycloak Server

```bash
# Start Keycloak with PostgreSQL database
npm run keycloak:up

# Check logs
npm run keycloak:logs
```

This will start:
- Keycloak server on `http://localhost:8080`
- PostgreSQL database on `localhost:5432`

## Step 3: Configure Keycloak

### 3.1 Access Admin Console

1. Open `http://localhost:8080`
2. Click "Administration Console"
3. Login:
   - Username: `admin`
   - Password: `admin` (or your `KEYCLOAK_ADMIN_PASSWORD`)

### 3.2 Create Realm

1. Hover over "Master" realm (top left)
2. Click "Create Realm"
3. Name: `docs-realm`
4. Click "Create"

### 3.3 Create Client

1. Go to "Clients" → "Create client"
2. Client type: `OpenID Connect`
3. Client ID: `docs-client`
4. Click "Next"
5. Client authentication: `OFF` (public client)
6. Valid redirect URIs: `http://localhost:3001/*`
7. Web origins: `http://localhost:3001`
8. Click "Save"

### 3.4 Create Roles

1. Go to "Realm roles" → "Create role"
2. Create the following roles:
   - `docs:all` - Full documentation access
   - `docs:flowcharts` - Flowcharts access only
   - `admin` - Administrator (optional)
   - `viewer` - Read-only access (optional)

### 3.5 Create Users

1. Go to "Users" → "Add user"
2. Fill in:
   - Username: `testuser`
   - Email: `test@example.com`
   - First Name: `Test`
   - Last Name: `User`
3. Click "Create"
4. Go to "Credentials" tab
5. Click "Set password"
6. Set password and toggle "Temporary" to OFF
7. Click "Save"
8. Go to "Role mapping" tab
9. Click "Assign role"
10. Select `docs:flowcharts` → "Assign"

### 3.6 Configure Client Scopes (Optional - for token claims)

1. Go to "Client scopes" → "Create"
2. Name: `docs-permissions`
3. Go to "Mappers" tab → "Add mapper" → "By configuration"
4. Select "User Realm Role" mapper
5. Configure:
   - Name: `docs-roles`
   - Token Claim Name: `docs_permissions`
   - Add to access token: ON
   - Add to ID token: ON
6. Go to "Clients" → Select `docs-client`
7. Go to "Client scopes" tab
8. Add `docs-permissions` to "Default Client Scopes"

## Step 4: Configure Environment Variables

Create a `.env` file in the project root:

```env
# Server Configuration
PORT=3001
NODE_ENV=development

# Session Secret (change this in production!)
SESSION_SECRET=your-random-session-secret-change-this-in-production

# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=docs-realm
KEYCLOAK_CLIENT_ID=docs-client

# Keycloak Admin (for Docker Compose)
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# Keycloak Database (for Docker Compose)
KEYCLOAK_DB_PASSWORD=keycloak
```

## Step 5: Build Docusaurus

```bash
npm run build
```

This creates the `build/` directory with static files.

## Step 6: Start Express Server with Keycloak

### Development Mode

```bash
npm run serve:keycloak
```

### Production Mode

```bash
# Compile TypeScript
npm run build:keycloak

# Run compiled version
npm run serve:keycloak:prod
```

### With PM2

```bash
# Install PM2 globally
npm install -g pm2

# Start server
pm2 start npm --name "technical-docs-keycloak" -- run serve:keycloak:prod

# Save PM2 configuration
pm2 save

# View logs
pm2 logs technical-docs-keycloak
```

## Step 7: Test the Setup

1. Open `http://localhost:3001`
2. You should be redirected to Keycloak login page
3. Login with your test user credentials
4. After successful login, you'll be redirected back to the documentation
5. Try accessing `/flowcharts/*` - users without `docs:flowcharts` role will see 403 error

## Access Control Testing

### Test User with Flowcharts Access

1. Create user with `docs:flowcharts` role
2. Login and access `/flowcharts/laser-event-detection`
3. Should work ✅

### Test User Without Flowcharts Access

1. Create user without `docs:flowcharts` role
2. Login and try to access `/flowcharts/laser-event-detection`
3. Should see 403 error page ❌

## Troubleshooting

### Keycloak Server Not Starting

```bash
# Check if ports are in use
lsof -i :8080
lsof -i :5432

# Restart Keycloak
npm run keycloak:down
npm run keycloak:up
```

### Cannot Access Admin Console

- Make sure Keycloak is running: `docker ps`
- Check logs: `npm run keycloak:logs`
- Verify URL: `http://localhost:8080`

### 401 Unauthorized Errors

- Check Keycloak URL in `.env`
- Verify realm name matches
- Check client ID matches
- Ensure user is logged in

### 403 Forbidden Errors

- Verify user has correct roles assigned
- Check role names match exactly (`docs:flowcharts`, `docs:all`)
- Verify token contains roles (decode at jwt.io)

### Database Connection Issues

- Check PostgreSQL is running: `docker ps`
- Verify database credentials in `docker-compose.keycloak.yml`
- Check database logs: `docker logs keycloak-postgres`

## Stopping Keycloak

```bash
# Stop Keycloak and database
npm run keycloak:down

# Stop and remove volumes (⚠️ deletes data)
docker-compose -f docker-compose.keycloak.yml down -v
```

## Production Deployment

### Important Security Considerations

1. **Change Default Passwords:**
   - Set strong `KEYCLOAK_ADMIN_PASSWORD`
   - Set strong `KEYCLOAK_DB_PASSWORD`
   - Set strong `SESSION_SECRET`

2. **Use HTTPS:**
   - Configure reverse proxy (Nginx)
   - Use SSL certificates
   - Update `KEYCLOAK_URL` to HTTPS

3. **Database:**
   - Use managed PostgreSQL in production
   - Regular backups
   - Connection pooling

4. **Environment Variables:**
   - Never commit `.env` to git
   - Use secrets management (AWS Secrets Manager, etc.)

5. **Rate Limiting:**
   - Adjust rate limits in `server-keycloak.ts`
   - Consider IP-based blocking

## Next Steps

- Customize Keycloak theme
- Set up email verification
- Configure password policies
- Add social login providers
- Set up user federation (LDAP, etc.)

## Additional Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/)
- [Express Session Documentation](https://github.com/expressjs/session)






