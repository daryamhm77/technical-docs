# Keycloak Testing Guide

## Step-by-Step Testing Instructions

### Step 1: Start Keycloak Server

Make sure Keycloak is running:

```bash
npm run keycloak:up
```

Wait for Keycloak to start (check logs):
```bash
npm run keycloak:logs
```

You should see: `Keycloak ... started in ... Listening on: http://0.0.0.0:8080`

### Step 2: Start Express Server

In a new terminal window:

```bash
cd /Users/mohammadi/technical-docs
npm run serve:keycloak
```

You should see:
```
📚 Documentation server with Keycloak running on http://localhost:3001
🔐 Keycloak URL: http://localhost:8080
🏛️  Realm: docs-realm
🛡️  Security: Helmet enabled
⏱️  Rate limiting: 100 requests per 15 minutes
```

**Keep this terminal open!**

### Step 3: Test with Browser

1. **Open your browser** and go to: `http://localhost:3001`

2. **You should be redirected to Keycloak login page** at:
   `http://localhost:8080/realms/docs-realm/protocol/openid-connect/auth?...`

3. **Login with test users:**

#### Test Case 1: Admin User (Full Access)
- **Username:** `admin-user`
- **Password:** `admin123`
- **Expected:** Can access ALL pages including `/flowcharts/*`

#### Test Case 2: Viewer User (Flowcharts Only)
- **Username:** `viewer-user`
- **Password:** `viewer123`
- **Expected:** 
  - ✅ Can access `/flowcharts/*` pages
  - ❌ Cannot access other restricted pages (if any)

#### Test Case 3: No Access User (403 Error)
- **Username:** `no-access-user`
- **Password:** `noaccess123`
- **Expected:** 
  - ✅ Can access home page
  - ❌ Gets 403 error when trying to access `/flowcharts/*`

### Step 4: Test Flowcharts Access

1. After logging in, try to access:
   ```
   http://localhost:3001/docs/backend/flowcharts/laser-event-detection
   ```

2. **Expected Results:**
   - **admin-user:** ✅ Should see the page
   - **viewer-user:** ✅ Should see the page
   - **no-access-user:** ❌ Should see 403 error page

### Step 5: Test Logout

1. Click logout (if available) or go to:
   ```
   http://localhost:3001/logout
   ```

2. You should be redirected back to Keycloak login

### Step 6: Verify Roles in Keycloak Admin

1. Go to: `http://localhost:8080`
2. Login as admin: `admin` / `admin`
3. Select realm: `docs-realm`
4. Go to **Users** → Select a user → **Role mapping** tab
5. Verify roles are assigned correctly

## Troubleshooting

### Server not starting?

```bash
# Check if port 3001 is in use
lsof -ti:3001

# Kill process if needed
kill -9 $(lsof -ti:3001)

# Restart server
npm run serve:keycloak
```

### Keycloak not responding?

```bash
# Check Keycloak status
docker ps | grep keycloak

# Check Keycloak logs
npm run keycloak:logs

# Restart Keycloak
npm run keycloak:down
npm run keycloak:up
```

### Getting 401 Unauthorized?

- Make sure Keycloak is running on port 8080
- Check `.env` file has correct Keycloak URL
- Verify realm name matches: `docs-realm`
- Verify client ID matches: `docs-client`

### Getting 403 but should have access?

- Check user roles in Keycloak Admin Console
- Verify role names match exactly: `docs:all`, `docs:flowcharts`
- Check server logs for role information

## Quick Test Commands

```bash
# Test server is running
curl -I http://localhost:3001

# Test Keycloak is running
curl -I http://localhost:8080

# Check server logs (in server terminal)
# Look for user roles in logs
```

## Success Criteria

✅ Server starts without errors
✅ Browser redirects to Keycloak login
✅ Can login with test users
✅ Admin user can access all pages
✅ Viewer user can access flowcharts
✅ No-access user gets 403 on flowcharts
✅ Logout works correctly





