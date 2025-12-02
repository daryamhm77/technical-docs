# RBAC Implementation with Nginx Reverse Proxy

This guide explains how to implement Role-Based Access Control (RBAC) for Docusaurus documentation using Nginx as a reverse proxy.

## Overview

Nginx sits in front of Docusaurus and validates each request with your NestJS backend before serving documentation. This approach keeps authentication logic in your backend and leverages Nginx's performance.

## Architecture

```
User Request → Nginx → NestJS Auth Check → Nginx → Docusaurus (if allowed)
                                    ↓
                             403 Forbidden (if denied)
```

## Prerequisites

- Nginx installed and running
- NestJS backend with JWT authentication
- Docusaurus built and running on a local port (e.g., `http://127.0.0.1:3001`)
- NestJS backend running (e.g., `http://127.0.0.1:4000`)

## Setup Steps

### 1. Configure NestJS Backend

Create an endpoint in your NestJS application to validate documentation access:

**File: `src/auth/auth.controller.ts`**

```typescript
import { Controller, Get, Req, Res, Headers } from '@nestjs/common';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';

@Controller('auth')
export class AuthController {
  constructor(private jwtService: JwtService) {}

  @Get('validate-docs')
  async validateDocs(
    @Req() req: Request,
    @Res() res: Response,
    @Headers('x-original-uri') originalUri: string,
    @Headers('authorization') authHeader: string,
  ) {
    try {
      // Extract token from Authorization header
      const token = authHeader?.replace('Bearer ', '') || authHeader;
      
      if (!token) {
        return res.status(401).send('Unauthorized');
      }

      // Verify JWT token
      const payload = this.jwtService.verify(token);
      const permissions: string[] = payload.permissions || [];
      const path = originalUri || req.url;

      // Check permissions
      const canAccessAll = permissions.includes('docs:all');
      const canAccessFlowcharts = 
        permissions.includes('docs:flowcharts') && 
        path.includes('/flowcharts');

      if (canAccessAll || canAccessFlowcharts) {
        return res.status(200).send('OK');
      }

      return res.status(403).send('Forbidden');
    } catch (error) {
      return res.status(401).send('Invalid token');
    }
  }
}
```

**Important:** Make sure your JWT tokens include a `permissions` array when issued:

```typescript
// Example: When creating JWT token
const token = this.jwtService.sign({
  sub: user.id,
  email: user.email,
  permissions: ['docs:all'], // or ['docs:flowcharts']
});
```

### 2. Install Nginx (if not already installed)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nginx
```

**CentOS/RHEL:**
```bash
sudo yum install nginx
```

### 3. Configure Nginx

Create or edit the Nginx configuration file:

**File: `/etc/nginx/sites-available/technical-docs`**

```nginx
server {
    listen 80;
    server_name 18.199.29.228;  # Replace with your domain or IP

    # Internal auth endpoint (not accessible from outside)
    location = /_auth_docs {
        internal;
        proxy_pass http://127.0.0.1:4000/auth/validate-docs;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Host $host;
    }

    # Main documentation location
    location / {
        # Check authentication before serving
        auth_request /_auth_docs;
        
        # Handle auth errors
        auth_request_set $auth_status $upstream_status;
        error_page 401 = @error401;
        error_page 403 = @error403;

        # Proxy to Docusaurus
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Custom error pages
    location @error401 {
        return 401 '{"error": "Unauthorized"}';
        add_header Content-Type application/json;
    }

    location @error403 {
        return 403 '{"error": "Forbidden - You do not have access to this resource"}';
        add_header Content-Type application/json;
    }
}
```

### 4. Enable the Site

```bash
# Create symlink
sudo ln -s /etc/nginx/sites-available/technical-docs /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### 5. Start Docusaurus

Build and serve Docusaurus:

```bash
cd /var/www/docs/technical
npm run build
npm run serve -- --port 3001
```

Or with PM2:

```bash
pm2 start npm --name "docusaurus-serve" -- run serve -- --port 3001
```

## Usage

### Accessing Documentation

1. **Get JWT Token** from your NestJS backend (via login endpoint)
2. **Include token in requests:**

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://18.199.29.228/
```

Or in browser, you'll need to:
- Implement a login page that stores the token
- Use JavaScript to add the token to all requests

### Permission Examples

- **User with `docs:all`:** Can access all documentation pages
- **User with `docs:flowcharts`:** Can only access `/flowcharts/*` pages
- **User without permissions:** Gets `403 Forbidden`

## Testing

### Test Auth Endpoint Directly

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     -H "X-Original-URI: /flowcharts/point-creation" \
     http://127.0.0.1:4000/auth/validate-docs
```

Expected: `200 OK` if allowed, `403 Forbidden` if not.

### Test Full Flow

```bash
# Should return 401 without token
curl http://18.199.29.228/

# Should return 403 with invalid permissions
curl -H "Authorization: Bearer INVALID_TOKEN" http://18.199.29.228/

# Should work with valid token
curl -H "Authorization: Bearer VALID_TOKEN" http://18.199.29.228/
```

## Troubleshooting

### Nginx returns 502 Bad Gateway

- Check if Docusaurus is running: `curl http://127.0.0.1:3001`
- Check if NestJS is running: `curl http://127.0.0.1:4000/auth/validate-docs`
- Check Nginx error logs: `sudo tail -f /var/log/nginx/error.log`

### Always getting 403 Forbidden

- Verify JWT token is valid: decode it at [jwt.io](https://jwt.io)
- Check if `permissions` array exists in JWT payload
- Verify path matching logic in NestJS controller

### Auth endpoint not being called

- Check Nginx config syntax: `sudo nginx -t`
- Verify `internal` directive is present in `/_auth_docs` location
- Check Nginx access logs: `sudo tail -f /var/log/nginx/access.log`

## Security Considerations

1. **HTTPS:** Use SSL/TLS in production (Let's Encrypt with Certbot)
2. **Token Storage:** Store JWT in HttpOnly cookies for browser clients
3. **Rate Limiting:** Add rate limiting to prevent brute force
4. **CORS:** Configure CORS properly if accessing from different domains

## Advanced: HTTPS Setup

Add SSL configuration:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # ... rest of config
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

## Maintenance

- Monitor Nginx logs regularly
- Keep NestJS backend updated
- Rotate JWT secrets periodically
- Review and update permissions as needed













