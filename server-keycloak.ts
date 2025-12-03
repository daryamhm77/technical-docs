import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import session from 'express-session';
import Keycloak from 'keycloak-connect';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { MemoryStore } from 'express-session';

const app = express();
const PORT = process.env.PORT || 3001;
const BUILD_DIR = path.join(__dirname, 'build');

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Disable if Docusaurus needs it
}));

// Rate limiting (increased for development/testing)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs (increased for testing)
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Session configuration
const memoryStore = new MemoryStore();
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: memoryStore,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

// Keycloak configuration
const keycloakConfig: any = {
  realm: process.env.KEYCLOAK_REALM || 'docs-realm',
  'auth-server-url': process.env.KEYCLOAK_URL || 'http://localhost:8080',
  'ssl-required': 'external',
  resource: process.env.KEYCLOAK_CLIENT_ID || 'docs-client',
  'public-client': true,
  'confidential-port': 0,
};

// Initialize Keycloak
const keycloak = new Keycloak({ store: memoryStore }, keycloakConfig);

// Keycloak middleware
app.use(keycloak.middleware());

// Helper function to create 403 error page
function create403Page(roles: string[], message: string) {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Access Denied</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          }
          .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
          }
          h1 {
            color: #e74c3c;
            margin-bottom: 1rem;
          }
          p {
            color: #555;
            line-height: 1.6;
          }
          code {
            background: #f4f4f4;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
          }
          a {
            display: inline-block;
            margin-top: 1rem;
            padding: 0.75rem 1.5rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
            margin: 0.5rem;
          }
          a:hover {
            background: #5568d3;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>403 - Access Denied</h1>
          <p>${message}</p>
          <p>Your current roles: ${roles.length > 0 ? roles.join(', ') : 'None'}</p>
          <a href="/docs/backend/flowcharts/laser-event-detection">Go to Flowcharts</a>
          <a href="/">Go to Home</a>
        </div>
      </body>
    </html>
  `;
}

// Permission check middleware
function checkKeycloakPermissions(req: Request, res: Response, next: NextFunction) {
  const urlPath = req.path;
  
  // Skip permission check for static assets, logout, auth endpoints, and home page
  if (
    urlPath.startsWith('/assets/') ||
    urlPath.startsWith('/_next/') ||
    urlPath.startsWith('/logout') ||
    urlPath.startsWith('/auth/') ||
    urlPath === '/favicon.ico' ||
    urlPath.startsWith('/img/') ||
    urlPath.startsWith('/css/') ||
    urlPath === '/' ||
    urlPath === '/index.html'
  ) {
    return next();
  }
  
  // Get token from Keycloak
  const token = (req as any).kauth?.grant?.access_token;
  
  if (!token) {
    // If no token, Keycloak will handle redirect to login
    return next();
  }
  
  // Extract roles from token
  const roles = token.content?.realm_access?.roles || [];
  const hasFullAccess = roles.includes('docs:all') || roles.includes('admin');
  const hasFlowchartsAccess = roles.includes('docs:flowcharts');
  
  // Determine path type - be very specific and strict
  const isFlowchartsPath = urlPath.includes('/flowcharts') || urlPath.includes('flowcharts');
  const isAnyDocsPath = urlPath.startsWith('/docs/') || urlPath.includes('/docs/');
  
  // Users with full access can see everything
  if (hasFullAccess) {
    console.log(`✅ Full access: ${token.content?.email || 'unknown'} | Roles: ${roles.join(', ')} | Path: ${urlPath}`);
    return next();
  }
  
  // Users with only flowcharts access - STRICT: ONLY flowcharts allowed
  if (hasFlowchartsAccess && !hasFullAccess) {
    // Allow ONLY flowcharts paths - must contain 'flowcharts' in path
    if (isFlowchartsPath) {
      console.log(`✅ Flowcharts access: ${token.content?.email || 'unknown'} | Roles: ${roles.join(', ')} | Path: ${urlPath}`);
      return next();
    }
    
    // Block ALL other docs paths (backend, frontend, documentation-rules, etc.)
    // This includes ANY path that starts with /docs/ or contains /docs/ but NOT flowcharts
    if (isAnyDocsPath && !isFlowchartsPath) {
      console.log(`❌ Docs access blocked: ${token.content?.email || 'unknown'} | Roles: ${roles.join(', ')} | Path: ${urlPath}`);
      return res.status(403).send(create403Page(
        roles,
        'Your role (<code>docs:flowcharts</code>) only allows access to <strong>flowcharts documentation</strong>. You cannot access other documentation sections. Required role: <code>docs:all</code> for full access.'
      ));
    }
    
    // Allow non-docs pages (home, etc.)
    console.log(`✅ Non-docs access: ${token.content?.email || 'unknown'} | Path: ${urlPath}`);
    return next();
  }
  
  // Users without any docs access trying to access docs
  if (isAnyDocsPath && !isFlowchartsPath) {
    console.log(`❌ No docs access: ${token.content?.email || 'unknown'} | Roles: ${roles.join(', ')} | Path: ${urlPath}`);
    return res.status(403).send(create403Page(
      roles,
      'You do not have permission to access documentation. Required permissions: <code>docs:flowcharts</code> or <code>docs:all</code>'
    ));
  }
  
  // Users without docs access trying to access flowcharts
  if (isFlowchartsPath && !hasFlowchartsAccess) {
    console.log(`❌ Flowcharts access denied: ${token.content?.email || 'unknown'} | Roles: ${roles.join(', ')} | Path: ${urlPath}`);
    return res.status(403).send(create403Page(
      roles,
      'You do not have permission to access flowcharts. Required permissions: <code>docs:flowcharts</code> or <code>docs:all</code>'
    ));
  }
  
  // Attach user info to request (optional, for logging)
  (req as any).user = {
    id: token.content?.sub,
    email: token.content?.email,
    roles: roles,
  };
  
  // Log user access for debugging
  console.log(`✅ Access granted: ${token.content?.email || 'unknown'} | Roles: ${roles.join(', ') || 'none'} | Path: ${urlPath}`);
  
  next();
}

// Logout endpoint (must be before keycloak.protect())
app.get('/logout', (req: Request, res: Response) => {
  const logoutUrl = `${keycloakConfig['auth-server-url']}/realms/${keycloakConfig.realm}/protocol/openid-connect/logout?redirect_uri=${encodeURIComponent('http://localhost:3001')}`;
  (req as any).session?.destroy(() => {
    res.redirect(logoutUrl);
  });
});

// User info endpoint (for debugging)
app.get('/auth/user', keycloak.protect(), (req: Request, res: Response) => {
  const token = (req as any).kauth?.grant?.access_token;
  if (token) {
    res.json({
      id: token.content?.sub,
      email: token.content?.email,
      roles: token.content?.realm_access?.roles || [],
      username: token.content?.preferred_username,
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Protect all routes with Keycloak
app.use(keycloak.protect());
app.use(checkKeycloakPermissions);

// Middleware to inject user roles and hide restricted sidebar items
app.use((req: Request, res: Response, next: NextFunction) => {
  const originalSend = res.send;
  
  res.send = function (data: any): Response {
    // Only modify HTML responses
    if (typeof data === 'string' && data.includes('<!DOCTYPE html>')) {
      const token = (req as any).kauth?.grant?.access_token;
      const roles = token?.content?.realm_access?.roles || [];
      const hasFullAccess = roles.includes('docs:all') || roles.includes('admin');
      const hasFlowchartsAccess = roles.includes('docs:flowcharts');
      
      // Inject roles and sidebar filtering script
      const rolesScript = `
      <script>
        window.__USER_ROLES__ = ${JSON.stringify(roles)};
        window.__HAS_FULL_ACCESS__ = ${hasFullAccess};
        window.__HAS_FLOWCHARTS_ACCESS__ = ${hasFlowchartsAccess};
        console.log('User roles injected:', window.__USER_ROLES__);
        
        // Hide restricted sidebar items based on user roles
        (function() {
          function hideRestrictedSidebarItems() {
            if (window.__HAS_FULL_ACCESS__) {
              return; // Show everything for full access users
            }
            
            if (!window.__HAS_FLOWCHARTS_ACCESS__) {
              // Hide all docs if no access
              const sidebar = document.querySelector('nav[class*="menu"], nav[class*="sidebar"], aside[class*="menu"]');
              if (sidebar) {
                sidebar.style.display = 'none';
              }
              return;
            }
            
            // For flowcharts-only users, hide all non-flowcharts items
            if (window.__HAS_FLOWCHARTS_ACCESS__ && !window.__HAS_FULL_ACCESS__) {
              // Wait for sidebar to load
              setTimeout(function() {
                // Find all sidebar links
                const sidebarLinks = document.querySelectorAll('a[href*="/docs/"]');
                sidebarLinks.forEach(function(link) {
                  const href = link.getAttribute('href') || '';
                  // Hide if it's NOT a flowcharts link
                  if (href.includes('/docs/') && !href.includes('flowcharts')) {
                    // Hide the parent list item
                    let parent = link.closest('li');
                    if (parent) {
                      parent.style.display = 'none';
                    }
                    // Also hide parent sections
                    let section = link.closest('[class*="menu__list-item"], [class*="theme-doc-sidebar-item"]');
                    if (section) {
                      section.style.display = 'none';
                    }
                  }
                });
                
                // Hide entire sections that don't contain flowcharts
                const menuSections = document.querySelectorAll('[class*="menu__list"], [class*="theme-doc-sidebar-container"] > ul > li');
                menuSections.forEach(function(section) {
                  const sectionLinks = section.querySelectorAll('a[href*="/docs/"]');
                  let hasFlowchartsLink = false;
                  sectionLinks.forEach(function(link) {
                    const href = link.getAttribute('href') || '';
                    if (href.includes('flowcharts')) {
                      hasFlowchartsLink = true;
                    }
                  });
                  
                  // If section has no flowcharts links, hide it
                  if (sectionLinks.length > 0 && !hasFlowchartsLink) {
                    section.style.display = 'none';
                  }
                });
                
                // Hide specific sections by text content
                const allMenuItems = document.querySelectorAll('[class*="menu__list-item"], li[class*="theme-doc-sidebar-item"]');
                allMenuItems.forEach(function(item) {
                  const text = item.textContent || '';
                  const link = item.querySelector('a');
                  const href = link ? (link.getAttribute('href') || '') : '';
                  
                  // Hide if it's a docs link but not flowcharts
                  if (href.includes('/docs/') && !href.includes('flowcharts')) {
                    item.style.display = 'none';
                  }
                  
                  // Hide specific sections
                  if (text.includes('db-panto-erd') || 
                      text.includes('documentation-rules') || 
                      text.includes('system-overview') ||
                      (text.includes('backend') && !text.includes('flowcharts')) ||
                      text.includes('frontend')) {
                    item.style.display = 'none';
                  }
                });
              }, 500);
            }
          }
          
          // Run on page load
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', hideRestrictedSidebarItems);
          } else {
            hideRestrictedSidebarItems();
          }
          
          // Also run after navigation (for SPA)
          let lastUrl = location.href;
          new MutationObserver(function() {
            const url = location.href;
            if (url !== lastUrl) {
              lastUrl = url;
              setTimeout(hideRestrictedSidebarItems, 300);
            }
          }).observe(document, { subtree: true, childList: true });
        })();
      </script>
    `;
      
      data = data.replace('</head>', `${rolesScript}</head>`);
    }
    
    return originalSend.call(this, data);
  };
  
  next();
});

// Serve static files from build directory
app.use(express.static(BUILD_DIR, {
  index: 'index.html',
  extensions: ['html'],
}));

// Handle SPA routing (fallback to index.html for client-side routes)
// Inject sidebar filtering script
app.get('*', (req: Request, res: Response) => {
  const filePath = path.join(BUILD_DIR, 'index.html');
  
  // Read the HTML file
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.sendFile(filePath); // Fallback to original
    }
    
    // Get user roles from token
    const token = (req as any).kauth?.grant?.access_token;
    const roles = token?.content?.realm_access?.roles || [];
    const hasFullAccess = roles.includes('docs:all') || roles.includes('admin');
    const hasFlowchartsAccess = roles.includes('docs:flowcharts');
    
    // Inject roles and sidebar filtering script
    const rolesScript = `
      <script>
        window.__USER_ROLES__ = ${JSON.stringify(roles)};
        window.__HAS_FULL_ACCESS__ = ${hasFullAccess};
        window.__HAS_FLOWCHARTS_ACCESS__ = ${hasFlowchartsAccess};
        console.log('User roles injected:', window.__USER_ROLES__);
        
        // Hide restricted sidebar items based on user roles
        (function() {
          function hideRestrictedSidebarItems() {
            if (window.__HAS_FULL_ACCESS__) {
              return; // Show everything for full access users
            }
            
            if (!window.__HAS_FLOWCHARTS_ACCESS__) {
              // Hide all docs if no access
              const sidebar = document.querySelector('nav[class*="menu"], nav[class*="sidebar"], aside[class*="menu"]');
              if (sidebar) {
                sidebar.style.display = 'none';
              }
              return;
            }
            
            // For flowcharts-only users, hide all non-flowcharts items
            if (window.__HAS_FLOWCHARTS_ACCESS__ && !window.__HAS_FULL_ACCESS__) {
              function doHide() {
                // Find all sidebar links and hide non-flowcharts ones
                const sidebarLinks = document.querySelectorAll('a[href*="/docs/"]');
                sidebarLinks.forEach(function(link) {
                  const href = link.getAttribute('href') || '';
                  // Hide if it's NOT a flowcharts link
                  if (href.includes('/docs/') && !href.includes('flowcharts')) {
                    // Hide the parent list item and all parents
                    let parent = link.closest('li');
                    while (parent) {
                      parent.style.display = 'none';
                      parent = parent.parentElement?.closest('li') || null;
                    }
                  }
                });
                
                // Hide specific sections by text content
                const allMenuItems = document.querySelectorAll('li, [class*="menu__list-item"], [class*="theme-doc-sidebar-item"]');
                allMenuItems.forEach(function(item) {
                  const text = item.textContent || '';
                  const link = item.querySelector('a');
                  const href = link ? (link.getAttribute('href') || '') : '';
                  
                  // Hide if it's a docs link but not flowcharts
                  if (href.includes('/docs/') && !href.includes('flowcharts')) {
                    item.style.display = 'none';
                  }
                  
                  // Hide specific sections by text
                  if (text.includes('db-panto-erd') || 
                      text.includes('documentation-rules') || 
                      text.includes('system-overview') ||
                      (text.includes('backend') && !text.includes('flowcharts') && !text.includes('Flowcharts')) ||
                      text.includes('frontend')) {
                    item.style.display = 'none';
                  }
                });
              }
              
              // Run multiple times to catch dynamic content
              doHide();
              setTimeout(doHide, 100);
              setTimeout(doHide, 500);
              setTimeout(doHide, 1000);
              setTimeout(doHide, 2000);
            }
          }
          
          // Run on page load
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', hideRestrictedSidebarItems);
          } else {
            hideRestrictedSidebarItems();
          }
          
          // Also run after navigation (for SPA)
          let lastUrl = location.href;
          new MutationObserver(function() {
            const url = location.href;
            if (url !== lastUrl) {
              lastUrl = url;
              setTimeout(hideRestrictedSidebarItems, 300);
            }
          }).observe(document, { subtree: true, childList: true });
        })();
      </script>
    `;
    
    // Inject script before </head>
    const modifiedData = data.replace('</head>', `${rolesScript}</head>`);
    res.send(modifiedData);
  });
});

// Error handling middleware
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`📚 Documentation server with Keycloak running on http://localhost:${PORT}`);
  console.log(`🔐 Keycloak URL: ${keycloakConfig['auth-server-url']}`);
  console.log(`🏛️  Realm: ${keycloakConfig.realm}`);
  console.log(`🛡️  Security: Helmet enabled`);
  console.log(`⏱️  Rate limiting: 1000 requests per 15 minutes`);
  console.log(`\n⚠️  Make sure Keycloak server is running on ${keycloakConfig['auth-server-url']}`);
  console.log(`⚠️  Make sure Docusaurus is built: npm run build`);
});
