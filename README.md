Next-Authz
====
[![CI](https://github.com/node-casbin/next-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/node-casbin/next-authz/actions/workflows/ci.yml)
[![NPM version][npm-image]][npm-url]
[![NPM download][download-image]][download-url]
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

[npm-image]: https://img.shields.io/npm/v/next-authz.svg?style=flat-square
[npm-url]: https://npmjs.com/package/next-authz
[download-image]: https://img.shields.io/npm/dm/next-authz.svg?style=flat-square
[download-url]: https://npmjs.com/package/next-authz

Next-Authz is a Next.js middleware for [Casbin](https://github.com/casbin/node-casbin) authorization. It provides an easy-to-use middleware function that integrates Casbin's powerful access control into your Next.js application.

## Installation

```bash
npm install next-authz
```

## Simple Example

Create a middleware file in your Next.js project (e.g., `middleware.ts` in the root or `src` directory):

```typescript
import { newEnforcer } from 'casbin';
import { nextAuthz } from 'next-authz';

// Initialize Casbin enforcer
const enforcer = await newEnforcer('model.conf', 'policy.csv');

// Create the middleware
export const middleware = nextAuthz({
  enforcer,
  subjectExtractor: (req) => req.headers.get('user') || 'anonymous',
});

// Configure which routes to protect
export const config = {
  matcher: '/api/:path*',
};
```

## Configuration Options

The `nextAuthz` function accepts a configuration object with the following options:

### Required Options

- **`enforcer`**: A Casbin enforcer instance

### Optional Options

- **`subjectExtractor`**: Function to extract the subject (user) from the request
  - Default: Returns `'anonymous'`
  - Example: `(req) => req.headers.get('user') || 'anonymous'`

- **`resourceExtractor`**: Function to extract the resource from the request
  - Default: Returns the request pathname
  - Example: `(req) => req.nextUrl.pathname`

- **`actionExtractor`**: Function to extract the action from the request
  - Default: Returns the HTTP method in lowercase
  - Example: `(req) => req.method.toLowerCase()`

- **`onForbidden`**: Custom response when authorization fails
  - Default: Returns 403 Forbidden response
  - Example: `(req) => new NextResponse('Access Denied', { status: 401 })`

- **`onAuthorized`**: Custom response when authorization succeeds
  - Default: Returns `NextResponse.next()`
  - Example: `(req) => { const res = NextResponse.next(); res.headers.set('x-authorized', 'true'); return res; }`

- **`onError`**: Function to handle errors during authorization
  - Default: Returns 500 Internal Server Error
  - Example: `(req, error) => new NextResponse('Error: ' + error.message, { status: 500 })`

## Examples

### Basic RBAC Example

```typescript
import { newEnforcer } from 'casbin';
import { nextAuthz } from 'next-authz';

const enforcer = await newEnforcer('model.conf', 'policy.csv');

export const middleware = nextAuthz({
  enforcer,
  subjectExtractor: (req) => {
    // Extract user from JWT token, session, or header
    return req.headers.get('x-user-id') || 'anonymous';
  },
});

export const config = {
  matcher: ['/api/admin/:path*', '/api/users/:path*'],
};
```

### Custom Resource and Action Example

```typescript
import { newEnforcer } from 'casbin';
import { nextAuthz } from 'next-authz';

const enforcer = await newEnforcer('model.conf', 'policy.csv');

export const middleware = nextAuthz({
  enforcer,
  subjectExtractor: (req) => req.headers.get('user') || 'anonymous',
  resourceExtractor: (req) => {
    // Map URL paths to resource names
    const path = req.nextUrl.pathname;
    if (path.startsWith('/api/posts')) return 'posts';
    if (path.startsWith('/api/comments')) return 'comments';
    return path;
  },
  actionExtractor: (req) => {
    // Map HTTP methods to actions
    const method = req.method;
    if (method === 'GET') return 'read';
    if (method === 'POST') return 'create';
    if (method === 'PUT' || method === 'PATCH') return 'update';
    if (method === 'DELETE') return 'delete';
    return method.toLowerCase();
  },
});

export const config = {
  matcher: '/api/:path*',
};
```

### Custom Response Handlers Example

```typescript
import { newEnforcer } from 'casbin';
import { nextAuthz } from 'next-authz';
import { NextResponse } from 'next/server';

const enforcer = await newEnforcer('model.conf', 'policy.csv');

export const middleware = nextAuthz({
  enforcer,
  subjectExtractor: (req) => req.headers.get('user') || 'anonymous',
  onForbidden: (req) => {
    return NextResponse.json(
      { error: 'You do not have permission to access this resource' },
      { status: 403 }
    );
  },
  onAuthorized: (req) => {
    const response = NextResponse.next();
    response.headers.set('x-authorized', 'true');
    response.headers.set('x-timestamp', new Date().toISOString());
    return response;
  },
  onError: (req, error) => {
    console.error('Authorization error:', error);
    return NextResponse.json(
      { error: 'An error occurred during authorization' },
      { status: 500 }
    );
  },
});

export const config = {
  matcher: '/api/:path*',
};
```

### Async Extractors Example

All extractor functions support async operations:

```typescript
import { newEnforcer } from 'casbin';
import { nextAuthz } from 'next-authz';

const enforcer = await newEnforcer('model.conf', 'policy.csv');

export const middleware = nextAuthz({
  enforcer,
  subjectExtractor: async (req) => {
    // Fetch user from database or validate JWT token
    const token = req.headers.get('authorization');
    if (!token) return 'anonymous';
    
    const user = await validateToken(token);
    return user.id;
  },
  resourceExtractor: async (req) => {
    // You can perform async operations here too
    return req.nextUrl.pathname;
  },
});

export const config = {
  matcher: '/api/:path*',
};
```

## Model and Policy Files

Next-Authz uses Casbin's model and policy format. Here's an example:

### model.conf (RBAC model)

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

### policy.csv

```csv
p, alice, /api/data, read
p, bob, /api/data, write
p, admin, /api/admin, read
p, admin, /api/admin, write

g, alice, admin
```

## Integration with Next.js

Next-Authz is designed to work seamlessly with Next.js middleware. The middleware runs on edge runtime by default, providing fast authorization checks close to your users.

For more information on Next.js middleware, see the [Next.js documentation](https://nextjs.org/docs/app/building-your-application/routing/middleware).

## API Reference

### `nextAuthz(config: NextAuthzConfig)`

Creates a Next.js middleware function with Casbin authorization.

**Parameters:**
- `config`: Configuration object for the authorization middleware

**Returns:**
- Next.js middleware function

## Getting Help

- [Node-Casbin](https://github.com/casbin/node-casbin)
- [Casbin Documentation](https://casbin.org/docs/overview)
- [Next.js Middleware Documentation](https://nextjs.org/docs/app/building-your-application/routing/middleware)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.