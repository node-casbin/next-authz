// Copyright 2026 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { newEnforcer, Enforcer, newModelFromString } from 'casbin';
import { NextRequest, NextResponse } from 'next/server';
import { nextAuthz } from '../src/authz';

// Mock Next.js request helper
function createMockRequest(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {}
): NextRequest {
  const req = new NextRequest(url, { method });
  Object.entries(headers).forEach(([key, value]) => {
    req.headers.set(key, value);
  });
  return req;
}

describe('nextAuthz', () => {
  let enforcer: Enforcer;

  beforeAll(async () => {
    // Create a model from string
    const model = newModelFromString(`
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
    `);

    // Create an enforcer with the model
    enforcer = await newEnforcer(model);

    // Add some policies (using lowercase HTTP methods)
    await enforcer.addPolicy('alice', '/api/data', 'get');
    await enforcer.addPolicy('bob', '/api/data', 'write');
    await enforcer.addPolicy('admin', '/api/admin', 'get');
    await enforcer.addPolicy('admin', '/api/admin', 'write');

    // Add role
    await enforcer.addGroupingPolicy('alice', 'admin');
  });

  describe('Default Configuration', () => {
    it('should allow authorized requests', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should deny unauthorized requests', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'charlie',
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(403);
      expect(await res.text()).toBe('Forbidden');
    });

    it('should use pathname as resource by default', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should use HTTP method as action by default', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'bob',
      });

      const reqGet = createMockRequest('http://localhost/api/data', 'GET');
      const resGet = await middleware(reqGet);
      expect(resGet.status).toBe(403);

      const reqWrite = createMockRequest('http://localhost/api/data', 'WRITE');
      const resWrite = await middleware(reqWrite);
      expect(resWrite.status).not.toBe(403);
    });

    it('should use anonymous as default subject', async () => {
      const middleware = nextAuthz({
        enforcer,
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(403);
    });
  });

  describe('Custom Extractors', () => {
    it('should use custom subject extractor', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: (req) => req.headers.get('x-user') || 'anonymous',
      });

      const req = createMockRequest('http://localhost/api/data', 'GET', {
        'x-user': 'alice',
      });
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should use custom resource extractor', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
        resourceExtractor: (req) => '/api/data',
      });

      const req = createMockRequest('http://localhost/different/path', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should use custom action extractor', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
        actionExtractor: () => 'get',
      });

      const req = createMockRequest('http://localhost/api/data', 'POST');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });
  });

  describe('Custom Handlers', () => {
    it('should use custom onForbidden handler', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'charlie',
        onForbidden: () => new NextResponse('Access Denied', { status: 401 }),
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(401);
      expect(await res.text()).toBe('Access Denied');
    });

    it('should use custom onAuthorized handler', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
        onAuthorized: (req) => {
          const res = NextResponse.next();
          res.headers.set('x-authorized', 'true');
          return res;
        },
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.headers.get('x-authorized')).toBe('true');
    });

    it('should use custom onError handler', async () => {
      const mockEnforcer = {
        enforce: jest.fn().mockRejectedValue(new Error('Test error')),
      } as any;

      const middleware = nextAuthz({
        enforcer: mockEnforcer,
        onError: () => new NextResponse('Custom Error', { status: 503 }),
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(503);
      expect(await res.text()).toBe('Custom Error');
    });
  });

  describe('Async Extractors', () => {
    it('should support async subject extractor', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: async (req) => {
          return new Promise((resolve) => {
            setTimeout(() => resolve('alice'), 10);
          });
        },
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should support async resource extractor', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
        resourceExtractor: async () => {
          return new Promise((resolve) => {
            setTimeout(() => resolve('/api/data'), 10);
          });
        },
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should support async action extractor', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
        actionExtractor: async () => {
          return new Promise((resolve) => {
            setTimeout(() => resolve('get'), 10);
          });
        },
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });
  });

  describe('RBAC', () => {
    it('should handle role-based access control', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'alice',
      });

      // Alice has admin role, so should access admin endpoints
      const req = createMockRequest('http://localhost/api/admin', 'GET');
      const res = await middleware(req);

      expect(res.status).not.toBe(403);
    });

    it('should deny access without proper role', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => 'bob',
      });

      // Bob doesn't have admin role
      const req = createMockRequest('http://localhost/api/admin', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(403);
    });
  });

  describe('Error Handling', () => {
    it('should handle enforcer errors', async () => {
      const mockEnforcer = {
        enforce: jest.fn().mockRejectedValue(new Error('Database error')),
      } as any;

      const middleware = nextAuthz({
        enforcer: mockEnforcer,
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(500);
      expect(await res.text()).toBe('Internal Server Error');
    });

    it('should handle extractor errors', async () => {
      const middleware = nextAuthz({
        enforcer,
        subjectExtractor: () => {
          throw new Error('Extractor error');
        },
      });

      const req = createMockRequest('http://localhost/api/data', 'GET');
      const res = await middleware(req);

      expect(res.status).toBe(500);
    });
  });
});
