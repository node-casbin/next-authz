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

import { newEnforcer } from 'casbin';
import { nextAuthz } from '../src';

async function main() {
  // Initialize Casbin enforcer with RBAC model
  const enforcer = await newEnforcer();

  // Set up a simple RBAC model
  await enforcer.initWithModelAndAdapter(
    `
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
    `.trim(),
    undefined
  );

  // Add some policies
  await enforcer.addPolicy('alice', '/api/data', 'get');
  await enforcer.addPolicy('bob', '/api/data', 'write');
  await enforcer.addPolicy('admin', '/api/admin', 'get');
  await enforcer.addPolicy('admin', '/api/admin', 'write');

  // Add role
  await enforcer.addGroupingPolicy('alice', 'admin');

  // Create the middleware
  const middleware = nextAuthz({
    enforcer,
    subjectExtractor: (req) => req.headers.get('user') || 'anonymous',
  });

  console.log('Next-Authz middleware created successfully!');
  console.log('Use this middleware in your Next.js middleware.ts file');
}

main().catch(console.error);
