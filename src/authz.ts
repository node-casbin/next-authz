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

import { Enforcer } from 'casbin';
import { NextRequest, NextResponse } from 'next/server';

export interface NextAuthzConfig {
  /**
   * The Casbin enforcer instance
   */
  enforcer: Enforcer;

  /**
   * Function to extract the subject (user) from the request
   * Default: returns 'anonymous'
   */
  subjectExtractor?: (req: NextRequest) => string | Promise<string>;

  /**
   * Function to extract the resource from the request
   * Default: returns the pathname
   */
  resourceExtractor?: (req: NextRequest) => string | Promise<string>;

  /**
   * Function to extract the action from the request
   * Default: returns the HTTP method in lowercase
   */
  actionExtractor?: (req: NextRequest) => string | Promise<string>;

  /**
   * Custom response when authorization fails
   * Default: 403 Forbidden
   */
  onForbidden?: (req: NextRequest) => NextResponse | Promise<NextResponse>;

  /**
   * Custom response when authorization succeeds
   * Default: NextResponse.next()
   */
  onAuthorized?: (req: NextRequest) => NextResponse | Promise<NextResponse>;

  /**
   * Function to handle errors during authorization
   * Default: returns 500 Internal Server Error
   */
  onError?: (req: NextRequest, error: Error) => NextResponse | Promise<NextResponse>;
}

/**
 * Default subject extractor - returns 'anonymous'
 */
const defaultSubjectExtractor = (): string => {
  return 'anonymous';
};

/**
 * Default resource extractor - returns the pathname
 */
const defaultResourceExtractor = (req: NextRequest): string => {
  return req.nextUrl.pathname;
};

/**
 * Default action extractor - returns the HTTP method in lowercase
 */
const defaultActionExtractor = (req: NextRequest): string => {
  return req.method.toLowerCase();
};

/**
 * Default forbidden response handler
 */
const defaultOnForbidden = (): NextResponse => {
  return new NextResponse('Forbidden', { status: 403 });
};

/**
 * Default authorized response handler
 */
const defaultOnAuthorized = (): NextResponse => {
  return NextResponse.next();
};

/**
 * Default error handler
 */
const defaultOnError = (req: NextRequest, error: Error): NextResponse => {
  console.error('Authorization error:', error);
  return new NextResponse('Internal Server Error', { status: 500 });
};

/**
 * Creates a Next.js middleware function with Casbin authorization
 * 
 * @param config - Configuration for the authorization middleware
 * @returns Next.js middleware function
 * 
 * @example
 * ```typescript
 * import { newEnforcer } from 'casbin';
 * import { nextAuthz } from 'next-authz';
 * 
 * const enforcer = await newEnforcer('model.conf', 'policy.csv');
 * 
 * export const middleware = nextAuthz({
 *   enforcer,
 *   subjectExtractor: (req) => req.headers.get('user') || 'anonymous',
 * });
 * 
 * export const config = {
 *   matcher: '/api/:path*',
 * };
 * ```
 */
export function nextAuthz(config: NextAuthzConfig) {
  const {
    enforcer,
    subjectExtractor = defaultSubjectExtractor,
    resourceExtractor = defaultResourceExtractor,
    actionExtractor = defaultActionExtractor,
    onForbidden = defaultOnForbidden,
    onAuthorized = defaultOnAuthorized,
    onError = defaultOnError,
  } = config;

  return async (req: NextRequest): Promise<NextResponse> => {
    try {
      // Extract subject, resource, and action from the request
      const subject = await subjectExtractor(req);
      const resource = await resourceExtractor(req);
      const action = await actionExtractor(req);

      // Check authorization using Casbin enforcer
      const allowed = await enforcer.enforce(subject, resource, action);

      if (allowed) {
        return await onAuthorized(req);
      } else {
        return await onForbidden(req);
      }
    } catch (error) {
      return await onError(req, error as Error);
    }
  };
}
