import { createMiddleware } from 'hono/factory';
import { JWTService } from '../services/jwt-service';
import type { Env } from '../types/env';

export type AuthVars = {
  userId: string;
  email: string;
  jti: string;
};

export const requireAuth = createMiddleware<{ Bindings: Env; Variables: AuthVars }>(
  async (c, next) => {
    const header = c.req.header('Authorization') ?? '';
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    if (!match) {
      return c.json({ success: false, message: 'Missing or malformed bearer token' }, 401);
    }

    const token = match[1].trim();
    if (!token) {
      return c.json({ success: false, message: 'Missing or malformed bearer token' }, 401);
    }

    let result;
    try {
      const service = new JWTService(c.env);
      result = await service.verifyToken(token);
    } catch (error) {
      console.error('requireAuth: error verifying token', error);
      return c.json({ success: false, message: 'Token verification failed' }, 401);
    }

    if (!result.success || !result.payload) {
      return c.json({ success: false, message: result.error ?? 'Invalid token' }, 401);
    }

    c.set('userId', result.payload.sub);
    c.set('email', result.payload.email);
    c.set('jti', result.payload.jti);

    await next();
  }
);
