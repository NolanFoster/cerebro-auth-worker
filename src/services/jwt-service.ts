/**
 * JWT Service for handling authentication tokens
 * Follows security best practices for JWT implementation
 */

import { SignJWT, jwtVerify, decodeJwt } from 'jose';
import { Env } from '../types/env';

export interface CustomJWTPayload {
  sub: string; // Subject (user ID)
  email: string; // User's email
  iat: number; // Issued at
  exp: number; // Expiration time
  jti: string; // JWT ID (unique identifier)
  aud: string; // Audience
  iss: string; // Issuer
}

export interface JWTResult {
  success: boolean;
  token?: string;
  payload?: CustomJWTPayload;
  error?: string;
}

export class JWTService {
  private secret: Uint8Array;
  private issuer: string;
  private audience: string;

  constructor(env: Env) {
    if (!env.JWT_SECRET) {
      throw new Error('JWT_SECRET not configured');
    }
    if (!env.JWT_ISSUER?.trim()) {
      throw new Error('JWT_ISSUER not configured');
    }
    if (!env.JWT_AUDIENCE?.trim()) {
      throw new Error('JWT_AUDIENCE not configured');
    }

    this.secret = new TextEncoder().encode(env.JWT_SECRET);
    this.issuer = env.JWT_ISSUER.trim();
    this.audience = env.JWT_AUDIENCE.trim();
  }

  /**
   * Create a JWT token for a user
   * @param userId - The user's ID (email hash)
   * @param email - The user's email address
   * @param expiresIn - Token expiration time in seconds (default: 24 hours)
   * @returns Promise<JWTResult>
   */
  async createToken(userId: string, email: string, expiresIn: number = 86400): Promise<JWTResult> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const exp = now + expiresIn;

      const payload = {
        sub: userId,
        email: email,
        iat: now,
        exp: exp,
        jti: this.generateJWTId(),
        aud: this.audience,
        iss: this.issuer
      };

      const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .setIssuer(this.issuer)
        .setAudience(this.audience)
        .setJti(payload.jti)
        .sign(this.secret);

      return {
        success: true,
        token,
        payload: payload as CustomJWTPayload
      };
    } catch (error) {
      console.error('Error creating JWT token:', error);
      return {
        success: false,
        error: 'Failed to create authentication token'
      };
    }
  }

  /**
   * Verify and decode a JWT token
   * @param token - The JWT token to verify
   * @returns Promise<JWTResult>
   */
  async verifyToken(token: string): Promise<JWTResult> {
    try {
      const { payload } = await jwtVerify(token, this.secret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ['HS256']
      });

      // Type assertion with validation
      const customPayload = payload as any;
      if (customPayload.email && customPayload.sub) {
        return {
          success: true,
          payload: customPayload as CustomJWTPayload
        };
      } else {
        throw new Error('Invalid payload structure');
      }
    } catch (error) {
      console.error('Error verifying JWT token:', error);
      return {
        success: false,
        error: 'Invalid or expired authentication token'
      };
    }
  }

  /**
   * Decode a JWT token without verification (for debugging/logging only)
   * @param token - The JWT token to decode
   * @returns JWTResult
   */
  decodeToken(token: string): JWTResult {
    try {
      const payload = decodeJwt(token) as any;
      
      // Validate payload structure
      if (payload.email && payload.sub) {
        return {
          success: true,
          payload: payload as CustomJWTPayload
        };
      } else {
        throw new Error('Invalid payload structure');
      }
    } catch (error) {
      console.error('Error decoding JWT token:', error);
      return {
        success: false,
        error: 'Invalid token format'
      };
    }
  }

  /**
   * Generate a unique JWT ID
   * @returns string
   */
  private generateJWTId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2);
    return `${timestamp}-${random}`;
  }

  /**
   * Check if a token is expired
   * @param payload - The JWT payload
   * @returns boolean
   */
  isTokenExpired(payload: CustomJWTPayload): boolean {
    const now = Math.floor(Date.now() / 1000);
    return payload.exp < now;
  }

  /**
   * Get token expiration time in seconds from now
   * @param payload - The JWT payload
   * @returns number
   */
  getTimeUntilExpiration(payload: CustomJWTPayload): number {
    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, payload.exp - now);
  }
}
