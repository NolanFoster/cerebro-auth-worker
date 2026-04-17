import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { Env } from './types/env';
import { storeOTP, verifyOTPForEmail, hasOTP, deleteOTP, getOTPStats } from './utils/otp-manager';
import {
  storeRegChallenge,
  consumeRegChallenge,
  storeAuthChallenge,
  consumeAuthChallenge,
  saveCredential,
  getCredential,
  updateCredentialCounter,
  listUserCredentials,
  deleteCredential,
  type CredentialRecord,
} from './utils/passkey-manager';
import { PasskeyService } from './services/passkey-service';
import { EmailService } from './services/email-service';
import { identifyUser } from './services/flaggly-service';
import { recordLogin } from './services/user-sync';
import { requireAuth, type AuthVars } from './middleware/require-auth';
import { generateSecureToken } from './utils/crypto';

const app = new Hono<{ Bindings: Env; Variables: AuthVars }>();

// Middleware
app.use('*', logger());
app.use('*', (c, next) => {
  const raw = c.env.CORS_ORIGINS?.trim();
  const allowList = raw ? raw.split(',').map((s) => s.trim()).filter(Boolean) : [];
  return cors({
    origin: allowList.length > 0 ? allowList : (origin) => origin || '*',
  })(c, next);
});

// Health check endpoint
app.get('/health', async (c) => {
  const env = c.env;
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: env.ENVIRONMENT,
    services: {
      otp_kv: 'unknown',
      user_management: 'unknown',
      email: 'unknown'
    }
  };

  try {
    // Test OTP_KV access
    const testKey = '__health_check_otp__';
    await env.OTP_KV.put(testKey, new Date().toISOString(), {
      expirationTtl: 60 // Expire after 1 minute
    });
    const otpKvValue = await env.OTP_KV.get(testKey);
    if (otpKvValue) {
      health.services.otp_kv = 'healthy';
    }
  } catch (error) {
    health.services.otp_kv = 'unhealthy';
    health.status = 'degraded';
    console.error('OTP_KV health check failed:', error);
  }

  const userMgmtUrl = env.USER_MANAGEMENT_WORKER_URL?.trim();
  if (userMgmtUrl) {
    try {
      const response = await fetch(`${userMgmtUrl}/health`);
      if (response.ok) {
        health.services.user_management = 'healthy';
      } else {
        health.services.user_management = 'unhealthy';
        health.status = 'degraded';
      }
    } catch (error) {
      health.services.user_management = 'unhealthy';
      health.status = 'degraded';
      console.error('User Management Worker health check failed:', error);
    }
  } else {
    health.services.user_management = 'skipped';
  }

  try {
    // Test Cloudflare send_email binding configuration
    if (env.send_email && typeof env.send_email.send === 'function') {
      health.services.email = 'healthy';
    } else {
      health.services.email = 'unhealthy';
      health.status = 'degraded';
    }
  } catch (error) {
    health.services.email = 'unhealthy';
    health.status = 'degraded';
    console.error('Email binding configuration check failed:', error);
  }

  // Determine overall health
  const unhealthyServices = Object.values(health.services).filter(status => status === 'unhealthy');
  if (unhealthyServices.length === Object.keys(health.services).length) {
    health.status = 'unhealthy';
  }

  const statusCode = health.status === 'healthy' ? 200 : 
                     health.status === 'degraded' ? 503 : 500;

  return c.json(health, statusCode);
});

// OTP Endpoints

// Generate and store OTP
app.post('/otp/generate', async (c) => {
  try {
    const body = await c.req.json();
    const { email } = body;

    if (!email || typeof email !== 'string') {
      return c.json({
        success: false,
        message: 'Email is required and must be a string'
      }, 400);
    }

    // Check if OTP already exists
    const existingOTP = await hasOTP(c.env.OTP_KV, email);
    if (existingOTP) {
      return c.json({
        success: false,
        message: 'OTP already exists for this email. Please wait for it to expire or verify it first.'
      }, 409);
    }

    const result = await storeOTP(c.env.OTP_KV, email);
    
    if (result.success) {
      // Always send verification email (security best practice)
      let emailSent = false;
      if (result.otp) {
        try {
          const emailService = new EmailService(c.env);
          const emailResult = await emailService.sendVerificationEmail(email, result.otp, 10);
          
          if (emailResult.success) {
            emailSent = true;
            console.log('Verification email sent successfully:', emailResult.messageId);
          } else {
            console.error('Failed to send verification email:', emailResult.error);
            // Don't fail the OTP generation if email fails, but log it
          }
        } catch (emailError) {
          console.error('Error sending verification email:', emailError);
          // Don't fail the OTP generation if email fails
        }
      }

      return c.json({
        success: true,
        message: 'OTP generated successfully. Please check your email for the verification code.',
        emailSent: emailSent
      });
    } else {
      return c.json({
        success: false,
        message: result.message
      }, 500);
    }
  } catch (error) {
    console.error('Error generating OTP:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Verify OTP
app.post('/otp/verify', async (c) => {
  try {
    const body = await c.req.json();
    const { email, otp } = body;

    if (!email || typeof email !== 'string') {
      return c.json({
        success: false,
        message: 'Email is required and must be a string'
      }, 400);
    }

    if (!otp || typeof otp !== 'string') {
      return c.json({
        success: false,
        message: 'OTP is required and must be a string'
      }, 400);
    }

    const result = await verifyOTPForEmail(c.env.OTP_KV, email, otp);
    
    if (result.success) {
      // Generate JWT token for successful authentication (always do this first)
      let jwtToken = null;
      try {
        if (result.user_id) {
          const { JWTService } = await import('./services/jwt-service');
          const jwtService = new JWTService(c.env);
          
          // Create token with 7 day expiration
          const tokenResult = await jwtService.createToken(result.user_id, email, 604800);
          
          if (tokenResult.success && tokenResult.token) {
            jwtToken = tokenResult.token;
          } else {
            console.error('Failed to generate JWT token:', tokenResult.error);
          }
        } else {
          console.error('No user_id returned from OTP verification');
        }
      } catch (jwtError) {
        console.error('Error generating JWT token:', jwtError);
      }

      // Fire-and-forget: identify user in Flaggly for allowed-users flag evaluation (non-blocking)
      if (result.user_id) {
        void identifyUser(c.env, result.user_id, email);
      }

      if (result.user_id) {
        await recordLogin(c.env, {
          userId: result.user_id,
          email,
          method: 'OTP',
          ipAddress: c.req.header('CF-Connecting-IP'),
          userAgent: c.req.header('User-Agent'),
        });
      } else {
        console.error('No user_id returned from OTP verification');
      }

      // Return success response with JWT token if available
      if (jwtToken) {
        return c.json({
          success: true,
          message: 'OTP verified successfully',
          token: jwtToken,
          expiresIn: 604800,
          user: {
            id: result.user_id,
            email: email
          }
        }, 200);
      } else {
        // Fall back to success without token
        return c.json({
          success: true,
          message: 'OTP verified successfully',
          user: {
            id: result.user_id,
            email: email
          }
        }, 200);
      }
    }
    
    // If OTP verification failed, return the original result
    const statusCode = result.success ? 200 : 400;
    return c.json(result, statusCode);
  } catch (error) {
    console.error('Error verifying OTP:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Refresh JWT token
app.post('/auth/refresh', async (c) => {
  try {
    const body = await c.req.json();
    const { token } = body;

    if (!token || typeof token !== 'string') {
      return c.json({
        success: false,
        message: 'Token is required and must be a string'
      }, 400);
    }

    try {
      const { JWTService } = await import('./services/jwt-service');
      const jwtService = new JWTService(c.env);
      
      // Verify the existing token
      const verifyResult = await jwtService.verifyToken(token);
      
      if (!verifyResult.success || !verifyResult.payload) {
        return c.json({
          success: false,
          message: verifyResult.error || 'Invalid token'
        }, 400);
      }

      // Create a new token with extended expiration (sliding window — refresh any valid token)
      const newTokenResult = await jwtService.createToken(
        verifyResult.payload.sub,
        verifyResult.payload.email,
        604800 // 7 days
      );

      if (newTokenResult.success && newTokenResult.token) {
        return c.json({
          success: true,
          message: 'Token refreshed successfully',
          token: newTokenResult.token,
          expiresIn: 604800,
          user: {
            id: verifyResult.payload.sub,
            email: verifyResult.payload.email
          }
        });
      } else {
        return c.json({
          success: false,
          message: 'Failed to refresh token'
        }, 500);
      }
    } catch (jwtError) {
      console.error('Error refreshing JWT token:', jwtError);
      return c.json({
        success: false,
        message: 'Token refresh failed'
      }, 500);
    }
  } catch (error) {
    console.error('Error in token refresh endpoint:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Validate JWT token
app.post('/auth/validate', async (c) => {
  try {
    const body = await c.req.json();
    const { token } = body;

    if (!token || typeof token !== 'string') {
      return c.json({
        success: false,
        message: 'Token is required and must be a string'
      }, 400);
    }

    try {
      const { JWTService } = await import('./services/jwt-service');
      const jwtService = new JWTService(c.env);
      
      const result = await jwtService.verifyToken(token);
      
      if (result.success && result.payload) {
        return c.json({
          success: true,
          valid: true,
          user: {
            id: result.payload.sub,
            email: result.payload.email
          },
          expiresAt: result.payload.exp,
          timeUntilExpiration: jwtService.getTimeUntilExpiration(result.payload)
        });
      } else {
        return c.json({
          success: false,
          valid: false,
          message: result.error || 'Invalid token'
        });
      }
    } catch (jwtError) {
      console.error('Error validating JWT token:', jwtError);
      return c.json({
        success: false,
        valid: false,
        message: 'Token validation failed'
      });
    }
  } catch (error) {
    console.error('Error in token validation endpoint:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Check OTP status
app.get('/otp/status/:email', async (c) => {
  try {
    const email = c.req.param('email');

    if (!email) {
      return c.json({
        success: false,
        message: 'Email parameter is required'
      }, 400);
    }

    const stats = await getOTPStats(c.env.OTP_KV, email);
    
    return c.json({
      success: true,
      exists: stats.exists,
      attempts: stats.attempts,
      expiresAt: stats.expiresAt
    });
  } catch (error) {
    console.error('Error getting OTP status:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Delete OTP (admin/cleanup endpoint)
app.delete('/otp/:email', async (c) => {
  try {
    const email = c.req.param('email');

    if (!email) {
      return c.json({
        success: false,
        message: 'Email parameter is required'
      }, 400);
    }

    const deleted = await deleteOTP(c.env.OTP_KV, email);
    
    return c.json({
      success: deleted,
      message: deleted ? 'OTP deleted successfully' : 'Failed to delete OTP'
    });
  } catch (error) {
    console.error('Error deleting OTP:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Send verification email manually
app.post('/email/send-verification', async (c) => {
  try {
    const body = await c.req.json();
    const { email, otp, expiryMinutes = 10 } = body;

    console.log('📧 Email verification request:', { email, otp, expiryMinutes });

    if (!email || typeof email !== 'string') {
      return c.json({
        success: false,
        message: 'Email is required and must be a string'
      }, 400);
    }

    if (!otp || typeof otp !== 'string') {
      return c.json({
        success: false,
        message: 'OTP is required and must be a string'
      }, 400);
    }

    console.log('✅ Request validation passed, calling email service with email:', email);

    const emailService = new EmailService(c.env);
    const result = await emailService.sendVerificationEmail(email, otp, expiryMinutes);
    
    if (result.success) {
      return c.json({
        success: true,
        message: 'Verification email sent successfully',
        messageId: result.messageId
      });
    } else {
      return c.json({
        success: false,
        message: 'Failed to send verification email',
        error: result.error
      }, 500);
    }
  } catch (error) {
    console.error('Error sending verification email:', error);
    return c.json({
      success: false,
      message: 'Internal server error'
    }, 500);
  }
});

// Passkey (WebAuthn) endpoints

// Begin passkey registration — requires an authenticated user (OTP-issued JWT).
app.post('/passkey/register/options', requireAuth, async (c) => {
  try {
    const userId = c.get('userId');
    const email = c.get('email');

    const existing = await listUserCredentials(c.env.OTP_KV, userId);
    const passkeyService = new PasskeyService(c.env);
    const { options, challenge } = await passkeyService.generateRegistration(
      userId,
      email,
      existing.map((cred) => ({ id: cred.credentialId, transports: cred.transports }))
    );

    await storeRegChallenge(c.env.OTP_KV, {
      challenge,
      userId,
      email,
      createdAt: Date.now(),
    });

    return c.json({ success: true, options });
  } catch (error) {
    console.error('Error generating passkey registration options:', error);
    return c.json({ success: false, message: 'Failed to generate registration options' }, 500);
  }
});

// Complete passkey registration — requires the same authenticated user.
app.post('/passkey/register/verify', requireAuth, async (c) => {
  try {
    const userId = c.get('userId');
    const email = c.get('email');

    const body = await c.req.json().catch(() => null) as
      | { response?: unknown; name?: unknown }
      | null;
    if (!body || typeof body.response !== 'object' || body.response === null) {
      return c.json({ success: false, message: 'response is required' }, 400);
    }
    const name = typeof body.name === 'string' && body.name.trim()
      ? body.name.trim()
      : `Passkey ${new Date().toISOString().slice(0, 10)}`;

    const challengeRecord = await consumeRegChallenge(c.env.OTP_KV, userId);
    if (!challengeRecord) {
      return c.json({ success: false, message: 'Registration challenge not found or expired' }, 400);
    }

    const passkeyService = new PasskeyService(c.env);
    const result = await passkeyService.verifyRegistration(
      body.response as Parameters<typeof passkeyService.verifyRegistration>[0],
      challengeRecord.challenge
    );

    if (
      !result.verified ||
      !result.credentialId ||
      !result.publicKey ||
      result.counter === undefined ||
      !result.deviceType ||
      result.backedUp === undefined
    ) {
      return c.json({ success: false, message: 'Passkey registration could not be verified' }, 400);
    }

    const record: CredentialRecord = {
      credentialId: result.credentialId,
      userId,
      email,
      publicKey: result.publicKey,
      counter: result.counter,
      transports: result.transports ?? [],
      deviceType: result.deviceType,
      backedUp: result.backedUp,
      name,
      createdAt: Date.now(),
    };

    await saveCredential(c.env.OTP_KV, record);

    return c.json({
      success: true,
      message: 'Passkey registered successfully',
      credential: {
        credentialId: record.credentialId,
        name: record.name,
        createdAt: record.createdAt,
      },
    });
  } catch (error) {
    console.error('Error verifying passkey registration:', error);
    return c.json({ success: false, message: 'Failed to verify passkey registration' }, 500);
  }
});

// Begin passkey authentication (no auth required — user is proving identity).
app.post('/passkey/authenticate/options', async (c) => {
  try {
    const body = await c.req.json().catch(() => ({})) as { email?: unknown };
    const email = typeof body.email === 'string' ? body.email.trim() : undefined;

    let allowCredentialIds: string[] = [];
    let allowCredentials: { id: string; transports?: CredentialRecord['transports'] }[] | undefined;

    if (email) {
      const { hashEmail } = await import('./utils/crypto');
      const userId = await hashEmail(email);
      const creds = await listUserCredentials(c.env.OTP_KV, userId);
      allowCredentialIds = creds.map((cred) => cred.credentialId);
      allowCredentials = creds.map((cred) => ({
        id: cred.credentialId,
        transports: cred.transports,
      }));
    }

    const passkeyService = new PasskeyService(c.env);
    const { options, challenge } = await passkeyService.generateAuthentication(allowCredentials);

    const sessionId = generateSecureToken(16);
    await storeAuthChallenge(c.env.OTP_KV, sessionId, {
      challenge,
      allowCredentialIds,
      email,
      createdAt: Date.now(),
    });

    return c.json({ success: true, sessionId, options });
  } catch (error) {
    console.error('Error generating passkey authentication options:', error);
    return c.json({ success: false, message: 'Failed to generate authentication options' }, 500);
  }
});

// Complete passkey authentication → returns JWT on success.
app.post('/passkey/authenticate/verify', async (c) => {
  try {
    const body = await c.req.json().catch(() => null) as
      | { sessionId?: unknown; response?: unknown }
      | null;
    if (!body || typeof body.sessionId !== 'string' || typeof body.response !== 'object' || body.response === null) {
      return c.json({ success: false, message: 'sessionId and response are required' }, 400);
    }

    const challengeRecord = await consumeAuthChallenge(c.env.OTP_KV, body.sessionId);
    if (!challengeRecord) {
      return c.json({ success: false, message: 'Authentication challenge not found or expired' }, 400);
    }

    const assertion = body.response as { id?: unknown };
    if (typeof assertion.id !== 'string' || !assertion.id) {
      return c.json({ success: false, message: 'Invalid authentication response' }, 400);
    }

    if (
      challengeRecord.allowCredentialIds.length > 0 &&
      !challengeRecord.allowCredentialIds.includes(assertion.id)
    ) {
      return c.json({ success: false, message: 'Credential not allowed for this session' }, 400);
    }

    const credential = await getCredential(c.env.OTP_KV, assertion.id);
    if (!credential) {
      return c.json({ success: false, message: 'Credential not found' }, 404);
    }

    const passkeyService = new PasskeyService(c.env);
    const result = await passkeyService.verifyAuthentication(
      body.response as Parameters<typeof passkeyService.verifyAuthentication>[0],
      challengeRecord.challenge,
      credential
    );

    if (!result.verified || result.newCounter === undefined) {
      return c.json({ success: false, message: 'Passkey authentication failed' }, 401);
    }

    await updateCredentialCounter(c.env.OTP_KV, credential.credentialId, result.newCounter, Date.now());

    const { JWTService } = await import('./services/jwt-service');
    const jwtService = new JWTService(c.env);
    const tokenResult = await jwtService.createToken(credential.userId, credential.email, 604800);
    if (!tokenResult.success || !tokenResult.token) {
      console.error('Failed to generate JWT token after passkey auth:', tokenResult.error);
      return c.json({ success: false, message: 'Authentication succeeded but token issuance failed' }, 500);
    }

    void identifyUser(c.env, credential.userId, credential.email);
    await recordLogin(c.env, {
      userId: credential.userId,
      email: credential.email,
      method: 'PASSKEY',
      ipAddress: c.req.header('CF-Connecting-IP'),
      userAgent: c.req.header('User-Agent'),
    });

    return c.json({
      success: true,
      message: 'Passkey authentication successful',
      token: tokenResult.token,
      expiresIn: 604800,
      user: { id: credential.userId, email: credential.email },
    });
  } catch (error) {
    console.error('Error verifying passkey authentication:', error);
    return c.json({ success: false, message: 'Failed to verify passkey authentication' }, 500);
  }
});

// List the authenticated user's registered passkeys.
app.get('/passkey/list', requireAuth, async (c) => {
  try {
    const userId = c.get('userId');
    const credentials = await listUserCredentials(c.env.OTP_KV, userId);
    return c.json({
      success: true,
      credentials: credentials.map((cred) => ({
        credentialId: cred.credentialId,
        name: cred.name,
        createdAt: cred.createdAt,
        lastUsedAt: cred.lastUsedAt,
        deviceType: cred.deviceType,
        backedUp: cred.backedUp,
      })),
    });
  } catch (error) {
    console.error('Error listing passkeys:', error);
    return c.json({ success: false, message: 'Failed to list passkeys' }, 500);
  }
});

// Delete a registered passkey (owner only).
app.delete('/passkey/:credentialId', requireAuth, async (c) => {
  try {
    const credentialId = c.req.param('credentialId');
    if (!credentialId) {
      return c.json({ success: false, message: 'credentialId is required' }, 400);
    }

    const userId = c.get('userId');
    const deleted = await deleteCredential(c.env.OTP_KV, userId, credentialId);
    if (!deleted) {
      return c.json({ success: false, message: 'Passkey not found' }, 404);
    }

    return c.json({ success: true, message: 'Passkey deleted successfully' });
  } catch (error) {
    console.error('Error deleting passkey:', error);
    return c.json({ success: false, message: 'Failed to delete passkey' }, 500);
  }
});

// Root endpoint
app.get('/', (c) => {
  return c.json({
    name: 'auth-worker',
    version: '1.0.0',
    endpoints: [
      {
        path: '/health',
        method: 'GET',
        description: 'Health check endpoint'
      },
      {
        path: '/otp/generate',
        method: 'POST',
        description: 'Generate and store OTP for email',
        body: { email: 'string' }
      },
      {
        path: '/otp/verify',
        method: 'POST',
        description: 'Verify OTP for email',
        body: { email: 'string', otp: 'string' }
      },
      {
        path: '/otp/status/:email',
        method: 'GET',
        description: 'Get OTP status for email'
      },
      {
        path: '/otp/:email',
        method: 'DELETE',
        description: 'Delete OTP for email (admin endpoint)'
      },
      {
        path: '/email/send-verification',
        method: 'POST',
        description: 'Send verification email manually',
        body: { email: 'string', otp: 'string', expiryMinutes: 'number (optional)' }
      },
      {
        path: '/auth/validate',
        method: 'POST',
        description: 'Validate JWT',
        body: { token: 'string' }
      },
      {
        path: '/auth/refresh',
        method: 'POST',
        description: 'Refresh JWT',
        body: { token: 'string' }
      },
      {
        path: '/passkey/register/options',
        method: 'POST',
        description: 'Begin passkey registration (requires Authorization: Bearer <JWT>)'
      },
      {
        path: '/passkey/register/verify',
        method: 'POST',
        description: 'Complete passkey registration (requires Authorization: Bearer <JWT>)',
        body: { response: 'RegistrationResponseJSON', name: 'string (optional)' }
      },
      {
        path: '/passkey/authenticate/options',
        method: 'POST',
        description: 'Begin passkey authentication; returns sessionId + options',
        body: { email: 'string (optional)' }
      },
      {
        path: '/passkey/authenticate/verify',
        method: 'POST',
        description: 'Complete passkey authentication; returns JWT on success',
        body: { sessionId: 'string', response: 'AuthenticationResponseJSON' }
      },
      {
        path: '/passkey/list',
        method: 'GET',
        description: "List the authenticated user's passkeys (requires Authorization: Bearer <JWT>)"
      },
      {
        path: '/passkey/:credentialId',
        method: 'DELETE',
        description: 'Delete a passkey owned by the authenticated user (requires Authorization: Bearer <JWT>)'
      }
    ]
  });
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not Found',
    message: `The requested endpoint ${c.req.path} does not exist`
  }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error(`Error handling request: ${err}`);
  return c.json({
    error: 'Internal Server Error',
    message: err.message || 'An unexpected error occurred'
  }, 500);
});

export default app;