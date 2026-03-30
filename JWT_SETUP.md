# JWT Authentication Setup Guide

This guide explains how to set up and use JWT (JSON Web Token) authentication in the auth-worker.

## 🔐 Overview

The auth-worker now includes JWT functionality that provides secure authentication tokens when OTPs are verified. This enables:

- **Stateless Authentication**: No need to store session data on the server
- **Secure API Access**: Other services can validate tokens to verify user identity
- **Token Refresh**: Users can extend their session without re-authentication
- **Audit Trail**: Each token has a unique identifier for tracking

## 🚀 Features

### 1. **OTP + JWT Flow**
- User requests OTP via email
- User verifies OTP
- System returns JWT token upon successful verification
- Token contains user ID, email, and expiration information

### 2. **JWT Endpoints**
- `POST /otp/verify` - Returns JWT token after OTP verification
- `POST /auth/validate` - Validates JWT tokens
- `POST /auth/refresh` - Refreshes tokens close to expiration

### 3. **Security Features**
- HS256 algorithm for signing
- Configurable expiration times
- Unique JWT IDs (JTI) for each token
- Issuer and audience validation
- Automatic token expiration

## ⚙️ Setup Instructions

### Step 1: Install Dependencies

The JWT functionality requires the `jose` library, which is already included in `package.json`:

```bash
npm install
```

### Step 2: Configure JWT Secret

**IMPORTANT**: You must set a strong JWT secret as a Cloudflare secret. This should be a random string of at least 32 characters.

```bash
# Generate a strong secret (example)
openssl rand -base64 32

# Set the secret in Cloudflare
wrangler secret put JWT_SECRET
```

When prompted, enter your generated secret.

### Step 3: Deploy the Worker

```bash
npm run deploy
# or: wrangler deploy
```

## 🔑 JWT Configuration

### Environment Variables

Set in `wrangler.toml` under `[vars]` (and match your deployed URL):

- **Issuer** (`JWT_ISSUER`): e.g. `https://YOUR_AUTH_WORKER.workers.dev`
- **Audience** (`JWT_AUDIENCE`): your app identifier (e.g. `my-app`)
- **Algorithm**: HS256
- **Default token TTL** in code paths: 24h generate / 7d post-OTP verify (see `index.ts`)

### JWT Payload Structure

```json
{
  "sub": "user-id-hash",
  "email": "user@example.com",
  "iat": 1640995200,
  "exp": 1641081600,
  "jti": "unique-token-id",
  "aud": "my-app",
  "iss": "https://YOUR_AUTH_WORKER.workers.dev"
}
```

## 📡 API Usage

### 1. **Generate OTP and Get JWT**

```bash
# Step 1: Generate OTP
curl -X POST https://YOUR_AUTH_WORKER.workers.dev/otp/generate \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Step 2: Verify OTP (returns JWT)
curl -X POST https://YOUR_AUTH_WORKER.workers.dev/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "otp": "123456"}'
```

**Response:**
```json
{
  "success": true,
  "message": "OTP verified successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 86400,
  "user": {
    "id": "user-id-hash",
    "email": "user@example.com"
  }
}
```

### 2. **Validate JWT Token**

```bash
curl -X POST https://YOUR_AUTH_WORKER.workers.dev/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

**Response:**
```json
{
  "success": true,
  "valid": true,
  "user": {
    "id": "user-id-hash",
    "email": "user@example.com"
  },
  "expiresAt": 1641081600,
  "timeUntilExpiration": 86399
}
```

### 3. **Refresh JWT Token**

```bash
curl -X POST https://YOUR_AUTH_WORKER.workers.dev/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

**Response:**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 86400,
  "user": {
    "id": "user-id-hash",
    "email": "user@example.com"
  }
}
```

## 🛡️ Security Best Practices

### 1. **JWT Secret Management**
- Use a strong, random secret (at least 32 characters)
- Store as Cloudflare secret, never in code
- Rotate secrets periodically in production

### 2. **Token Validation**
- Always validate tokens on the server side
- Check expiration times
- Verify issuer and audience claims
- Use HTTPS for all API calls

### 3. **Token Storage**
- Store tokens securely on the client side
- Use HttpOnly cookies when possible
- Implement token refresh logic
- Clear tokens on logout

### 4. **Error Handling**
- Handle token expiration gracefully
- Implement automatic token refresh
- Log authentication failures for monitoring

## 🔍 Integration Examples

### Frontend Integration (JavaScript)

```javascript
class AuthService {
  constructor() {
    this.baseUrl = 'https://YOUR_AUTH_WORKER.workers.dev';
    this.token = localStorage.getItem('auth_token');
  }

  async login(email) {
    // Step 1: Generate OTP
    const otpResponse = await fetch(`${this.baseUrl}/otp/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    
    if (!otpResponse.ok) {
      throw new Error('Failed to generate OTP');
    }
    
    // Step 2: User enters OTP (implement UI for this)
    const otp = prompt('Enter the OTP sent to your email:');
    
    // Step 3: Verify OTP and get JWT
    const verifyResponse = await fetch(`${this.baseUrl}/otp/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp })
    });
    
    const result = await verifyResponse.json();
    
    if (result.success && result.token) {
      this.token = result.token;
      localStorage.setItem('auth_token', result.token);
      return result.user;
    } else {
      throw new Error('Authentication failed');
    }
  }

  async validateToken() {
    if (!this.token) return false;
    
    const response = await fetch(`${this.baseUrl}/auth/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: this.token })
    });
    
    const result = await response.json();
    return result.success && result.valid;
  }

  async refreshToken() {
    if (!this.token) return false;
    
    const response = await fetch(`${this.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: this.token })
    });
    
    const result = await response.json();
    
    if (result.success && result.token) {
      this.token = result.token;
      localStorage.setItem('auth_token', result.token);
      return true;
    }
    
    return false;
  }

  logout() {
    this.token = null;
    localStorage.removeItem('auth_token');
  }
}
```

### Backend Integration (Node.js)

```javascript
const jwt = require('jsonwebtoken');

class AuthMiddleware {
  constructor(jwtSecret) {
    this.jwtSecret = jwtSecret;
  }

  async authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    
    try {
      // Validate token with auth-worker
      const response = await fetch('https://YOUR_AUTH_WORKER.workers.dev/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      
      const result = await response.json();
      
      if (result.success && result.valid) {
        req.user = result.user;
        next();
      } else {
        return res.status(401).json({ error: 'Invalid token' });
      }
    } catch (error) {
      return res.status(500).json({ error: 'Token validation failed' });
    }
  }
}

// Usage in Express
const authMiddleware = new AuthMiddleware(process.env.JWT_SECRET);

app.get('/protected', authMiddleware.authenticate, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});
```

## 🧪 Testing

### Run JWT Tests

```bash
# Run all JWT-related tests
npm test -- tests/jwt-service.test.ts
npm test -- tests/unit/jwt-endpoints.test.ts

# Run all tests
npm test
```

### Test JWT Endpoints

```bash
# Test token validation
curl -X POST https://YOUR_AUTH_WORKER.workers.dev/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "your-jwt-token"}'

# Test token refresh
curl -X POST https://YOUR_AUTH_WORKER.workers.dev/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"token": "your-jwt-token"}'
```

## 🚨 Troubleshooting

### Common Issues

1. **"JWT_SECRET not configured"**
   - Set the JWT_SECRET using `wrangler secret put JWT_SECRET`
   - Ensure the secret is at least 32 characters long

2. **"Invalid or expired authentication token"**
   - Check if the token has expired
   - Verify the token format
   - Ensure the token was issued by this auth-worker

3. **"Token is not close to expiration yet"**
   - Tokens can only be refreshed when within 1 hour of expiration
   - This is a security feature to prevent unnecessary token generation

### Debug Mode

Enable debug logging by setting the environment to development:

```bash
wrangler dev --env preview
```

Check the console output for detailed error messages.

## 📚 Additional Resources

- [JWT.io](https://jwt.io/) - JWT debugger and documentation
- [jose Library Documentation](https://github.com/panva/jose) - JWT library used
- [Cloudflare Workers Secrets](https://developers.cloudflare.com/workers/platform/environment-variables/manage-secrets/) - Managing secrets

## 🔄 Updates and Maintenance

### Token Expiration Management
- Monitor token expiration patterns
- Adjust default expiration times based on security requirements
- Implement automatic cleanup of expired tokens

### Security Audits
- Regularly review JWT implementation
- Monitor for security vulnerabilities
- Update dependencies as needed

### Performance Monitoring
- Track JWT validation performance
- Monitor token refresh patterns
- Optimize based on usage data

---

For questions or issues, please refer to the project documentation or create an issue in the repository.
