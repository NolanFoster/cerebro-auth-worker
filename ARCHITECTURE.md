# Authentication System Architecture

This worker implements OTP (one-time password) email verification and JWT issuance on Cloudflare Workers, with optional hooks to a separate user-management service.

## System Overview

```mermaid
graph TB
    subgraph "Client Layer"
        A[Frontend App]
        B[Mobile App]
        C[Browser Extension]
    end
    
    subgraph "Authentication Layer"
        D[Auth Worker]
        E[OTP KV Storage]
        F[Cloudflare Email Service]
    end
    
    subgraph "User Management Layer"
        G[User Management Worker]
        H[User Database D1]
    end
    
    subgraph "Application Layer"
        I[Recipe Workers]
        J[Recipe Database D1]
    end
    
    A --> D
    B --> D
    C --> D
    D --> E
    D --> F
    D --> G
    G --> H
    I --> G
    I --> J
    
    style D fill:#e1f5fe
    style E fill:#f3e5f5
    style G fill:#e8f5e8
    style H fill:#fff3e0
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant A as Auth Worker
    participant K as OTP KV
    participant S as Email Service
    participant UMW as User Management Worker
    participant DB as User Database
    
    Note over U,DB: OTP Generation Flow
    U->>F: Request OTP for email
    F->>A: POST /otp/generate
    A->>A: Generate secure OTP
    A->>A: Hash OTP with salt
    A->>K: Store hashed OTP with TTL
    A->>S: Send OTP via email
    S-->>U: Email with OTP
    A-->>F: Success response
    
    Note over U,DB: OTP Verification Flow
    U->>F: Submit OTP
    F->>A: POST /otp/verify
    A->>K: Retrieve hashed OTP
    A->>A: Verify OTP hash
    alt OTP Valid
        A->>K: Delete OTP
        A->>UMW: Create/update user
        UMW->>DB: Store user data
        UMW-->>A: User ID
        A-->>F: Authentication success + JWT
        F-->>U: Logged in
    else OTP Invalid
        A-->>F: Authentication failed
        F-->>U: Error message
    end
```

## Security Architecture

```mermaid
graph LR
    subgraph "Security Layers"
        A[Rate Limiting]
        B[OTP Hashing]
        C[TTL Expiration]
        D[Secure Cleanup]
    end
    
    subgraph "Data Protection"
        E[No Password Storage]
        F[Email Hashing]
        G[Salt Generation]
        H[Secure Communication]
    end
    
    subgraph "Integration Security"
        I[HTTPS Only]
        J[Worker-to-Worker Auth]
        K[Environment Isolation]
    end
    
    A --> B
    B --> C
    C --> D
    E --> F
    F --> G
    G --> H
    I --> J
    J --> K
    
    style A fill:#ffebee
    style B fill:#ffebee
    style C fill:#ffebee
    style D fill:#ffebee
    style E fill:#e8f5e8
    style F fill:#e8f5e8
    style G fill:#e8f5e8
    style H fill:#e8f5e8
    style I fill:#e3f2fd
    style J fill:#e3f2fd
    style K fill:#e3f2fd
```

## Key Components

### 1. **Auth Worker** (`auth-worker/`)
- **Purpose**: Handles all authentication operations
- **Responsibilities**:
  - OTP generation and verification
  - Rate limiting and security
  - Integration with User Management Worker
  - Email delivery via Cloudflare Email Workers
- **Technologies**: Cloudflare Workers, Hono.js, KV Storage

### 2. **OTP Management System**
- **Storage**: Cloudflare KV with automatic TTL
- **Security**: SHA-256 hashing with unique salts
- **Expiration**: 5-minute TTL with automatic cleanup
- **Rate Limiting**: 3 attempts per OTP with cooldown

### 3. **User Management Integration**
- **Separation**: Auth Worker never directly accesses user database
- **Communication**: HTTP calls to User Management Worker
- **Operations**: User creation, login tracking, profile updates
- **Security**: Environment-specific URLs and authentication

### 4. **Email Service Integration**
- **Provider**: Cloudflare Email Workers send_email binding
- **Templates**: Professional OTP delivery emails
- **Fallback**: Graceful degradation if email service unavailable
- **Security**: No sensitive data in email content

## Data Flow Architecture

```mermaid
flowchart TD
    A[User Request] --> B{{Request Type?}}
    
    B -->|Generate OTP| C[Validate Email]
    B -->|Verify OTP| D[Retrieve OTP Hash]
    
    C --> E[Generate Secure OTP]
    E --> F[Hash with Salt]
    F --> G[Store in KV with TTL]
    G --> H[Send via Cloudflare Email]
    H --> I[Return Success]
    
    D --> J{{OTP Exists?}}
    J -->|No| K[Return Error]
    J -->|Yes| L{{Expired?}}
    L -->|Yes| M[Cleanup & Error]
    L -->|No| N{{Attempts Exceeded?}}
    N -->|Yes| O[Return Rate Limited]
    N -->|No| P[Verify Hash]
    P --> Q{{Valid?}}
    Q -->|No| R[Increment Attempts]
    Q -->|Yes| S[Delete OTP]
    S --> T[Call User Management Worker]
    T --> U[Create/Update User]
    U --> V[Return JWT Token]
    
    R --> W[Return Error]
    M --> W
    O --> W
    K --> W
    
    I --> X[End]
    V --> X
    W --> X
```

## Environment Configuration

The auth worker supports multiple deployment environments:

```mermaid
graph TB
    subgraph "Environments"
        A[Preview]
        B[Staging]
        C[Production]
    end
    
    subgraph "Configuration"
        D[KV Namespaces]
        E[Worker URLs]
        F[Email Settings]
        G[Rate Limits]
    end
    
    A --> D
    B --> D
    C --> D
    
    A --> E
    B --> E
    C --> E
    
    A --> F
    B --> F
    C --> F
    
    A --> G
    B --> G
    C --> G
    
    style A fill:#fff3e0
    style B fill:#e8f5e8
    style C fill:#ffebee
```

## API Endpoints

| Endpoint | Method | Purpose | Request Body | Response |
|----------|--------|---------|--------------|----------|
| `/health` | GET | Service health check | None | Health status |
| `/otp/generate` | POST | Generate OTP | `{email: string}` | `{success: boolean, otp?: string}` |
| `/otp/verify` | POST | Verify OTP | `{email: string, otp: string}` | `{success: boolean, user_id?: string}` |

## Security Features

1. **OTP Security**
   - 6-digit numeric OTPs
   - SHA-256 hashing with unique salts
   - 5-minute expiration with automatic cleanup
   - Rate limiting (3 attempts per OTP)

2. **Data Protection**
   - No password storage
   - Email addresses hashed in KV keys
   - Secure worker-to-worker communication
   - Environment isolation

3. **Operational Security**
   - Comprehensive health monitoring
   - Automatic error handling and logging
   - Graceful degradation for service failures
   - Audit trail for authentication events

## Monitoring and Observability

```mermaid
graph LR
    subgraph "Health Checks"
        A[KV Connectivity]
        B[User Management Worker]
        C[Email Binding Configuration]
        D[Overall Status]
    end
    
    subgraph "Metrics"
        E[OTP Generation Rate]
        F[Verification Success Rate]
        G[Rate Limiting Events]
        H[Service Response Times]
    end
    
    subgraph "Logging"
        I[Authentication Events]
        J[Error Tracking]
        K[Performance Metrics]
        L[Security Events]
    end
    
    A --> D
    B --> D
    C --> D
    
    E --> K
    F --> K
    G --> K
    H --> K
    
    I --> J
    J --> L
    K --> L
```

This authentication architecture provides a secure, scalable, and maintainable solution for user authentication while maintaining clean separation of concerns and following security best practices.