# SecureShare - Secure File Sharing System

## 📋 Project Overview

พัฒนา/ต่อยอดจากโปรเจกต์ต้นทาง: [lXsaraXl/securefilesharing](https://github.com/lXsaraXl/securefilesharing/tree/main)

**SecureShare** is a web-based secure file-sharing system built for educational purposes as a graduation project. It demonstrates enterprise-grade security features including AES-256 encryption, RSA key exchange, multi-factor authentication, and role-based access control.

## 🔐 Security Features

### 1. AES-256 Encryption
- **Purpose**: Protects file content from unauthorized access
- **Implementation**: New uploads use **AES-256-GCM** (authenticated encryption). Legacy data may still be **AES-256-CBC**.
- **Process**:
  - Generate random 256-bit AES key for each file
  - Encrypt file content with AES-256
  - Store encrypted data in MongoDB
  - File content is never stored in plain text

### 2. RSA Encryption (2048-bit)
- **Purpose**: Secure key exchange mechanism
- **Implementation**: 
  - Each user receives an RSA keypair (public/private) on registration
  - AES keys are encrypted with user's RSA public key
  - Only the user's private key can decrypt the AES key
  - Enables secure file sharing without exposing encryption keys

### 3. Multi-Factor Authentication (MFA)
- **Type**: Email-based OTP (One-Time Password)
- **Implementation**:
  - 6-digit OTP generated on login
  - OTP expires after 5 minutes
  - OTP is sent to the user's email via SMTP
  - OTP is hashed before being stored in MongoDB
  - Resend requests are rate-limited with cooldown protection
  - Failed OTP attempts are capped before forcing a new login
- **Security**: Prevents unauthorized access even with compromised passwords

### 4. Role-Based Access Control (RBAC)
- **Roles**:
  - **User**: Can upload, download, share, and delete own files
  - **Admin**: All user permissions + access to user management and audit logs
- **Enforcement**: JWT token-based authentication with role validation

### 5. Cryptographic Hashing (SHA-256)
- **Purpose**: File integrity verification
- **Implementation**:
  - SHA-256 hash computed before encryption
  - Hash stored with file metadata
  - Verified on download to detect tampering
  - Ensures data integrity throughout lifecycle

## 🏗️ System Architecture

### Technology Stack
- **Backend**: FastAPI (Python)
- **Frontend**: React with professional UI components
- **Database**: MongoDB
- **Cryptography**: Python `cryptography` library
- **Authentication**: JWT (JSON Web Tokens) with bcrypt password hashing

### Database Collections

#### 1. Users Collection
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "full_name": "User Name",
  "role": "user|admin",
  "password_hash": "bcrypt_hash",
  "public_key": "RSA_public_key_PEM",
  "private_key": "RSA_private_key_PEM",
  "created_at": "ISO_datetime"
}
```

#### 2. Files Collection
```json
{
  "id": "uuid",
  "filename": "document.pdf",
  "original_hash": "sha256_hash",
  "encrypted_data": "base64_encrypted_content",
  "encrypted_key": "base64_rsa_encrypted_aes_key",
  "encryption_mode": "cbc|gcm",
  "owner_id": "owner_uuid",
  "owner_email": "owner@example.com",
  "size": 1024,
  "shared_with": ["user1@example.com", "user2@example.com"],
  "uploaded_at": "ISO_datetime"
}
```

#### 5. File Permissions Collection (Per-file RBAC)

```json
{
  "id": "uuid",
  "file_id": "file_uuid",
  "user_email": "user@example.com",
  "role": "owner|editor|viewer",
  "granted_by": "owner@example.com",
  "created_at": "ISO_datetime"
}
```

#### 6. Share Links Collection (Temporary Links)

```json
{
  "id": "uuid",
  "file_id": "file_uuid",
  "token_hash": "sha256(token)",
  "expires_at": "ISO_datetime",
  "max_uses": 1,
  "uses": 0,
  "created_by": "owner@example.com",
  "created_at": "ISO_datetime",

  "key_wrap": "token-derived|fragment-secret",
  "enc_file_key_b64": "...optional...",
  "enc_file_key_iv_b64": "...optional...",
  "enc_file_key_tag_b64": "...optional..."
}
```

#### 3. OTP Codes Collection
```json
{
  "email": "user@example.com",
  "otp_hash": "sha256_hash",
  "attempts": 0,
  "created_at": "ISO_datetime",
  "expires_at": "ISO_datetime"
}
```

#### 4. Access Logs Collection
```json
{
  "id": "uuid",
  "user_email": "user@example.com",
  "action": "File uploaded",
  "file_id": "file_uuid",
  "filename": "document.pdf",
  "timestamp": "ISO_datetime"
}
```

## 🔄 Data Flow

### File Upload Flow
1. User selects file in UI
2. Frontend sends file to backend
3. Backend:
   - Computes SHA-256 hash (integrity)
   - Generates random AES-256 key
   - Encrypts file with AES-256
   - Encrypts AES key with user's RSA public key
   - Stores encrypted data and encrypted key in MongoDB
4. Returns file metadata to frontend
5. Logs action in audit log

### File Download Flow
1. User requests file download
2. Backend verifies:
   - User authentication (JWT)
   - User authorization (owner or shared with)
3. Backend:
   - Retrieves encrypted data and encrypted AES key
   - Decrypts AES key using user's RSA private key
   - Decrypts file content using AES key
   - Verifies integrity using SHA-256 hash
4. Returns decrypted file to user
5. Logs action in audit log

### File Sharing Flow
1. Owner specifies recipient email
2. Backend:
   - Validates recipient exists
  - Adds recipient to file's `shared_with` list (legacy)
  - Upserts `file_permissions` with per-file role (`viewer` or `editor`)
3. Recipient can now decrypt using their own RSA private key
4. Logs sharing action

### Temporary Link Flow (Expiring + Limited Uses)
1. Owner creates a link with `expiresInMinutes` and `maxUses` (e.g., one-time)
2. Backend stores only `token_hash` and `access_code_hash` (never stores the raw token/code)
3. Backend returns `{ url, accessCode }` once so the owner can share the access code out-of-band
4. Public endpoint `GET /api/share/{token}` (requires `X-Share-Access-Code` header):
  - Validates not expired and not consumed
  - Validates provided code (either the per-file password or the link-specific access code)
  - Consumes one use (one-time links become invalid immediately after a successful retrieval)
  - Returns ciphertext/iv/tag + sha256 + a wrapped file key for the link

### “Zero-Knowledge Style” Link (Demo)
- Link format: `https://app/share/<token>#<secret>`
- `#secret` is never sent to the server (URL fragment)
- Frontend uses `#secret` to decrypt the wrapped file key and then decrypt the file locally

## 🚀 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Validate password and send OTP to email
- `POST /api/auth/verify-otp` - Verify OTP and get JWT token
- `POST /api/auth/resend-otp` - Resend OTP

## Email OTP Authentication Adaptation

The original demo mode displayed OTP codes directly on the screen. This adaptation improves the authentication process by sending OTP codes to the user's registered email address.

### Authentication Flow

1. User enters email and password.
2. Backend validates the user's credentials.
3. Backend generates a 6-digit OTP.
4. OTP is hashed and stored in MongoDB.
5. The plain OTP is sent to the user's email.
6. User enters the OTP in the verification page.
7. Backend hashes the submitted OTP and compares it with the stored hash.
8. If valid and not expired, the backend issues a JWT token.
9. The OTP is deleted after successful verification.

### Security Improvements

- OTP is no longer displayed on screen.
- OTP is sent to the user's email.
- OTP expires after 5 minutes.
- OTP is hashed before storage.
- OTP can only be used once.
- Failed OTP attempts are limited.
- Resend OTP has cooldown protection.

### File Management
- `POST /api/files/upload` - Upload and encrypt file
- `GET /api/files/list` - List user's files
- `GET /api/files/download/{file_id}` - Download and decrypt file (requires `X-File-Access-Code`)
- `DELETE /api/files/delete/{file_id}` - Delete file
- `POST /api/files/share/{file_id}` - Share file with user
- `PUT /api/files/{file_id}/access-password` - (Owner) Set/rotate file access password
- `POST /api/files/{file_id}/access-codes` - (Owner) Create expiring access code (DAC)
- `GET /api/files/{file_id}/access-codes` - (Owner) List access codes for a file
- `DELETE /api/files/{file_id}/access-codes/{code_id}` - (Owner) Revoke an access code for a file

### Temporary Links
- `POST /api/files/{file_id}/share-link` - Create expiring link (limited uses) (returns `{ url, accessCode }`)
- `GET /api/share/{token}` - Public share link payload (requires `X-Share-Access-Code`; no auth)
- `POST /api/share/{token}/zk-setup` - Save fragment-secret wrapped file key (owner)
- `DELETE /api/files/revoke/{file_id}` - Revoke access (owner)

### Admin (Admin Role Only)
- `GET /api/admin/users` - List all users
- `GET /api/admin/logs` - View audit logs
- `GET /api/admin/stats` - System statistics

## 🎨 User Interface

### Pages
1. **Landing Page**: Professional hero section with login/register forms
2. **OTP Verification**: Multi-factor authentication screen
3. **User Dashboard**: File management interface
4. **Admin Panel**: User management and audit logs (admin only)

### UI Features
- Clean, professional corporate design
- Responsive layout for all screen sizes
- Real-time notifications (toast messages)
- File cards with metadata display
- Secure sharing dialog
- Role-based UI elements

## 🧪 Testing

### Backend Testing
All 18 API endpoints tested and verified:
- User registration and authentication
- OTP generation and verification
- File upload with encryption
- File download with decryption
- File sharing and access control
- Admin features and RBAC
- Integrity verification

### Frontend Testing
- Complete user flow (register → login → OTP → dashboard)
- File upload/download functionality
- File sharing interface
- Admin panel access control
- Logout functionality

### Security Testing
- AES-256 encryption verified
- RSA key exchange working
- SHA-256 integrity checks passing
- JWT authentication enforced
- Role-based access control validated

## 📊 Demo Credentials

For graduation demo purposes, you can create accounts with different roles:

**Regular User**:
- Email: `user@example.com`
- Password: `user123`
- Role: `user`

**Admin User**:
- Email: `admin@example.com`
- Password: `admin123`
- Role: `admin`

**Note**: OTP is delivered through the configured email inbox, so demo verification now requires access to that inbox.

## 🔒 Security Considerations

### Production Recommendations
1. **Email Service**: For production scale, consider a managed provider such as SendGrid or AWS SES instead of basic SMTP.
2. **Key Storage**: Consider hardware security modules (HSM) for key management
3. **File Storage**: Move to dedicated object storage (S3, Azure Blob) for scalability
4. **HTTPS**: Ensure all communications use TLS/SSL
5. **Rate Limiting**: Implement rate limiting on authentication endpoints
6. **Password Policy**: Enforce strong password requirements
7. **Session Management**: Implement token refresh and revocation
8. **Audit Logging**: Expand logging for compliance requirements

### Current Limitations (Demo)
- SMTP delivery depends on valid provider credentials and inbox availability
- Files stored in MongoDB (not ideal for large files)
- Private keys stored in database (acceptable for demo, use HSM in production)
- No file size limits implemented
- No file type validation

## 📈 System Statistics

The admin dashboard displays:
- Total registered users
- Total encrypted files
- Total system actions/events
- Complete audit trail

## 🎓 Educational Value

This project demonstrates:
1. **Symmetric Encryption**: AES-256 for bulk data encryption
2. **Asymmetric Encryption**: RSA for secure key exchange
3. **Hashing**: SHA-256 for integrity verification
4. **Authentication**: Multi-factor authentication implementation
5. **Authorization**: Role-based access control
6. **Web Security**: JWT tokens, password hashing, secure API design
7. **Full-stack Development**: React frontend + FastAPI backend + MongoDB

## 📝 Conclusion

SecureShare successfully implements enterprise-grade security features in a user-friendly web application. It demonstrates the practical application of cryptographic principles, secure software development practices, and modern web technologies. The system is suitable as a graduation project to showcase understanding of information security, encryption, authentication, and full-stack development.

---

**Built with**: FastAPI, React, MongoDB, Python Cryptography Library
**Purpose**: Educational graduation project
**Security Level**: Enterprise-grade encryption with educational simplifications for demo purposes
