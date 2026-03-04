# SecureShare - Secure File Sharing System

## Project Overview

Developed/extended from: [lXsaraXl/securefilesharing](https://github.com/lXsaraXl/securefilesharing/tree/main)

This project is designed as a secure file-sharing system with robust security features and user-friendly interface. It implements end-to-end encryption, multi-factor authentication, and role-based access control to ensure data privacy and integrity.

## Security Features Implemented

- **AES-256 Encryption**: Files are encrypted before storage using 256-bit keys
- **RSA Encryption (2048-bit)**: Secure key exchange with RSA keypairs per user
- **Email-based MFA**: 6-digit OTP verification (demo mode displays OTP on screen)
- **Role-Based Access Control**: Admin and User roles with specified permissions
- **SHA-256 Hashing**: File integrity verification on upload/download

## Core Functionality

- User Registration/Login with multi-factor authentication
- File Upload with AES-256 encryption
- File Download with decryption and integrity checks
- File Sharing with owner-controlled access
- File Deletion (available to owner or admin)
- Admin Panel with user management, activity logging, and system stats
- JWT Authentication for secure session management
- Audit Logging to track all actions

## Technical Implementation

- **Backend**: FastAPI using Python cryptography
- **Frontend**: React with corporate UI styling (Manrope font)
- **Database**: MongoDB (users, files, otp_codes, access_logs collections)
- **Testing**: Backend APIs and frontend flows have been tested
- **Documentation**: PROJECT_DOCUMENTATION.md compiled

## Prerequisites

- Python 3.8+
- Node.js 16+
- MongoDB (local or cloud instance)
- Yarn package manager

## Installation

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the backend directory with the following variables:
   ```
   MONGO_URL=mongodb://localhost:27017
   DB_NAME=securefileshare
   SECRET_KEY=your-secret-key-here
   CORS_ORIGINS=http://localhost:3000
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   yarn install
   ```

## Running the Application

### Start MongoDB

Ensure MongoDB is running on your system. For local installation:
```bash
mongod
```

### Start Backend Server

From the backend directory:
```bash
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### Start Frontend

From the frontend directory:
```bash
yarn start
```

The application will open at `http://localhost:3000`

## Usage

### User Registration and Login

1. Register a new account with email, password, and role selection
2. Login with credentials
3. Enter the 6-digit OTP displayed on the screen (demo mode)

### File Operations

- **Upload**: Select and upload files (automatically encrypted)
- **Download**: Download and decrypt files you own or have access to
- **Share**: Share files with other users by email
- **Delete**: Delete files (owner or admin only)

### Admin Panel

Access the admin panel if logged in as admin:
- View system statistics
- Manage users
- View activity logs

## Demo Specific Features

- OTPs are displayed on screen instead of being emailed (for demo purposes)
- Role selection during registration
- Clean and professional UI
- Audit trail available in admin panel

## API Endpoints

The backend provides RESTful APIs for all operations. Key endpoints include:

- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/verify-otp` - OTP verification
- `POST /api/files/upload` - File upload
- `GET /api/files/list` - List user files
- `GET /api/files/download/{file_id}` - Download file
- `DELETE /api/files/delete/{file_id}` - Delete file
- `POST /api/files/share/{file_id}` - Share file
- `POST /api/files/{file_id}/share-link` - Create expiring link (limited uses)
- `GET /api/share/{token}` - Download payload for share link (no auth)
- `POST /api/share/{token}/zk-setup` - (Optional) Store fragment-secret wrapped file key for link
- `DELETE /api/files/revoke/{file_id}` - Revoke access for a user (owner only)
- `GET /api/files/key/{file_id}` - (Owner only) Export file AES key for demo/zk link setup
- `GET /api/admin/users` - Admin: List users
- `GET /api/admin/logs` - Admin: View logs
- `GET /api/admin/stats` - Admin: System stats

## RBAC (Per-file)

In addition to the global `admin/user` roles, files now support per-file roles:

- `viewer`: download only
- `editor`: (reserved for update/rename flows) + download
- `owner`: share, revoke, delete, create share links

Audit log events added for demo:

- `CREATE_LINK`
- `CONSUME_LINK`
- `REVOKE_ACCESS`

## Testing

Run backend tests:
```bash
cd backend
pytest
```

Run frontend tests:
```bash
cd frontend
yarn test
```

## Contributing

This is a graduation project. For any issues or enhancements, please refer to the PROJECT_DOCUMENTATION.md file.

## License

This project is for educational purposes.
