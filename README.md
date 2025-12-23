# Secure File Upload

A robust, production-ready file upload solution with comprehensive security features, encryption support, and detailed validation mechanisms to ensure safe and reliable file handling.

## Table of Contents

- [Project Description](#project-description)
- [Security Features](#security-features)
- [Installation Instructions](#installation-instructions)
- [Usage Examples](#usage-examples)
- [API Documentation](#api-documentation)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting Guide](#troubleshooting-guide)

## Project Description

**Secure File Upload** is a comprehensive file upload management system designed with security as the primary focus. This project provides developers with a reliable, easy-to-integrate solution for handling file uploads across web applications while maintaining the highest standards of data protection and integrity.

### Key Objectives

- **Security First**: Implement industry-standard encryption and validation protocols
- **Easy Integration**: Simple API for seamless integration into existing applications
- **Scalability**: Handle high-volume file uploads efficiently
- **Reliability**: Robust error handling and recovery mechanisms
- **Compliance**: Meet modern security compliance standards (OWASP, GDPR)

### Use Cases

- User profile image uploads
- Document management systems
- Medical records handling
- Financial document processing
- Secure file sharing platforms
- Backup and archive systems

## Security Features

### 1. File Validation

- **MIME Type Verification**: Validates file type against whitelist
- **Magic Byte Detection**: Verifies actual file content matches extension
- **Size Limitations**: Configurable file size restrictions
- **Filename Sanitization**: Removes malicious characters and path traversal attempts

### 2. Encryption

- **AES-256 Encryption**: Military-grade encryption for stored files
- **TLS/HTTPS Support**: Encrypted data in transit
- **Key Management**: Secure key rotation and storage
- **Encrypted Metadata**: File metadata encryption for privacy

### 3. Access Control

- **Authentication Required**: All uploads require valid authentication
- **Authorization Checks**: Role-based access control (RBAC)
- **Token Validation**: JWT-based token verification
- **Rate Limiting**: Prevent abuse and DoS attacks

### 4. Virus & Malware Scanning

- **ClamAV Integration**: Optional virus scanning on upload
- **Sandboxed Execution**: Files processed in isolated environment
- **Quarantine System**: Suspicious files automatically quarantined

### 5. Audit Logging

- **Complete Audit Trail**: Log all file operations
- **Timestamp Recording**: Precise operation timestamps
- **User Tracking**: Track which user performed each action
- **Change History**: Maintain file modification history

### 6. Data Protection

- **Secure Deletion**: Cryptographic shredding of deleted files
- **Backup Encryption**: All backups encrypted at rest
- **Database Security**: Sensitive data hashing and encryption
- **Network Security**: SSL/TLS for all communications

## Installation Instructions

### Prerequisites

- Node.js >= 14.0.0
- npm >= 6.0.0 or yarn >= 1.22.0
- MongoDB >= 4.4 (or compatible database)
- OpenSSL for key generation
- Optional: ClamAV for virus scanning

### Step 1: Clone the Repository

```bash
git clone https://github.com/DigitalDaWizard/secure-file-upload.git
cd secure-file-upload
```

### Step 2: Install Dependencies

```bash
npm install
# or
yarn install
```

### Step 3: Environment Configuration

Create a `.env` file in the project root:

```env
# Server Configuration
NODE_ENV=production
PORT=3000
HOST=localhost

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/secure-file-upload
DB_NAME=secure-file-upload

# File Upload Configuration
UPLOAD_DIR=/var/uploads
MAX_FILE_SIZE=52428800
ALLOWED_MIME_TYPES=image/jpeg,image/png,application/pdf,application/msword

# Encryption Configuration
ENCRYPTION_KEY=your-secret-encryption-key-min-32-chars
ENCRYPTION_ALGORITHM=aes-256-gcm
KEY_ROTATION_INTERVAL=2592000

# Security Configuration
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRATION=24h
ENABLE_VIRUS_SCAN=true
CLAMAV_HOST=localhost
CLAMAV_PORT=3310

# CORS Configuration
CORS_ORIGIN=https://yourdomain.com
CORS_CREDENTIALS=true

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX_REQUESTS=100

# Logging
LOG_LEVEL=info
LOG_DIR=/var/logs/secure-file-upload
```

### Step 4: Generate Encryption Keys

```bash
npm run generate-keys
```

This command will generate secure encryption keys and store them safely.

### Step 5: Initialize Database

```bash
npm run db:init
npm run db:migrate
```

### Step 6: Start the Service

```bash
# Development
npm run dev

# Production
npm run build
npm start
```

## Usage Examples

### Basic File Upload

#### JavaScript/Node.js

```javascript
const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');

async function uploadFile() {
  const form = new FormData();
  form.append('file', fs.createReadStream('document.pdf'));
  form.append('description', 'Important document');

  try {
    const response = await axios.post(
      'https://api.example.com/api/v1/upload',
      form,
      {
        headers: {
          ...form.getHeaders(),
          'Authorization': 'Bearer YOUR_JWT_TOKEN'
        }
      }
    );

    console.log('Upload successful:', response.data);
  } catch (error) {
    console.error('Upload failed:', error.response.data);
  }
}

uploadFile();
```

#### cURL

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@document.pdf" \
  -F "description=Important document" \
  https://api.example.com/api/v1/upload
```

### Upload with Metadata

```javascript
const uploadData = new FormData();
uploadData.append('file', fs.createReadStream('image.jpg'));
uploadData.append('metadata', JSON.stringify({
  title: 'Profile Picture',
  category: 'profile',
  tags: ['personal', 'avatar'],
  isPublic: false
}));

const response = await axios.post(
  'https://api.example.com/api/v1/upload',
  uploadData,
  {
    headers: {
      ...uploadData.getHeaders(),
      'Authorization': 'Bearer YOUR_JWT_TOKEN'
    }
  }
);
```

### Retrieve File

```javascript
async function downloadFile(fileId) {
  const response = await axios.get(
    `https://api.example.com/api/v1/files/${fileId}/download`,
    {
      headers: {
        'Authorization': 'Bearer YOUR_JWT_TOKEN'
      },
      responseType: 'stream'
    }
  );

  response.data.pipe(fs.createWriteStream('downloaded_file.pdf'));
}

downloadFile('file-uuid-here');
```

### List User Files

```javascript
async function listFiles(page = 1, limit = 10) {
  const response = await axios.get(
    'https://api.example.com/api/v1/files',
    {
      headers: {
        'Authorization': 'Bearer YOUR_JWT_TOKEN'
      },
      params: {
        page,
        limit,
        sort: '-createdAt'
      }
    }
  );

  return response.data;
}

listFiles().then(files => console.log(files));
```

### Delete File

```javascript
async function deleteFile(fileId) {
  const response = await axios.delete(
    `https://api.example.com/api/v1/files/${fileId}`,
    {
      headers: {
        'Authorization': 'Bearer YOUR_JWT_TOKEN'
      }
    }
  );

  console.log('File deleted:', response.data);
}
```

### Share File with Expiration

```javascript
async function shareFile(fileId, expirationDays = 7) {
  const response = await axios.post(
    `https://api.example.com/api/v1/files/${fileId}/share`,
    {
      expiresIn: expirationDays,
      permissions: ['read'],
      passwordProtected: true,
      password: 'securePassword123'
    },
    {
      headers: {
        'Authorization': 'Bearer YOUR_JWT_TOKEN'
      }
    }
  );

  return response.data.shareLink;
}
```

## API Documentation

### Authentication

All API endpoints require Bearer token authentication.

```
Authorization: Bearer <JWT_TOKEN>
```

### File Upload Endpoint

**POST** `/api/v1/upload`

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
Content-Type: multipart/form-data
```

**Body:**
```
file: <binary>
description: <string> (optional)
metadata: <json> (optional)
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "fileId": "550e8400-e29b-41d4-a716-446655440000",
    "filename": "document.pdf",
    "originalName": "document.pdf",
    "size": 1024000,
    "mimeType": "application/pdf",
    "uploadedAt": "2025-12-23T08:02:56Z",
    "uploadedBy": "user-uuid",
    "encryption": {
      "algorithm": "aes-256-gcm",
      "encrypted": true
    },
    "checksum": "sha256:abcd1234..."
  }
}
```

**Response (400 Bad Request):**
```json
{
  "success": false,
  "error": "File size exceeds maximum allowed size",
  "code": "FILE_SIZE_EXCEEDED"
}
```

### Get File Info

**GET** `/api/v1/files/{fileId}`

**Response:**
```json
{
  "success": true,
  "data": {
    "fileId": "550e8400-e29b-41d4-a716-446655440000",
    "filename": "document.pdf",
    "size": 1024000,
    "mimeType": "application/pdf",
    "uploadedAt": "2025-12-23T08:02:56Z",
    "uploadedBy": "user-uuid",
    "isPublic": false,
    "downloads": 5,
    "lastAccessedAt": "2025-12-23T08:00:00Z"
  }
}
```

### List Files

**GET** `/api/v1/files?page=1&limit=10&sort=-createdAt`

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `limit` (integer): Items per page (default: 10, max: 100)
- `sort` (string): Sort field with +/- prefix (default: -createdAt)
- `filter` (string): Filter by filename or category

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "fileId": "550e8400-e29b-41d4-a716-446655440000",
      "filename": "document.pdf",
      "size": 1024000,
      "uploadedAt": "2025-12-23T08:02:56Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 45,
    "pages": 5
  }
}
```

### Download File

**GET** `/api/v1/files/{fileId}/download`

**Response:** Binary file stream

### Delete File

**DELETE** `/api/v1/files/{fileId}`

**Response:**
```json
{
  "success": true,
  "message": "File deleted successfully"
}
```

### Share File

**POST** `/api/v1/files/{fileId}/share`

**Body:**
```json
{
  "expiresIn": 7,
  "permissions": ["read"],
  "passwordProtected": true,
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "shareLink": "https://api.example.com/share/abc123def456",
    "expiresAt": "2025-12-30T08:02:56Z",
    "shareToken": "abc123def456"
  }
}
```

### Error Response Format

All error responses follow this format:

```json
{
  "success": false,
  "error": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

**Common Error Codes:**
- `UNAUTHORIZED` - Missing or invalid authentication token
- `FORBIDDEN` - Insufficient permissions
- `FILE_NOT_FOUND` - Requested file doesn't exist
- `FILE_SIZE_EXCEEDED` - File exceeds maximum allowed size
- `INVALID_MIME_TYPE` - File type not allowed
- `VIRUS_DETECTED` - File flagged by antivirus
- `ENCRYPTION_ERROR` - Encryption/decryption failed
- `DATABASE_ERROR` - Database operation failed
- `RATE_LIMIT_EXCEEDED` - Too many requests

## Security Best Practices

### 1. File Upload Handling

**DO:**
- ✅ Always validate file types on both client and server
- ✅ Implement file size limits appropriate for your use case
- ✅ Use cryptographic hashing to verify file integrity
- ✅ Store files outside the web root
- ✅ Implement virus/malware scanning
- ✅ Use randomly generated filenames
- ✅ Maintain audit logs of all uploads

**DON'T:**
- ❌ Trust client-side file type validation alone
- ❌ Store user-supplied filenames directly
- ❌ Allow direct execution of uploaded files
- ❌ Store sensitive files in publicly accessible directories
- ❌ Skip encryption for sensitive data
- ❌ Use predictable file naming schemes
- ❌ Allow zip bombs or compressed files without limits

### 2. Authentication & Authorization

```javascript
// Always verify authentication
app.use(authenticateToken);

// Implement proper authorization
app.get('/api/v1/files/:id', authorizeFileAccess, getFile);

// Use strong JWT secrets
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

// Set appropriate token expiration
const TOKEN_EXPIRY = '24h'; // Short-lived tokens
```

### 3. Encryption Best Practices

```javascript
// Use strong encryption algorithms
const ALGORITHM = 'aes-256-gcm'; // Not aes-128-ecb

// Rotate encryption keys regularly
const KEY_ROTATION_INTERVAL = 2592000; // 30 days

// Use unique IVs for each encryption
const IV = crypto.randomBytes(16);

// Store encryption keys securely (use KMS)
// DON'T hardcode keys in source code
```

### 4. Input Validation

```javascript
// Validate all inputs
const validateFileUpload = (req, res, next) => {
  const { filename, size, mimetype } = req.file;
  
  // Check filename
  if (!/^[\w\-. ]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Check size
  if (size > MAX_FILE_SIZE) {
    return res.status(400).json({ error: 'File too large' });
  }
  
  // Check MIME type
  if (!ALLOWED_MIME_TYPES.includes(mimetype)) {
    return res.status(400).json({ error: 'File type not allowed' });
  }
  
  next();
};
```

### 5. CORS Configuration

```javascript
// Configure CORS properly
const cors = require('cors');

app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

### 6. Rate Limiting

```javascript
// Implement rate limiting
const rateLimit = require('express-rate-limit');

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window
  message: 'Too many uploads, please try again later'
});

app.post('/api/v1/upload', uploadLimiter, uploadFile);
```

### 7. HTTPS/TLS

- Always use HTTPS in production
- Use strong TLS version (1.2 or higher)
- Implement HSTS headers
- Use valid SSL certificates

```javascript
// Force HTTPS
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});

// Set HSTS header
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
```

### 8. Database Security

- Use parameterized queries to prevent SQL injection
- Encrypt sensitive data at rest
- Use strong database passwords
- Implement principle of least privilege
- Regular database backups with encryption

### 9. Logging & Monitoring

```javascript
// Log all sensitive operations
logger.info('File uploaded', {
  userId: req.user.id,
  fileId: file.id,
  fileSize: file.size,
  timestamp: new Date().toISOString()
});

// Monitor for suspicious activity
monitoringService.track('file_upload', {
  user: req.user.id,
  size: req.file.size,
  type: req.file.mimetype
});
```

### 10. Dependency Management

- Keep all dependencies updated
- Use `npm audit` to check for vulnerabilities
- Implement automated security scanning
- Review dependencies before installation

## Troubleshooting Guide

### Issue: Upload Fails with "Authentication Error"

**Causes:**
- Missing or invalid JWT token
- Token has expired
- User doesn't have upload permissions

**Solutions:**

1. Verify you're sending a valid token:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.example.com/api/v1/upload
```

2. Check token expiration:
```javascript
const decoded = jwt.decode(token);
console.log('Expires at:', new Date(decoded.exp * 1000));
```

3. Request a new token:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' \
  https://api.example.com/api/v1/auth/login
```

### Issue: File Upload Fails with "File Size Exceeded"

**Causes:**
- File is larger than MAX_FILE_SIZE setting
- Request payload too large

**Solutions:**

1. Check current max file size:
```bash
curl https://api.example.com/api/v1/config/limits \
  -H "Authorization: Bearer YOUR_TOKEN"
```

2. Reduce file size or compress:
```bash
# Compress PDF
gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 \
  -dPDFSETTINGS=/screen -o compressed.pdf original.pdf

# Compress image
convert image.jpg -quality 85 compressed.jpg
```

3. Contact administrator to increase file size limit if appropriate

### Issue: "Invalid MIME Type" Error

**Causes:**
- File extension not in whitelist
- File content doesn't match extension
- Incorrect Content-Type header

**Solutions:**

1. Check allowed MIME types:
```bash
curl https://api.example.com/api/v1/config/mime-types \
  -H "Authorization: Bearer YOUR_TOKEN"
```

2. Verify file is correct type:
```bash
file document.pdf
# Output: application/pdf

# Use magic bytes library
npm install file-type
const fileType = await FileType.fromFile('document.pdf');
console.log(fileType.mime);
```

3. Ensure correct Content-Type in upload request

### Issue: Virus Scan Fails

**Causes:**
- ClamAV service not running
- File flagged as suspicious/malicious
- Virus database outdated

**Solutions:**

1. Check ClamAV status:
```bash
sudo systemctl status clamav-daemon
sudo systemctl restart clamav-daemon
```

2. Update virus definitions:
```bash
sudo freshclam
```

3. Manually scan file:
```bash
clamscan --log=scan.log document.pdf
```

4. Review quarantined files:
```bash
ls -la /var/quarantine/
```

### Issue: Encryption/Decryption Errors

**Causes:**
- Encryption key mismatch
- Corrupted encrypted data
- Key rotation issue

**Solutions:**

1. Verify encryption key is set:
```bash
echo $ENCRYPTION_KEY
```

2. Check key format:
```bash
# Key should be 32 bytes for AES-256
echo -n "YOUR_KEY" | wc -c
```

3. Generate new key pair:
```bash
npm run generate-keys
```

4. Check encryption logs:
```bash
tail -f /var/logs/secure-file-upload/encryption.log
```

### Issue: Database Connection Failed

**Causes:**
- MongoDB service not running
- Incorrect connection string
- Authentication failure
- Network connectivity issue

**Solutions:**

1. Check MongoDB status:
```bash
sudo systemctl status mongodb
sudo systemctl restart mongodb
```

2. Verify connection string in .env:
```
MONGODB_URI=mongodb://username:password@localhost:27017/secure-file-upload?authSource=admin
```

3. Test connection:
```bash
mongosh "mongodb://localhost:27017/secure-file-upload"
```

4. Check network connectivity:
```bash
telnet localhost 27017
```

### Issue: Rate Limiting - Too Many Requests

**Causes:**
- Exceeded request limit
- Retry logic in client code
- DDoS protection triggered

**Solutions:**

1. Wait before retrying (exponential backoff):
```javascript
async function uploadWithRetry(file, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await uploadFile(file);
    } catch (error) {
      if (error.status === 429) {
        const delay = Math.pow(2, i) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        throw error;
      }
    }
  }
}
```

2. Check your rate limit:
```bash
curl -i https://api.example.com/api/v1/upload
# Look for X-RateLimit-* headers
```

3. Contact support if limit needs adjustment

### Issue: Permission Denied on File Access

**Causes:**
- File not shared with user
- User permissions revoked
- File ownership issue

**Solutions:**

1. Check file permissions:
```bash
curl https://api.example.com/api/v1/files/{fileId}/permissions \
  -H "Authorization: Bearer YOUR_TOKEN"
```

2. Request file access:
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"reason":"Need this file for project"}' \
  https://api.example.com/api/v1/files/{fileId}/request-access
```

3. Check if file owner granted access:
```javascript
// As file owner, share file
await shareFile(fileId, {
  userId: 'other-user-id',
  permissions: ['read']
});
```

### Issue: Performance Issues - Slow Uploads

**Causes:**
- Large file size
- Network bandwidth limitation
- Server processing bottleneck
- Disk I/O issues

**Solutions:**

1. Enable chunked uploads:
```javascript
const uploadInChunks = async (file) => {
  const chunkSize = 5 * 1024 * 1024; // 5MB chunks
  const totalChunks = Math.ceil(file.size / chunkSize);
  
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const chunk = file.slice(start, end);
    
    await uploadChunk(chunk, i, totalChunks);
  }
};
```

2. Check server resources:
```bash
# CPU usage
top -b -n 1 | head -n 20

# Disk I/O
iostat -x 1 5

# Memory usage
free -h
```

3. Enable compression:
```javascript
app.use(compression());
```

4. Increase upload timeout:
```javascript
app.post('/api/v1/upload', (req, res) => {
  req.setTimeout(30000); // 30 seconds
  // ... upload logic
});
```

### Issue: Logs Show Encryption Errors

**Causes:**
- IV (Initialization Vector) mismatch
- Authentication tag verification failed
- Corrupted encryption headers

**Solutions:**

1. Enable debug logging:
```javascript
process.env.LOG_LEVEL = 'debug';
```

2. Check encryption logs:
```bash
grep "ENCRYPTION_ERROR" /var/logs/secure-file-upload/error.log
```

3. Verify encryption configuration:
```bash
node -e "
const config = require('./config');
console.log('Algorithm:', config.encryption.algorithm);
console.log('Key length:', Buffer.from(process.env.ENCRYPTION_KEY).length);
"
```

4. Reset encryption for problematic files:
```bash
npm run re-encrypt -- --files [fileIds]
```

---

## Support & Contributing

For issues, questions, or contributions, please:

1. Check the [Troubleshooting Guide](#troubleshooting-guide)
2. Review [Security Best Practices](#security-best-practices)
3. Open an issue on GitHub with detailed information
4. Submit pull requests following the contribution guidelines

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Security Notice

If you discover a security vulnerability, please email security@example.com instead of using the issue tracker. Please do not disclose security issues publicly until they have been addressed.

---

**Last Updated:** 2025-12-23  
**Version:** 1.0.0  
**Status:** Production Ready
