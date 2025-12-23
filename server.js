/**
 * Secure File Upload Express Server
 * Features:
 * - Multer configuration with file size limits
 * - MIME type validation
 * - Path traversal prevention
 * - Secure file handling and storage
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// ==================== SECURITY MIDDLEWARE ====================

// Helmet for setting various HTTP headers
app.use(helmet());

// Rate limiting middleware to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Body and URL-encoded parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// ==================== MULTER CONFIGURATION ====================

// Ensure uploads directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Allowed MIME types
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
  'text/plain',
  'text/csv',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
];

// Allowed file extensions (as additional validation)
const ALLOWED_EXTENSIONS = [
  '.jpg',
  '.jpeg',
  '.png',
  '.gif',
  '.webp',
  '.pdf',
  '.txt',
  '.csv',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx'
];

// File size limits (in bytes)
const FILE_SIZE_LIMITS = {
  image: 5 * 1024 * 1024,      // 5 MB for images
  document: 10 * 1024 * 1024,   // 10 MB for documents
  default: 5 * 1024 * 1024      // 5 MB default
};

// Custom storage engine with security features
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Store files in uploads directory
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Generate secure filename to prevent path traversal
    const fileExt = path.extname(file.originalname).toLowerCase();
    const uniqueSuffix = crypto.randomBytes(8).toString('hex');
    const timestamp = Date.now();
    const filename = `${timestamp}-${uniqueSuffix}${fileExt}`;
    
    // Store original filename in memory for reference
    req.uploadedFilename = filename;
    req.originalFilename = file.originalname;
    
    cb(null, filename);
  }
});

// File filter with MIME type and extension validation
const fileFilter = (req, file, cb) => {
  const fileExt = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;
  
  // Validate extension
  if (!ALLOWED_EXTENSIONS.includes(fileExt)) {
    return cb(new Error(`File extension not allowed: ${fileExt}`), false);
  }
  
  // Validate MIME type
  if (!ALLOWED_MIME_TYPES.includes(mimeType)) {
    return cb(new Error(`MIME type not allowed: ${mimeType}`), false);
  }
  
  // Additional validation: check for double extensions (e.g., .php.jpg)
  const nameWithoutExt = path.basename(file.originalname, fileExt);
  const additionalExt = path.extname(nameWithoutExt);
  if (additionalExt && !ALLOWED_EXTENSIONS.includes(additionalExt)) {
    return cb(new Error('Double extension detected'), false);
  }
  
  cb(null, true);
};

// Multer middleware configuration
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: FILE_SIZE_LIMITS.default,
    files: 1 // Allow only one file per request
  }
});

// ==================== SECURITY UTILITY FUNCTIONS ====================

/**
 * Validate file path to prevent path traversal attacks
 * @param {string} filename - The filename to validate
 * @returns {boolean} - True if filename is safe, false otherwise
 */
const isValidFilePath = (filename) => {
  // Resolve the full path
  const fullPath = path.resolve(UPLOAD_DIR, filename);
  
  // Ensure the resolved path is within the UPLOAD_DIR
  return fullPath.startsWith(path.resolve(UPLOAD_DIR)) && !filename.includes('..');
};

/**
 * Sanitize filename to prevent directory traversal
 * @param {string} filename - The filename to sanitize
 * @returns {string} - Sanitized filename
 */
const sanitizeFilename = (filename) => {
  // Remove any path separators and parent directory references
  return filename
    .replace(/\.\./g, '')
    .replace(/[\/\\]/g, '')
    .replace(/^\.+/, '');
};

/**
 * Get file size limit based on MIME type
 * @param {string} mimeType - The MIME type of the file
 * @returns {number} - File size limit in bytes
 */
const getFileSizeLimit = (mimeType) => {
  if (mimeType.startsWith('image/')) {
    return FILE_SIZE_LIMITS.image;
  }
  if (mimeType.startsWith('application/') || mimeType === 'text/csv') {
    return FILE_SIZE_LIMITS.document;
  }
  return FILE_SIZE_LIMITS.default;
};

// ==================== ROUTES ====================

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'Server is running' });
});

/**
 * File upload endpoint
 * POST /upload
 * Accepts single file upload with validation
 */
app.post('/upload', upload.single('file'), (req, res) => {
  try {
    // Additional validation
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file provided'
      });
    }
    
    // Validate file path
    if (!isValidFilePath(req.file.filename)) {
      // Delete the uploaded file
      fs.unlinkSync(req.file.path);
      return res.status(400).json({
        success: false,
        message: 'Invalid file path detected'
      });
    }
    
    // Return success response with file details
    res.json({
      success: true,
      message: 'File uploaded successfully',
      file: {
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
        uploadedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    // Clean up on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      success: false,
      message: 'File upload failed',
      error: error.message
    });
  }
});

/**
 * File download endpoint
 * GET /download/:filename
 * Serves uploaded files with path traversal prevention
 */
app.get('/download/:filename', (req, res) => {
  try {
    const filename = sanitizeFilename(req.params.filename);
    
    // Validate file path
    if (!isValidFilePath(filename)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    
    const filepath = path.join(UPLOAD_DIR, filename);
    
    // Check if file exists
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }
    
    // Check if it's a file (not a directory)
    if (!fs.statSync(filepath).isFile()) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    
    // Set appropriate headers for file download
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', fs.statSync(filepath).size);
    
    // Send file
    const fileStream = fs.createReadStream(filepath);
    fileStream.pipe(res);
    
    fileStream.on('error', (error) => {
      console.error('File stream error:', error);
      res.status(500).json({
        success: false,
        message: 'Error downloading file'
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Download failed',
      error: error.message
    });
  }
});

/**
 * List uploaded files endpoint
 * GET /files
 * Returns list of all uploaded files
 */
app.get('/files', (req, res) => {
  try {
    const files = fs.readdirSync(UPLOAD_DIR).map(filename => {
      const filepath = path.join(UPLOAD_DIR, filename);
      const stats = fs.statSync(filepath);
      
      return {
        filename: filename,
        size: stats.size,
        uploadedAt: stats.birthtime,
        modifiedAt: stats.mtime
      };
    });
    
    res.json({
      success: true,
      count: files.length,
      files: files
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve files',
      error: error.message
    });
  }
});

/**
 * Delete file endpoint
 * DELETE /delete/:filename
 * Removes uploaded file with path traversal prevention
 */
app.delete('/delete/:filename', (req, res) => {
  try {
    const filename = sanitizeFilename(req.params.filename);
    
    // Validate file path
    if (!isValidFilePath(filename)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    
    const filepath = path.join(UPLOAD_DIR, filename);
    
    // Check if file exists
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }
    
    // Check if it's a file (not a directory)
    if (!fs.statSync(filepath).isFile()) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    
    // Delete the file
    fs.unlinkSync(filepath);
    
    res.json({
      success: true,
      message: 'File deleted successfully',
      filename: filename
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to delete file',
      error: error.message
    });
  }
});

// ==================== ERROR HANDLING ====================

/**
 * Multer error handling middleware
 */
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      const mimeType = req.file?.mimetype || 'unknown';
      const maxSize = getFileSizeLimit(mimeType);
      return res.status(400).json({
        success: false,
        message: `File too large. Maximum size: ${maxSize / (1024 * 1024)} MB`
      });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Only one file is allowed per request'
      });
    }
  }
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: error.message
    });
  }
  
  next();
});

/**
 * 404 handler
 */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// ==================== SERVER STARTUP ====================

app.listen(PORT, () => {
  console.log(`✓ Secure File Upload Server running on http://localhost:${PORT}`);
  console.log(`✓ Upload directory: ${UPLOAD_DIR}`);
  console.log(`✓ Max file size: ${FILE_SIZE_LIMITS.default / (1024 * 1024)} MB`);
  console.log(`✓ Allowed MIME types: ${ALLOWED_MIME_TYPES.length} types`);
});

module.exports = app;
