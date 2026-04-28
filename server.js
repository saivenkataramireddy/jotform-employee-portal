const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 5001;

// ============================================
// CONFIGURATION
// ============================================
const JWT_SECRET = process.env.JWT_SECRET || 'employee_portal_secret_key_2024';
const JWT_EXPIRY = '1h'; // JWT session token expires after 1 hour
const AUTO_LOGIN_TOKEN_EXPIRY_MINUTES = 15; // Auto-login token expires after 15 minutes

// ============================================
// DATABASE INITIALIZATION
// ============================================

/**
 * Initialize auto_login_tokens table
 */
async function initAutoLoginTokensTable() {
    try {
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS auto_login_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                token VARCHAR(255) UNIQUE NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used_at DATETIME NULL,
                INDEX idx_token (token),
                INDEX idx_employee (employee_id),
                INDEX idx_expires (expires_at)
            )
        `);
        console.log('[DB] auto_login_tokens table initialized');
    } catch (error) {
        console.error('[DB] Error initializing auto_login_tokens table:', error);
    }
}

/**
 * Clean up expired and used tokens from database
 */
async function cleanupExpiredTokens() {
    try {
        const [result] = await pool.execute(`
            DELETE FROM auto_login_tokens 
            WHERE expires_at < NOW() 
            OR (is_used = TRUE AND used_at < DATE_SUB(NOW(), INTERVAL 1 HOUR))
        `);
        if (result.affectedRows > 0) {
            console.log(`[DB] Cleaned up ${result.affectedRows} expired/used tokens`);
        }
    } catch (error) {
        console.error('[DB] Error cleaning up tokens:', error);
    }
}

// Run cleanup every 10 minutes
setInterval(cleanupExpiredTokens, 10 * 60 * 1000);

// ============================================
// TOKEN MANAGEMENT FUNCTIONS
// ============================================

/**
 * Generate secure random token
 */
function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Store auto-login token in database
 */
async function storeAutoLoginToken(employeeId, token) {
    const expiresAt = new Date(Date.now() + AUTO_LOGIN_TOKEN_EXPIRY_MINUTES * 60 * 1000);

    await pool.execute(`
        INSERT INTO auto_login_tokens (employee_id, token, expires_at)
        VALUES (?, ?, ?)
    `, [employeeId, token, expiresAt]);

    return expiresAt;
}

/**
 * Validate and consume auto-login token from database
 * Returns: { valid: boolean, error?: string, employeeId?: string }
 */
async function validateAndConsumeToken(token) {
    try {
        // Get token from database
        const [rows] = await pool.execute(`
            SELECT id, employee_id, is_used, expires_at 
            FROM auto_login_tokens 
            WHERE token = ?
        `, [token]);

        if (rows.length === 0) {
            return { valid: false, error: 'Invalid token' };
        }

        const tokenData = rows[0];

        // Check if already used
        if (tokenData.is_used) {
            return { valid: false, error: 'Token already used' };
        }

        // Check if expired
        if (new Date() > new Date(tokenData.expires_at)) {
            return { valid: false, error: 'Token expired' };
        }

        // Mark as used
        await pool.execute(`
            UPDATE auto_login_tokens 
            SET is_used = TRUE, used_at = NOW() 
            WHERE id = ?
        `, [tokenData.id]);

        return { valid: true, employeeId: tokenData.employee_id };

    } catch (error) {
        console.error('[TOKEN] Error validating token:', error);
        return { valid: false, error: 'Server error' };
    }
}

// ============================================
// MIDDLEWARE
// ============================================

// CORS middleware
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, 'client/dist')));

// ============================================
// JWT MIDDLEWARE FOR TOKEN VERIFICATION
// ============================================

/**
 * Middleware to verify JWT token from Authorization header
 * Use this to protect API routes
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    message: 'Token has expired. Please login again.',
                    expired: true
                });
            }
            return res.status(403).json({
                success: false,
                message: 'Invalid token.'
            });
        }
        req.user = user;
        next();
    });
};

// ============================================
// EMPLOYEE AUTHENTICATION APIs
// ============================================

/**
 * POST /api/direct-login
 * Logs in a user based purely on employeeId and division (no password required).
 * This endpoint is used when these parameters are passed in the URL to the dashboard.
 */
app.post('/api/direct-login', async (req, res) => {
    try {
        const { employeeId, division } = req.body;

        if (!employeeId || !division) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID and Division are required'
            });
        }

        // Verify credentials
        const [rows] = await pool.execute(`
            SELECT e.id, e.employee_id, e.full_name, e.designation, e.hq, e.division_id, d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            WHERE e.employee_id = ? AND d.division_name = ?
        `, [employeeId, division]);

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid Employee ID or Division'
            });
        }

        const employee = rows[0];

        // Generate JWT token for session
        const jwtToken = jwt.sign(
            {
                id: employee.id,
                employee_id: employee.employee_id,
                full_name: employee.full_name,
                division_id: employee.division_id,
                division_name: employee.division_name,
                designation: employee.designation,
                hq: employee.hq
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );

        console.log(`[DIRECT-LOGIN] Success: ${employeeId} from division ${division}`);

        res.json({
            success: true,
            token: jwtToken,
            employee: {
                id: employee.id,
                employee_id: employee.employee_id,
                full_name: employee.full_name,
                division_id: employee.division_id,
                division_name: employee.division_name,
                designation: employee.designation,
                hq: employee.hq
            }
        });

    } catch (error) {
        console.error('[DIRECT-LOGIN] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

/**
 * POST /api/employee-login
 * Standard login endpoint for form-based authentication
 * On success, returns JWT token AND secure auto-login token
 */
app.post('/api/employee-login', async (req, res) => {
    try {
        const { employee_id, password } = req.body;

        if (!employee_id || !password) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID and password are required'
            });
        }

        // Query employee with division name
        const [rows] = await pool.execute(`
            SELECT 
                e.id,
                e.employee_id,
                e.full_name,
                e.password,
                e.division_id,
                e.designation,
                e.hq,
                d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            WHERE e.employee_id = ?
        `, [employee_id]);

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid Employee ID or password'
            });
        }

        const employee = rows[0];

        // Verify password
        if (password !== employee.password) {
            return res.status(401).json({
                success: false,
                message: 'Invalid Employee ID or password'
            });
        }

        // Generate JWT token for immediate session
        const jwtToken = jwt.sign(
            {
                id: employee.id,
                employee_id: employee.employee_id,
                full_name: employee.full_name,
                division_id: employee.division_id,
                division_name: employee.division_name,
                designation: employee.designation,
                hq: employee.hq
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );

        // Generate secure auto-login token and store in database
        const autoLoginToken = generateSecureToken();
        const autoLoginExpiry = await storeAutoLoginToken(employee.employee_id, autoLoginToken);

        console.log(`[LOGIN] Success: ${employee_id}, Auto-login token stored in DB`);

        // Return both tokens
        res.json({
            success: true,
            message: 'Login successful',
            token: jwtToken,
            autoLoginToken: autoLoginToken,
            autoLoginUrl: `/auto-login?token=${autoLoginToken}`,
            autoLoginExpiry: autoLoginExpiry.toISOString(),
            employee: {
                id: employee.id,
                employee_id: employee.employee_id,
                full_name: employee.full_name,
                division_id: employee.division_id,
                division_name: employee.division_name,
                designation: employee.designation,
                hq: employee.hq
            }
        });

    } catch (error) {
        console.error('[LOGIN] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

/**
 * GET /auto-login?token=SECURE_TOKEN
 * Secure auto-login endpoint using one-time token from database
 * Validates token, generates JWT, redirects to dashboard
 */
app.get('/auto-login', async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).send(renderErrorPage('Missing token', 'No authentication token provided.'));
        }

        // Validate the secure auto-login token from database
        const validation = await validateAndConsumeToken(token);

        if (!validation.valid) {
            console.log(`[AUTO-LOGIN] Failed: ${validation.error}`);
            return res.status(401).send(renderErrorPage('Login Failed', validation.error + '. Please login again using the login form.'));
        }

        // Token is valid - get employee details
        const [rows] = await pool.execute(`
            SELECT 
                e.id,
                e.employee_id,
                e.full_name,
                e.division_id,
                e.designation,
                e.hq,
                d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            WHERE e.employee_id = ?
        `, [validation.employeeId]);

        if (rows.length === 0) {
            return res.status(404).send(renderErrorPage('Employee Not Found', 'The employee associated with this token no longer exists.'));
        }

        const employee = rows[0];

        // Generate JWT token for session
        const jwtToken = jwt.sign(
            {
                id: employee.id,
                employee_id: employee.employee_id,
                full_name: employee.full_name,
                division_id: employee.division_id,
                division_name: employee.division_name,
                designation: employee.designation,
                hq: employee.hq
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );

        console.log(`[AUTO-LOGIN] Success: ${employee.employee_id}`);

        // Redirect to dashboard with JWT token
        const redirectUrl = `/dashboard.html?token=${encodeURIComponent(jwtToken)}`;
        return res.redirect(redirectUrl);

    } catch (error) {
        console.error('[AUTO-LOGIN] Error:', error);
        res.status(500).send(renderErrorPage('Server Error', 'An error occurred during auto-login. Please try again.'));
    }
});

/**
 * Render error page HTML
 */
function renderErrorPage(title, message) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${title} - Employee Portal</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }
                .error-box { 
                    background: white; 
                    padding: 48px; 
                    border-radius: 16px; 
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    text-align: center;
                    max-width: 400px;
                }
                .error-icon {
                    width: 80px;
                    height: 80px;
                    background: #fef2f2;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 24px;
                    font-size: 40px;
                }
                h1 { color: #dc2626; margin-bottom: 16px; font-size: 24px; }
                p { color: #6b7280; margin-bottom: 24px; line-height: 1.5; }
                .btn {
                    display: inline-block;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 12px 24px;
                    border-radius: 8px;
                    text-decoration: none;
                    font-weight: 500;
                    transition: transform 0.2s;
                }
                .btn:hover { transform: translateY(-2px); }
            </style>
        </head>
        <body>
            <div class="error-box">
                <div class="error-icon">⚠️</div>
                <h1>${title}</h1>
                <p>${message}</p>
                <a href="/dashboard.html" class="btn">Return to Dashboard</a>
            </div>
        </body>
        </html>
    `;
}

/**
 * POST /api/generate-auto-login-token
 * Generate a new auto-login token for an already authenticated user
 * Requires valid JWT token
 */
app.post('/api/generate-auto-login-token', authenticateToken, async (req, res) => {
    try {
        const employeeId = req.user.employee_id;

        // Generate new secure token and store in database
        const autoLoginToken = generateSecureToken();
        const autoLoginExpiry = await storeAutoLoginToken(employeeId, autoLoginToken);

        // Construct full URL
        const protocol = req.headers['x-forwarded-proto'] || req.protocol;
        const host = req.get('host');
        const autoLoginUrl = `${protocol}://${host}/auto-login?token=${autoLoginToken}`;

        res.json({
            success: true,
            autoLoginToken,
            autoLoginUrl,
            expiresAt: autoLoginExpiry.toISOString(),
            expiresIn: `${AUTO_LOGIN_TOKEN_EXPIRY_MINUTES} minutes`
        });

    } catch (error) {
        console.error('[GENERATE-TOKEN] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error generating token'
        });
    }
});

// ============================================
// PROTECTED API ROUTES
// ============================================

/**
 * GET /api/employee-dashboard/:employeeId
 * Protected route - requires valid JWT token
 */
app.get('/api/employee-dashboard/:employeeId', authenticateToken, async (req, res) => {
    try {
        const { employeeId } = req.params;

        // Verify the requesting user matches the token
        if (req.user.employee_id !== employeeId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized access'
            });
        }

        const [rows] = await pool.execute(`
            SELECT 
                e.id,
                e.employee_id,
                e.full_name,
                e.division_id,
                e.designation,
                e.hq,
                d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            WHERE e.employee_id = ?
        `, [employeeId]);

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Employee not found'
            });
        }

        res.json({
            success: true,
            employee: rows[0]
        });

    } catch (error) {
        console.error('[DASHBOARD] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

/**
 * GET /api/forms/:employeeId
 * Get forms for employee's division - Protected route
 */
app.get('/api/forms/:employeeId', authenticateToken, async (req, res) => {
    try {
        const { employeeId } = req.params;

        // Verify the requesting user matches the token
        if (req.user.employee_id !== employeeId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized access'
            });
        }

        // Query forms based on employee's division
        const [rows] = await pool.execute(`
            SELECT 
                f.id,
                f.form_name,
                f.form_link,
                f.created_at,
                f.updated_at,
                d.division_name
            FROM forms f
            JOIN employees e ON f.division_id = e.division_id
            JOIN divisions d ON f.division_id = d.id
            WHERE e.employee_id = ?
            ORDER BY f.created_at DESC
        `, [employeeId]);

        res.json({
            success: true,
            forms: rows
        });

    } catch (error) {
        console.error('[FORMS] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

/**
 * GET /api/open-form/:formId/:employeeId
 * Get form with SSO parameters - Protected route
 */
app.get('/api/open-form/:formId/:employeeId', authenticateToken, async (req, res) => {
    try {
        const { formId, employeeId } = req.params;

        // Verify the requesting user matches the token
        if (req.user.employee_id !== employeeId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized access'
            });
        }

        // Get form details with division
        const [formRows] = await pool.execute(`
            SELECT f.id, f.form_name, f.form_link, f.division_id
            FROM forms f
            WHERE f.id = ?
        `, [formId]);

        if (formRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Form not found'
            });
        }

        // Get employee details with division
        const [empRows] = await pool.execute(`
            SELECT e.employee_id, e.full_name, e.designation, e.hq, e.division_id,
                   d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            WHERE e.employee_id = ?
        `, [employeeId]);

        if (empRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Employee not found'
            });
        }

        const form = formRows[0];
        const employee = empRows[0];

        // Check if employee belongs to the same division as the form
        if (form.division_id !== employee.division_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. This form is not available for your division.'
            });
        }

        // Build SSO URL with employeeId and division
        const baseUrl = form.form_link;
        const separator = baseUrl.includes('?') ? '&' : '?';

        const ssoUrl = `${baseUrl}${separator}employeeId=${encodeURIComponent(employee.employee_id)}&division=${encodeURIComponent(employee.division_name)}`;

        res.json({
            success: true,
            form: {
                id: form.id,
                form_name: form.form_name,
                original_url: form.form_link,
                sso_url: ssoUrl
            }
        });

    } catch (error) {
        console.error('[OPEN-FORM] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ============================================
// PUBLIC API for JotForm SSO (No Auth Required)
// ============================================

/**
 * GET /api/validate-form-access
 * Public endpoint for JotForm to validate employee access to a form
 */
app.get('/api/validate-form-access', async (req, res) => {
    try {
        const { employeeId, division, formUrl } = req.query;

        if (!employeeId || !division || !formUrl) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID, division, and form URL are required'
            });
        }

        // Get employee details with division
        const [empRows] = await pool.execute(`
            SELECT e.employee_id, e.full_name, e.designation, e.hq, e.division_id, d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            WHERE e.employee_id = ?
        `, [employeeId]);

        if (empRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Employee not found'
            });
        }

        const employee = empRows[0];

        // Validate that the division in URL matches employee's actual division
        const divisionParam = Array.isArray(division) ? division[0] : division;
        if (employee.division_name.toLowerCase() !== divisionParam.toLowerCase()) {
            return res.status(403).json({
                success: false,
                message: `Access denied. The division parameter does not match your assigned division (${employee.division_name}).`
            });
        }

        // Extract form URL pattern to find the form in database
        const urlMatch = formUrl.match(/jotform\.com\/(\d+)/);
        const jotformId = urlMatch ? urlMatch[1] : null;

        if (!jotformId) {
            return res.status(400).json({
                success: false,
                message: 'Invalid form URL'
            });
        }

        // Find form by jotform ID in the form_link
        const [formRows] = await pool.execute(`
            SELECT f.id, f.form_name, f.form_link, f.division_id, d.division_name
            FROM forms f
            JOIN divisions d ON f.division_id = d.id
            WHERE f.form_link LIKE ?
        `, [`%${jotformId}%`]);

        if (formRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Form not found in the system'
            });
        }

        const form = formRows[0];

        // Check if employee's division matches form's division
        if (employee.division_id !== form.division_id) {
            return res.status(403).json({
                success: false,
                message: `Access denied. You are from ${employee.division_name} division. This form is only available for ${form.division_name} division.`
            });
        }

        // Validation successful
        res.json({
            success: true,
            message: 'Access granted',
            employee: {
                employeeId: employee.employee_id,
                fullName: employee.full_name,
                designation: employee.designation,
                hq: employee.hq,
                division: employee.division_name
            },
            form: {
                id: form.id,
                formName: form.form_name,
                division: form.division_name
            }
        });

    } catch (error) {
        console.error('[VALIDATE-FORM] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during validation'
        });
    }
});

/**
 * GET /api/employee-details
 * Public endpoint for JotForm to fetch employee details
 */
app.get('/api/employee-details', async (req, res) => {
    try {
        const { employeeId, formId } = req.query;

        if (!employeeId) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID is required'
            });
        }

        // Get employee details with division
        const [empRows] = await pool.execute(`
            SELECT employee_id, full_name, designation, hq, division_id
            FROM employees
            WHERE employee_id = ?
        `, [employeeId]);

        if (empRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Employee not found'
            });
        }

        const employee = empRows[0];

        // If formId is provided, validate employee belongs to form's division
        if (formId) {
            const [formRows] = await pool.execute(`
                SELECT division_id FROM forms WHERE id = ?
            `, [formId]);

            if (formRows.length > 0) {
                const formDivisionId = formRows[0].division_id;

                if (formDivisionId !== employee.division_id) {
                    return res.status(403).json({
                        success: false,
                        message: 'Access denied. This form is not available for your division.'
                    });
                }
            }
        }

        res.json({
            success: true,
            employee: {
                employeeId: employee.employee_id,
                fullName: employee.full_name,
                designation: employee.designation,
                hq: employee.hq
            }
        });

    } catch (error) {
        console.error('[EMPLOYEE-DETAILS] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ============================================
// EMPLOYEE MANAGEMENT APIs (Admin)
// ============================================

/**
 * POST /api/employees
 * Create new employee
 */
app.post('/api/employees', async (req, res) => {
    try {
        const { employee_id, full_name, password, division_id, designation, hq } = req.body;

        const [result] = await pool.execute(`
            INSERT INTO employees (employee_id, full_name, password, division_id, designation, hq)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [employee_id, full_name, password, division_id, designation, hq]);

        res.status(201).json({
            success: true,
            message: 'Employee created successfully',
            employeeId: result.insertId
        });

    } catch (error) {
        console.error('[CREATE-EMPLOYEE] Error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                success: false,
                message: 'Employee ID already exists'
            });
        }
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

/**
 * GET /api/employees
 * Get all employees
 */
app.get('/api/employees', async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                e.id,
                e.employee_id,
                e.full_name,
                e.division_id,
                e.designation,
                e.hq,
                e.created_at,
                d.division_name
            FROM employees e
            JOIN divisions d ON e.division_id = d.id
            ORDER BY e.created_at DESC
        `);

        res.json({
            success: true,
            employees: rows
        });

    } catch (error) {
        console.error('[GET-EMPLOYEES] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ============================================
// DATABASE INITIALIZATION ENDPOINTS
// ============================================

/**
 * GET /api/init-employees
 * Initialize employees table
 */
app.get('/api/init-employees', async (req, res) => {
    try {
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS employees (
                id INT PRIMARY KEY AUTO_INCREMENT,
                employee_id VARCHAR(50) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                division_id INT NOT NULL,
                designation VARCHAR(100),
                hq VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (division_id) REFERENCES divisions(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            )
        `);

        res.json({
            success: true,
            message: 'Employees table initialized successfully'
        });
    } catch (error) {
        console.error('[INIT-EMPLOYEES] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error initializing table'
        });
    }
});

/**
 * GET /api/init-auto-login-tokens
 * Initialize auto_login_tokens table manually
 */
app.get('/api/init-auto-login-tokens', async (req, res) => {
    try {
        await initAutoLoginTokensTable();
        res.json({
            success: true,
            message: 'auto_login_tokens table initialized successfully'
        });
    } catch (error) {
        console.error('[INIT-TOKENS] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error initializing auto_login_tokens table'
        });
    }
});

/**
 * GET /api/seed-employees
 * Seed sample employees for testing
 */
app.get('/api/seed-employees', async (req, res) => {
    try {
        const sampleEmployees = [
            { emp_id: 'EMP001', name: 'John Doe', pass: 'password123', div: 1, desig: 'Sales Representative', hq: 'Hyderabad' },
            { emp_id: 'EMP002', name: 'Jane Smith', pass: 'password123', div: 2, desig: 'Manager', hq: 'Mumbai' },
            { emp_id: 'EMP003', name: 'Bob Johnson', pass: 'password123', div: 3, desig: 'Field Officer', hq: 'Delhi' },
            { emp_id: 'EMP004', name: 'Alice Brown', pass: 'password123', div: 4, desig: 'Supervisor', hq: 'Bangalore' },
            { emp_id: 'EMP005', name: 'Charlie Wilson', pass: 'password123', div: 5, desig: 'Executive', hq: 'Chennai' },
            { emp_id: 'EMP006', name: 'Diana Prince', pass: 'password123', div: 6, desig: 'Coordinator', hq: 'Pune' }
        ];

        for (const emp of sampleEmployees) {
            await pool.execute(`
                REPLACE INTO employees (employee_id, full_name, password, division_id, designation, hq)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [emp.emp_id, emp.name, emp.pass, emp.div, emp.desig, emp.hq]);
        }

        res.json({
            success: true,
            message: 'Sample employees seeded successfully'
        });
    } catch (error) {
        console.error('[SEED-EMPLOYEES] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error seeding employees'
        });
    }
});

/**
 * GET /api/seed-forms
 * Seed sample forms for testing
 */
app.get('/api/seed-forms', async (req, res) => {
    try {
        const sampleForms = [
            { div: 1, name: 'Maxmus Form 1', link: 'https://form.jotform.com/261111170676046' },
            { div: 2, name: 'Nucles Form 1', link: 'https://form.jotform.com/261111170676047' },
            { div: 3, name: 'Gladius Form 1', link: 'https://form.jotform.com/261111170676048' },
            { div: 4, name: 'Stimulas Form 1', link: 'https://form.jotform.com/261111170676049' },
            { div: 5, name: 'Glamus Form 1', link: 'https://form.jotform.com/261111170676050' },
            { div: 6, name: 'Nutrius Form 1', link: 'https://form.jotform.com/261111170676051' }
        ];

        for (const form of sampleForms) {
            await pool.execute(`
                INSERT IGNORE INTO forms (division_id, form_name, form_link)
                VALUES (?, ?, ?)
            `, [form.div, form.name, form.link]);
        }

        res.json({
            success: true,
            message: 'Sample forms seeded successfully'
        });
    } catch (error) {
        console.error('[SEED-FORMS] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error seeding forms'
        });
    }
});

// ============================================
// ROOT ENDPOINT
// ============================================

/**
 * GET *
 * Catch-all endpoint - serves React SPA
 */
app.get('*', (req, res, next) => {
    if (!req.url.startsWith('/api/') && !req.url.startsWith('/auto-login')) {
        res.sendFile(path.join(__dirname, 'client/dist/index.html'));
    } else {
        next();
    }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, '0.0.0.0', async () => {
    console.log('========================================');
    console.log('  Employee Secure Token Login System');
    console.log('========================================');
    console.log(`  Server running on http://localhost:${PORT}`);
    console.log('========================================');

    // Initialize database tables
    await initAutoLoginTokensTable();
    await cleanupExpiredTokens();

    console.log('----------------------------------------');
    console.log('  AUTHENTICATION:');
    console.log(`    POST /api/employee-login - Form login`);
    console.log(`    GET  /auto-login?token=TOKEN - Secure auto-login`);
    console.log('----------------------------------------');
    console.log('  TOKEN FEATURES:');
    console.log(`    - Stored in MySQL database`);
    console.log(`    - 15-minute expiry`);
    console.log(`    - One-time use`);
    console.log(`    - 64-character random`);
    console.log(`    - Auto-cleanup every 10 min`);
    console.log('----------------------------------------');
    console.log('  INIT ENDPOINTS:');
    console.log(`    GET /api/init-employees`);
    console.log(`    GET /api/init-auto-login-tokens`);
    console.log(`    GET /api/seed-employees`);
    console.log(`    GET /api/seed-forms`);
    console.log('========================================');
});

module.exports = app;
