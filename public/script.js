/**
 * Employee Portal - Main JavaScript
 * Tokenized Auto Login System
 * Handles authentication, dashboard, forms, and SSO functionality
 */

// ============================================
// CONFIGURATION
// ============================================
const API_BASE_URL = 'http://localhost:5001/api';

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Show toast notification
 */
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;

    const toastIcon = toast.querySelector('i');
    const toastText = toast.querySelector('span');

    toastText.textContent = message;

    if (type === 'error') {
        toastIcon.className = 'fas fa-exclamation-circle';
        toast.classList.add('error');
    } else {
        toastIcon.className = 'fas fa-check-circle';
        toast.classList.remove('error');
    }

    toast.classList.remove('hidden');

    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

/**
 * Show error message on login form
 */
function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    if (!errorDiv) return;

    const errorText = errorDiv.querySelector('span');
    if (errorText) errorText.textContent = message;

    errorDiv.classList.remove('hidden');

    // Auto-hide after 5 seconds
    setTimeout(() => {
        errorDiv.classList.add('hidden');
    }, 5000);
}

/**
 * Hide error message
 */
function hideError() {
    const errorDiv = document.getElementById('errorMessage');
    if (errorDiv) errorDiv.classList.add('hidden');
}

/**
 * Set loading state on button
 */
function setButtonLoading(button, isLoading) {
    if (!button) return;

    const btnText = button.querySelector('.btn-text');
    const btnIcon = button.querySelector('.fa-arrow-right');
    const spinner = button.querySelector('.spinner');

    if (isLoading) {
        button.disabled = true;
        if (btnText) btnText.style.display = 'none';
        if (btnIcon) btnIcon.style.display = 'none';
        if (spinner) spinner.classList.remove('hidden');
    } else {
        button.disabled = false;
        if (btnText) btnText.style.display = 'inline';
        if (btnIcon) btnIcon.style.display = 'inline-block';
        if (spinner) spinner.classList.add('hidden');
    }
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    const options = {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

/**
 * Format date and time
 */
function formatDateTime(dateString) {
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// LOCAL STORAGE FUNCTIONS
// ============================================

/**
 * Store authentication data in localStorage
 */
function storeAuthData(token, employee) {
    localStorage.setItem('token', token);
    localStorage.setItem('isLoggedIn', 'true');
    localStorage.setItem('employeeId', employee.employee_id);

    const employeeData = {
        employee_id: employee.employee_id,
        full_name: employee.full_name,
        division_id: employee.division_id,
        division_name: employee.division_name,
        designation: employee.designation,
        hq: employee.hq,
        login_time: new Date().toISOString()
    };
    localStorage.setItem('employee_data', JSON.stringify(employeeData));

    console.log('[AUTH] Data stored in localStorage:', {
        token: token.substring(0, 20) + '...',
        employeeId: employee.employee_id
    });
}

/**
 * Get token from localStorage
 */
function getToken() {
    return localStorage.getItem('token');
}

/**
 * Get employee data from localStorage
 */
function getEmployeeData() {
    const data = localStorage.getItem('employee_data');
    return data ? JSON.parse(data) : null;
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    const token = getToken();
    const loggedIn = localStorage.getItem('isLoggedIn');
    return !!(token && loggedIn === 'true');
}

/**
 * Clear all authentication data (logout)
 */
function clearAuthData() {
    localStorage.removeItem('token');
    localStorage.removeItem('isLoggedIn');
    localStorage.removeItem('employeeId');
    localStorage.removeItem('employee_data');
    localStorage.removeItem('remembered_employee_id');
    localStorage.removeItem('auto_login_token');
    localStorage.removeItem('auto_login_url');
    localStorage.removeItem('auto_login_expiry');
    console.log('[AUTH] All auth data cleared from localStorage');
}

// ============================================
// API FUNCTIONS
// ============================================

/**
 * Make authenticated API request
 * Automatically includes JWT token from localStorage in Authorization header
 */
async function apiRequest(endpoint, options = {}) {
    const token = getToken();

    // Build headers with Authorization if token exists
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    // Add Authorization header with Bearer token
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers
        });

        // Handle 401 Unauthorized - Token expired or invalid
        if (response.status === 401) {
            const data = await response.json();

            // Check if token expired
            if (data.expired) {
                console.log('[API] Token expired, clearing auth data');
                showToast('Session expired. Please login again.', 'error');
            }

            // Clear auth data
            clearAuthData();

            // Instead of redirecting to login.html, show an error message
            // or let the page handle the lack of auth
            showToast('Session expired. Access denied.', 'error');
            
            return null;
        }

        return response.json();
    } catch (error) {
        console.error('[API] Request error:', error);
        throw error;
    }
}

/**
 * Direct login using employeeId and division
 */
async function performDirectLogin(employeeId, division) {
    if (!employeeId || !division) {
        return { success: false, message: 'Missing credentials in URL.' };
    }

    try {
        console.log(`[AUTH] Attempting direct login for: ${employeeId} (${division})`);
        
        const response = await fetch(`${API_BASE_URL}/direct-login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ employeeId, division })
        });

        const data = await response.json();
        
        if (response.ok && data.success) {
            console.log('[AUTH] Direct login successful');
            // Store auth data
            storeAuthData(data.token, data.employee);
            
            // Clean URL
            window.history.replaceState({}, document.title, window.location.pathname);
            
            return { success: true };
        } else {
            return { success: false, message: data.message || 'Login failed' };
        }
    } catch (error) {
        console.error('[AUTH] Error during direct login process:', error);
        return { success: false, message: 'An error occurred during authentication.' };
    }
}

/**
 * Employee login via API
 */
async function loginEmployee(employeeId, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/employee-login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                employee_id: employeeId,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Store auth data
            storeAuthData(data.token, data.employee);

            // Store auto-login token for future quick access
            if (data.autoLoginToken) {
                localStorage.setItem('auto_login_token', data.autoLoginToken);
                localStorage.setItem('auto_login_url', data.autoLoginUrl);
                localStorage.setItem('auto_login_expiry', data.autoLoginExpiry);
                console.log('[LOGIN] Auto-login token stored');
            }

            return { success: true, data };
        } else {
            return { success: false, message: data.message || 'Login failed' };
        }
    } catch (error) {
        console.error('[LOGIN] Error:', error);
        return { success: false, message: 'Network error. Please try again.' };
    }
}

/**
 * Fetch employee dashboard data
 */
async function fetchDashboardData(employeeId) {
    return apiRequest(`/employee-dashboard/${employeeId}`);
}

/**
 * Fetch forms for employee
 */
async function fetchEmployeeForms(employeeId) {
    return apiRequest(`/forms/${employeeId}`);
}

/**
 * Get SSO form URL
 */
async function getSSOFormUrl(formId, employeeId) {
    return apiRequest(`/open-form/${formId}/${employeeId}`);
}

// ============================================
// LOGIN PAGE FUNCTIONS
// ============================================

/**
 * Initialize login page
 */
function initLoginPage() {
    console.log('[LOGIN-PAGE] Initializing login page');

    // Check if already logged in
    if (isLoggedIn()) {
        console.log('[LOGIN-PAGE] User already logged in, redirecting to dashboard');
        window.location.href = 'dashboard.html';
        return;
    }

    const loginForm = document.getElementById('loginForm');
    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    // Toggle password visibility
    if (togglePassword && passwordInput) {
        togglePassword.addEventListener('click', () => {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);

            const icon = togglePassword.querySelector('i');
            if (icon) {
                icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
            }
        });
    }

    // Handle form submission
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideError();

            const employeeIdInput = document.getElementById('employeeId');
            const passwordInput = document.getElementById('password');
            const rememberMeCheckbox = document.getElementById('rememberMe');
            const loginBtn = document.getElementById('loginBtn');

            if (!employeeIdInput || !passwordInput) return;

            const employeeId = employeeIdInput.value.trim();
            const password = passwordInput.value;

            // Validation
            if (!employeeId || !password) {
                showError('Please enter both Employee ID and Password');
                return;
            }

            // Show loading
            setButtonLoading(loginBtn, true);

            // Attempt login
            const result = await loginEmployee(employeeId, password);

            // Hide loading
            setButtonLoading(loginBtn, false);

            if (result.success) {
                // Remember employee ID if checkbox is checked
                if (rememberMeCheckbox && rememberMeCheckbox.checked) {
                    localStorage.setItem('remembered_employee_id', employeeId);
                } else {
                    localStorage.removeItem('remembered_employee_id');
                }

                showToast('Login successful! Redirecting...');
                setTimeout(() => {
                    window.location.href = 'dashboard.html';
                }, 1000);
            } else {
                showError(result.message);
            }
        });
    }

    // Check for remembered employee ID
    const rememberedId = localStorage.getItem('remembered_employee_id');
    if (rememberedId) {
        const employeeIdInput = document.getElementById('employeeId');
        const rememberMeCheckbox = document.getElementById('rememberMe');
        if (employeeIdInput) employeeIdInput.value = rememberedId;
        if (rememberMeCheckbox) rememberMeCheckbox.checked = true;
    }
}

// ============================================
// DASHBOARD PAGE FUNCTIONS
// ============================================

/**
 * Update navigation with employee info
 */
function updateNavigation(employeeData) {
    const navName = document.getElementById('navEmployeeName');
    const navId = document.getElementById('navEmployeeId');

    if (navName) navName.textContent = employeeData.full_name || 'User';
    if (navId) navId.textContent = employeeData.employee_id || '-';
}

/**
 * Update welcome section
 */
function updateWelcomeSection(employeeData) {
    const welcomeName = document.getElementById('welcomeName');
    const currentDate = document.getElementById('currentDate');

    if (welcomeName) {
        const firstName = employeeData.full_name ? employeeData.full_name.split(' ')[0] : 'User';
        welcomeName.textContent = firstName;
    }

    if (currentDate) {
        currentDate.textContent = formatDate(new Date());
    }
}

/**
 * Update info cards
 */
function updateInfoCards(employeeData) {
    const infoEmployeeId = document.getElementById('infoEmployeeId');
    const infoDivision = document.getElementById('infoDivision');
    const infoDesignation = document.getElementById('infoDesignation');
    const infoHQ = document.getElementById('infoHQ');

    if (infoEmployeeId) infoEmployeeId.textContent = employeeData.employee_id || '-';
    if (infoDivision) infoDivision.textContent = employeeData.division_name || '-';
    if (infoDesignation) infoDesignation.textContent = employeeData.designation || '-';
    if (infoHQ) infoHQ.textContent = employeeData.hq || '-';
}

/**
 * Create form card HTML
 */
function createFormCard(form) {
    return `
        <div class="form-card">
            <div class="form-icon">
                <i class="fas fa-file-alt"></i>
            </div>
            <div class="form-content">
                <h3>${escapeHtml(form.form_name)}</h3>
                <p>Complete this form for your division</p>
                <div class="form-meta">
                    <i class="fas fa-folder"></i>
                    <span>${escapeHtml(form.division_name)}</span>
                    <span>•</span>
                    <span>${formatDateTime(form.created_at)}</span>
                </div>
            </div>
            <button class="btn-open-form" data-form-id="${form.id}" data-form-name="${escapeHtml(form.form_name)}">
                <span>Open Form</span>
                <i class="fas fa-external-link-alt"></i>
            </button>
        </div>
    `;
}

/**
 * Load forms for employee
 */
async function loadForms(employeeId) {
    console.log('[DASHBOARD] Loading forms for employee:', employeeId);

    const formsContainer = document.getElementById('formsContainer');
    const noFormsMessage = document.getElementById('noFormsMessage');
    const formsCount = document.getElementById('formsCount');

    if (!formsContainer) return;

    // Show loading state
    formsContainer.innerHTML = `
        <div class="loading-state">
            <div class="spinner"></div>
            <p>Loading your forms...</p>
        </div>
    `;
    if (noFormsMessage) noFormsMessage.classList.add('hidden');

    try {
        const result = await fetchEmployeeForms(employeeId);
        console.log('[DASHBOARD] Forms API result:', result);

        if (!result || !result.success) {
            console.error('[DASHBOARD] Failed to load forms:', result);
            showToast('Failed to load forms', 'error');

            formsContainer.innerHTML = `
                <div class="error-state">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Failed to load forms. Please try again.</p>
                    <button onclick="loadForms('${employeeId}')" class="btn-retry">Retry</button>
                </div>
            `;
            return;
        }

        const forms = result.forms;

        // Update count
        if (formsCount) {
            formsCount.textContent = forms.length;
        }

        if (forms.length === 0) {
            // No forms available
            formsContainer.innerHTML = '';
            if (noFormsMessage) noFormsMessage.classList.remove('hidden');
        } else {
            // Display forms
            if (noFormsMessage) noFormsMessage.classList.add('hidden');
            formsContainer.innerHTML = forms.map(form => createFormCard(form)).join('');

            // Add click handlers to form buttons
            document.querySelectorAll('.btn-open-form').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    const formId = btn.dataset.formId;
                    const formName = btn.dataset.formName;
                    openFormModal(formId, formName);
                });
            });
        }
    } catch (error) {
        console.error('[DASHBOARD] Error loading forms:', error);
        showToast('Error loading forms', 'error');

        formsContainer.innerHTML = `
            <div class="error-state">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Error loading forms. Please try again.</p>
                <button onclick="loadForms('${employeeId}')" class="btn-retry">Retry</button>
            </div>
        `;
    }
}

/**
 * Load dashboard data and UI
 */
async function loadDashboardData(employeeData) {
    console.log('[DASHBOARD] Loading dashboard data:', employeeData);

    // Load forms
    await loadForms(employeeData.employee_id);
}

/**
 * Initialize dashboard page
 */
async function initDashboard() {
    console.log('[DASHBOARD] Initializing dashboard');

    // Get employee data from localStorage
    let employeeData = getEmployeeData();

    // If no employee data but token exists, try to decode token
    if (!employeeData) {
        const token = getToken();
        if (token) {
            try {
                console.log('[DASHBOARD] No employee data, decoding token...');
                const base64Url = token.split('.')[1];
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
                const payload = JSON.parse(jsonPayload);

                employeeData = {
                    employee_id: payload.employee_id,
                    full_name: payload.full_name,
                    division_id: payload.division_id,
                    division_name: payload.division_name,
                    designation: payload.designation,
                    hq: payload.hq
                };

                // Store for future use
                localStorage.setItem('employee_data', JSON.stringify(employeeData));
                console.log('[DASHBOARD] Employee data decoded and stored:', employeeData);
            } catch (e) {
                console.error('[DASHBOARD] Error decoding token:', e);
            }
        }
    }

    if (!employeeData) {
        console.error('[DASHBOARD] No employee data found in localStorage');
        
        // Check for URL parameters for direct login
        const urlParams = new URLSearchParams(window.location.search);
        const urlEmployeeId = urlParams.get('employeeId');
        const urlDivision = urlParams.get('division');
        
        if (urlEmployeeId && urlDivision) {
            console.log('[DASHBOARD] Attempting direct URL login...');
            
            // Show overlay temporarily
            const overlay = document.getElementById('authCheckOverlay');
            if (overlay) {
                overlay.classList.remove('hidden');
                overlay.innerHTML = `
                    <div class="spinner"></div>
                    <p>Authenticating...</p>
                `;
            }
            
            const loginResult = await performDirectLogin(urlEmployeeId, urlDivision);
            
            if (loginResult.success) {
                // Re-fetch employee data
                employeeData = getEmployeeData();
            } else {
                showToast(loginResult.message || 'Authentication failed.', 'error');
                clearAuthData();
                
                const container = document.querySelector('.dashboard-main');
                if (container) {
                    container.innerHTML = `
                        <div class="error-state" style="margin-top: 50px;">
                            <i class="fas fa-lock" style="font-size: 48px; margin-bottom: 20px;"></i>
                            <h2>Access Denied</h2>
                            <p>${loginResult.message || 'Please ensure your URL contains valid credentials.'}</p>
                        </div>
                    `;
                }
                if (overlay) overlay.classList.add('hidden');
                return;
            }
        } else {
            showToast('Access denied. No valid session.', 'error');
            clearAuthData();
            
            // Show access denied state on UI
            const container = document.querySelector('.dashboard-main');
            if (container) {
                container.innerHTML = `
                    <div class="error-state" style="margin-top: 50px;">
                        <i class="fas fa-lock" style="font-size: 48px; margin-bottom: 20px;"></i>
                        <h2>Access Denied</h2>
                        <p>Please ensure you are authenticated through the main portal.</p>
                    </div>
                `;
            }
            return;
        }
    }

    console.log('[DASHBOARD] Employee data from localStorage:', employeeData);

    // Setup modal
    setupModal();

    // Load dashboard data
    await loadDashboardData(employeeData);
}

// ============================================
// LOGOUT FUNCTIONALITY
// ============================================

/**
 * Setup logout functionality
 */
function setupLogout() {
    const logoutBtn = document.getElementById('logoutBtn');

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            console.log('[AUTH] Logout button clicked');

            // Clear all auth data
            clearAuthData();

            showToast('Logged out successfully');

            // Redirect to dashboard (which will then handle the auth check)
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1000);
        });
    }
}

// ============================================
// MODAL FUNCTIONS
// ============================================

let currentFormId = null;

/**
 * Setup modal handlers
 */
function setupModal() {
    const modal = document.getElementById('formModal');
    const closeModal = document.getElementById('closeModal');

    // Close modal handlers
    if (closeModal) {
        closeModal.addEventListener('click', hideModal);
    }

    // Close on outside click
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                hideModal();
            }
        });
    }
}

/**
 * Open form modal
 */
function openFormModal(formId, formName) {
    const employeeData = getEmployeeData();

    if (!employeeData) {
        showToast('Session expired. Please login again.', 'error');
        return;
    }

    currentFormId = formId;

    // Show modal with loading state
    const modal = document.getElementById('formModal');
    const modalFormName = document.getElementById('modalFormName');
    const formIframe = document.getElementById('formIframe');

    if (modalFormName) modalFormName.textContent = formName || 'Form';
    if (formIframe) formIframe.src = 'about:blank';

    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    // Load the form in iframe
    getSSOFormUrl(formId, employeeData.employee_id)
        .then(result => {
            if (result && result.success) {
                if (formIframe) {
                    formIframe.src = result.form.sso_url;
                }
            } else {
                showToast('Failed to load form', 'error');
                hideModal();
            }
        })
        .catch(error => {
            console.error('[DASHBOARD] Error loading form:', error);
            showToast('Error loading form', 'error');
            hideModal();
        });
}

/**
 * Hide modal
 */
function hideModal() {
    const modal = document.getElementById('formModal');
    const formIframe = document.getElementById('formIframe');

    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
    }

    // Clear iframe src to stop loading and free memory
    if (formIframe) {
        formIframe.src = 'about:blank';
    }

    currentFormId = null;
}

// ============================================
// PAGE INITIALIZATION
// ============================================

/**
 * Initialize page based on current URL
 */
document.addEventListener('DOMContentLoaded', async () => {
    const path = window.location.pathname;
    const currentPage = path.split('/').pop();
    console.log('[APP] Page loaded:', currentPage);

    // If on root or login.html, redirect to dashboard.html
    // Since login.html is being removed, we want everything to go to dashboard
    if (currentPage === 'login.html' || currentPage === '' || currentPage === 'index.html' || path === '/') {
        console.log('[APP] Redirecting to dashboard...');
        window.location.href = 'dashboard.html';
        return;
    }
});

// ============================================
// EXPORTS FOR GLOBAL ACCESS
// ============================================

// Make functions available globally for inline scripts
window.initDashboard = initDashboard;
window.loadForms = loadForms;
window.showToast = showToast;
window.openFormModal = openFormModal;
window.hideModal = hideModal;
