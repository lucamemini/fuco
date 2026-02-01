/**
 * auth.js - Centralized authentication management
 * Includes login modal HTML, CSS, and all auth functions
 */

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Create login modal HTML once when script loads
document.addEventListener('DOMContentLoaded', function() {
    // Inject modal only if it doesn't already exist
    if (!document.getElementById('loginModal')) {
        const modalHTML = `
<div id="loginModal" class="login-modal-overlay">
  <div class="login-modal">
    <h2>Login</h2>
    <div class="form-group">
      <label for="loginUsername">Username</label>
      <input type="text" id="loginUsername" placeholder="Enter username" />
    </div>
    <div class="form-group">
      <label for="loginPassword">Password</label>
      <input type="password" id="loginPassword" placeholder="Enter password" />
    </div>
    <div class="login-modal-buttons">
      <button type="button" class="btn-cancel" onclick="closeLoginModal()">Cancel</button>
      <button type="button" class="btn-submit" onclick="submitLogin()">Login</button>
    </div>
  </div>
</div>
        `;
        document.body.insertAdjacentHTML('afterbegin', modalHTML);
    }
    
    // Setup keyboard handlers for login modal
    const loginPassword = document.getElementById('loginPassword');
    if (loginPassword) {
        loginPassword.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                submitLogin();
            }
        });
    }
    
    const loginUsername = document.getElementById('loginUsername');
    if (loginUsername) {
        loginUsername.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                document.getElementById('loginPassword').focus();
            }
        });
    }
    
    // Check auth status on page load
    checkAuthStatus();
});

// Global auth state
window.authState = {
    authenticated: false,
    username: null
};

// Auth Management Functions
async function checkAuthStatus() {
    try {
        const response = await fetch('/api/auth/status');
        const data = await response.json();
        
        if (data.authenticated) {
            showLoggedIn(data.username);
            updateAuthState(true, data.username);
        } else {
            showLoggedOut();
            updateAuthState(false, null);
        }
    } catch (error) {
        console.error('Error checking auth:', error);
        showLoggedOut();
        updateAuthState(false, null);
    }
}

function updateAuthState(authenticated, username) {
    window.authState.authenticated = authenticated;
    window.authState.username = username;
    updateAuthDependentUI(authenticated);
}

function updateAuthDependentUI(authenticated) {
    const authRequiredElements = document.querySelectorAll('[data-requires-auth="true"], .requires-auth');
    authRequiredElements.forEach((el) => {
        if (el.tagName === 'BUTTON' || el.tagName === 'A') {
            if (authenticated) {
                el.classList.remove('disabled');
                el.removeAttribute('aria-disabled');
                el.removeAttribute('disabled');
                el.title = el.getAttribute('data-auth-title') || el.title || '';
            } else {
                el.classList.add('disabled');
                el.setAttribute('aria-disabled', 'true');
                if (el.tagName === 'BUTTON') {
                    el.setAttribute('disabled', 'disabled');
                }
                el.title = 'Login required';
            }
        }
    });

    if (typeof window.updateSubmitButtonState === 'function') {
        window.updateSubmitButtonState();
    }
}

// Expose for dynamic UI updates
window.updateAuthDependentUI = updateAuthDependentUI;

function showLoggedIn(username) {
    const loginNav = document.getElementById('loginNav');
    const userNav = document.getElementById('userNav');
    const bulkNav = document.getElementById('bulkNav');
    
    if (loginNav) loginNav.classList.add('d-none');
    if (userNav) userNav.classList.remove('d-none');
    
    if (bulkNav) {
        const link = bulkNav.querySelector('a');
        if (link) link.classList.remove('disabled');
    }
    
    const usernameDisplay = document.getElementById('usernameDisplay');
    const userInitial = document.getElementById('userInitial');
    
    if (usernameDisplay) usernameDisplay.textContent = username;
    if (userInitial) userInitial.textContent = username.charAt(0).toUpperCase();
}

function showLoggedOut() {
    const loginNav = document.getElementById('loginNav');
    const userNav = document.getElementById('userNav');
    const bulkNav = document.getElementById('bulkNav');
    
    if (loginNav) loginNav.classList.remove('d-none');
    if (userNav) userNav.classList.add('d-none');
    
    if (bulkNav) {
        const link = bulkNav.querySelector('a');
        if (link) link.classList.add('disabled');
    }
}

function handleLogin() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.add('show');
        const usernameInput = document.getElementById('loginUsername');
        if (usernameInput) usernameInput.focus();
    }
}

function closeLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) modal.classList.remove('show');
    
    const usernameInput = document.getElementById('loginUsername');
    const passwordInput = document.getElementById('loginPassword');
    if (usernameInput) usernameInput.value = '';
    if (passwordInput) passwordInput.value = '';
}

async function submitLogin() {
    const usernameInput = document.getElementById('loginUsername');
    const passwordInput = document.getElementById('loginPassword');
    
    const username = usernameInput ? usernameInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value : '';
    
    if (!username || !password) {
        alert('Please enter both username and password');
        return;
    }
    
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            closeLoginModal();
            showLoggedIn(data.username);
            updateAuthState(true, data.username);
            //alert('Login successful!');
        } else {
            alert('Login failed: ' + data.error);
        }
    } catch (error) {
        alert('Login error: ' + error.message);
    }
}

async function handleLogout() {
    if (!confirm('Logout?')) return;
    
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'X-CSRFToken': getCsrfToken() }
        });
        showLoggedOut();
        updateAuthState(false, null);
        location.reload();
    } catch (error) {
        alert('Logout error: ' + error.message);
    }
}
