// Authentication module for Python Network Dashboard
// This script handles cookie-based authentication for API requests

(function() {
    'use strict';

    // Global auth state
    let authRequired = false;
    let terminateEnabled = true;
    let isAuthenticated = false;

    // Fetch configuration on startup
    async function fetchConfig() {
        try {
            const response = await fetch('/api/config', {
                credentials: 'include'  // Include cookies
            });
            const config = await response.json();
            authRequired = config.auth_required;
            terminateEnabled = config.terminate_enabled;

            if (authRequired && !isAuthenticated) {
                await checkAuth();
            }
        } catch (error) {
            console.error('Failed to fetch config:', error);
        }
    }

    // Check if already authenticated via cookie
    async function checkAuth() {
        try {
            const response = await fetch('/api/system', {
                credentials: 'include'
            });
            if (response.ok) {
                isAuthenticated = true;
            } else if (response.status === 401) {
                showTokenPrompt();
            }
        } catch (error) {
            showTokenPrompt();
        }
    }

    // Show token input modal and login
    async function showTokenPrompt() {
        const token = prompt('Enter Dashboard Token:\n(Required for API access)');
        if (token) {
            await loginWithToken(token);
        }
    }

    // Login with token and set httpOnly cookie
    async function loginWithToken(token) {
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',  // Include cookies
                body: JSON.stringify({ token: token })
            });

            if (response.ok) {
                isAuthenticated = true;
                location.reload();
            } else {
                const data = await response.json();
                alert('Authentication failed: ' + (data.error || 'Invalid token'));
                showTokenPrompt();
            }
        } catch (error) {
            console.error('Login error:', error);
            alert('Login failed. Please try again.');
        }
    }

    // Logout and clear cookie
    async function logout() {
        try {
            await fetch('/api/logout', {
                method: 'POST',
                credentials: 'include'
            });
            isAuthenticated = false;
            location.reload();
        } catch (error) {
            console.error('Logout error:', error);
        }
    }

    // Enhanced fetch with credentials (includes httpOnly cookies automatically)
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        if (url.startsWith('/api/')) {
            options.credentials = 'include';  // Always include cookies for API calls
        }
        return originalFetch(url, options).then(response => {
            if (response.status === 401) {
                isAuthenticated = false;
                showTokenPrompt();
                throw new Error('Authentication required');
            }
            return response;
        });
    };

    // Expose utility functions
    window.dashboardAuth = {
        isAuthRequired: () => authRequired,
        isTerminateEnabled: () => terminateEnabled,
        isAuthenticated: () => isAuthenticated,
        logout: logout,
        updateToken: () => {
            showTokenPrompt();
        }
    };

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', fetchConfig);
    } else {
        fetchConfig();
    }
})();
