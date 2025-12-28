// Authentication module for Python Network Dashboard
// This script handles token-based authentication for API requests

(function() {
    'use strict';

    // Global auth state
    let authToken = localStorage.getItem('dashboard_token') || '';
    let authRequired = false;
    let terminateEnabled = true;

    // Fetch configuration on startup
    async function fetchConfig() {
        try {
            const response = await fetch('/api/config');
            const config = await response.json();
            authRequired = config.auth_required;
            terminateEnabled = config.terminate_enabled;

            if (authRequired && !authToken) {
                showTokenPrompt();
            }
        } catch (error) {
            console.error('Failed to fetch config:', error);
        }
    }

    // Show token input modal
    function showTokenPrompt() {
        const token = prompt('Enter Dashboard Token:\n(Required for API access)');
        if (token) {
            authToken = token;
            localStorage.setItem('dashboard_token', token);
            location.reload();
        }
    }

    // Enhanced fetch with auth header
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        if (authToken && url.startsWith('/api/')) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = `Bearer ${authToken}`;
        }
        return originalFetch(url, options).then(response => {
            if (response.status === 401) {
                localStorage.removeItem('dashboard_token');
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
        clearToken: () => {
            localStorage.removeItem('dashboard_token');
            authToken = '';
            location.reload();
        },
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
