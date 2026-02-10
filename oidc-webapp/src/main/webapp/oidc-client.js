/**
 * OIDC Client Toolkit for Corzia OIDC Example
 * Provides encapsulated logic for Tab management, CSRF protection, and API interaction.
 */

const OidcClient = (() => {
    // --- Internal State & Constants ---
    const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
    const CSRF_HEADER_NAME = 'X-XSRF-TOKEN';
    const TAB_ID_HEADER_NAME = 'X-Tab-Id';
    const TAB_ID_SESSION_KEY = 'tabId';

    // Initialize or retrieve Tab ID
    let currentTabId = sessionStorage.getItem(TAB_ID_SESSION_KEY);
    if (!currentTabId) {
        currentTabId = "tab-" + Math.random().toString(36).substring(2, 9);
        sessionStorage.setItem(TAB_ID_SESSION_KEY, currentTabId);
    }

    // --- Private Utilities ---
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    /**
     * Internal fetch wrapper to include standard security headers.
     */
    async function secureFetch(url, options = {}) {
        const headers = {
            [TAB_ID_HEADER_NAME]: currentTabId,
            ...options.headers
        };

        const csrfToken = getCookie(CSRF_COOKIE_NAME);
        if (csrfToken) {
            headers[CSRF_HEADER_NAME] = csrfToken;
        }

        const response = await fetch(url, { ...options, headers });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: `HTTP ${response.status}` }));
            throw new Error(errorData.message || `Request failed with status ${response.status}`);
        }
        return response.json();
    }

    // --- Public API ---
    return {
        /**
         * Returns the current isolated Tab ID.
         */
        getTabId: () => currentTabId,

        /**
         * Returns a set of standard headers for external use.
         */
        getHeaders: () => {
            const headers = { [TAB_ID_HEADER_NAME]: currentTabId };
            const csrfToken = getCookie(CSRF_COOKIE_NAME);
            if (csrfToken) headers[CSRF_HEADER_NAME] = csrfToken;
            return headers;
        },

        /**
         * Fetches valid OIDC providers from the server.
         */
        fetchProviders: () => secureFetch('api/providers'),

        /**
         * Fetches current session information.
         */
        fetchSession: () => secureFetch('api/session'),

        /**
         * Performs a local credential-based login.
         */
        login: (username, password) => {
            const data = new URLSearchParams();
            data.append('username', username);
            data.append('password', password);

            return secureFetch('api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: data
            });
        },

        /**
         * Returns the correct Logout URL.
         */
        getLogoutUrl: () => `portal/logout?tabId=${currentTabId}`,

        /**
         * Utility to build OIDC login URL for a provider.
         */
        getOidcLoginUrl: (providerName) => `portal/oidc/login?provider=${providerName}&tabId=${currentTabId}`
    };
})();
