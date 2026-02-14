/**************************************************************************
 * Copyright 2025 Corzia AB, Sweden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************/
package org.corzia.oidc;

/**
 * Centralized constants for OIDC and security strings.
 */
public final class OidcConstants {

    private OidcConstants() {
        // Private constructor to prevent instantiation
    }

    // Configuration Categories
    public static final String CONFIG_SECURITY = "security";

    // Headers
    public static final String HEADER_TAB_ID = "X-Tab-Id";
    public static final String HEADER_CSRF_TOKEN = "X-XSRF-TOKEN";

    // Request Parameters
    public static final String PARAM_TAB_ID = "tabId";
    public static final String PARAM_CSRF_TOKEN = "_csrf";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_CODE = "code";
    public static final String PARAM_PROVIDER = "provider";

    // Session Attributes
    public static final String ATTR_CSRF_TOKEN = "CSRF_TOKEN";
    public static final String ATTR_TAB_ID = "shiro_tab_id";
    public static final String ATTR_OIDC_STATE = "oidc_state";
    public static final String ATTR_OIDC_NONCE = "oidc_nonce";
    public static final String ATTR_OIDC_PROVIDER = "oidc_provider";
    public static final String ATTR_SAVED_REQUEST = "shiroSavedRequestUrl";

    // Cookie Names
    public static final String COOKIE_BROWSER_ID = "JSESSIONID";
    public static final String COOKIE_CSRF_TOKEN = "XSRF-TOKEN";

    // HTTP Methods
    public static final String METHOD_GET = "GET";
    public static final String METHOD_POST = "POST";
    public static final String METHOD_PUT = "PUT";
    public static final String METHOD_DELETE = "DELETE";
    public static final String METHOD_PATCH = "PATCH";

    // Content Types
    public static final String TYPE_JSON = "application/json";
    public static final String TYPE_TEXT = "text/plain";
    public static final String TYPE_FORM = "application/x-www-form-urlencoded";
    public static final String TYPE_HTML = "text/html";

    // Configuration Properties
    public static final String PROP_CSRF_EXEMPT_PATHS = "csrf.exempt_paths";
}
