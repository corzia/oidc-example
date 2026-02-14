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
package org.corzia.oidc.shiro;

import org.corzia.oidc.OidcConstants;

import org.corzia.oidc.internal.config.*;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

/**
 * A custom CSRF filter that implements the Synchronizer Token Pattern.
 * - Generates a token and stores it in the session.
 * - Exposes the token via a non-HttpOnly cookie (XSRF-TOKEN) for frontend
 * access.
 * - Validates the X-XSRF-TOKEN header for unsafe methods (POST, PUT, DELETE,
 * PATCH).
 */
public class CsrfFilter implements Filter {

    private static final Set<String> UNSAFE_METHODS = Set.of(
            OidcConstants.METHOD_POST,
            OidcConstants.METHOD_PUT,
            OidcConstants.METHOD_DELETE,
            OidcConstants.METHOD_PATCH);
    private static final Set<String> exemptPaths = new java.util.HashSet<>();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Properties securityProps = OidcConfigManager.getSecurityConfig(OidcConstants.CONFIG_SECURITY);
        String paths = securityProps.getProperty(OidcConstants.PROP_CSRF_EXEMPT_PATHS);
        if (paths != null && !paths.isBlank()) {
            for (String p : paths.split(",")) {
                exemptPaths.add(p.trim());
            }
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest httpRequest)
                || !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpSession session = httpRequest.getSession(true);
        String token = (String) session.getAttribute(OidcConstants.ATTR_CSRF_TOKEN);

        // Race condition fix: If session has no token, adopt it from the cookie if
        // present.
        // This ensures that when Shiro switches from 'default' session to a
        // tab-specific one,
        // the CSRF token remains stable for the browser.
        if (token == null) {
            String cookieToken = getCookieValue(httpRequest, OidcConstants.COOKIE_CSRF_TOKEN);
            if (cookieToken != null && !cookieToken.isBlank()) {
                token = cookieToken;
                session.setAttribute(OidcConstants.ATTR_CSRF_TOKEN, token);
            } else {
                token = UUID.randomUUID().toString();
                session.setAttribute(OidcConstants.ATTR_CSRF_TOKEN, token);
            }
        }

        // Always update/set the cookie so the frontend can read it
        Cookie csrfCookie = new Cookie(OidcConstants.COOKIE_CSRF_TOKEN, token);
        csrfCookie.setPath("/");
        csrfCookie.setHttpOnly(false); // Frontend must read this
        if (httpRequest.isSecure()) {
            csrfCookie.setSecure(true);
        }
        httpResponse.addCookie(csrfCookie);

        // Validate unsafe methods
        String requestUri = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        String relativePath = contextPath.isEmpty() ? requestUri : requestUri.substring(contextPath.length());
        boolean isExempt = exemptPaths.stream().anyMatch(p -> relativePath.startsWith(p));

        if (!isExempt && UNSAFE_METHODS.contains(httpRequest.getMethod().toUpperCase())) {
            String headerToken = httpRequest.getHeader(OidcConstants.HEADER_CSRF_TOKEN);
            String paramToken = httpRequest.getParameter(OidcConstants.PARAM_CSRF_TOKEN);

            if ((headerToken == null || !headerToken.equals(token)) &&
                    (paramToken == null || !paramToken.equals(token))) {
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private String getCookieValue(HttpServletRequest req, String name) {
        if (req.getCookies() == null)
            return null;
        for (Cookie c : req.getCookies()) {
            if (name.equals(c.getName()))
                return c.getValue();
        }
        return null;
    }

    @Override
    public void destroy() {
    }
}
