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
package org.corzia.oidc.config;

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

    private static final String CSRF_TOKEN_SESSION_ATTR = "CSRF_TOKEN";
    private static final String CSRF_TOKEN_COOKIE_NAME = "XSRF-TOKEN";
    private static final String CSRF_TOKEN_HEADER_NAME = "X-XSRF-TOKEN";
    private static final Set<String> UNSAFE_METHODS = Set.of("POST", "PUT", "DELETE", "PATCH");

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
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
        String token = (String) session.getAttribute(CSRF_TOKEN_SESSION_ATTR);

        if (token == null) {
            token = UUID.randomUUID().toString();
            session.setAttribute(CSRF_TOKEN_SESSION_ATTR, token);
        }

        // Always update/set the cookie so the frontend can read it
        Cookie csrfCookie = new Cookie(CSRF_TOKEN_COOKIE_NAME, token);
        csrfCookie.setPath("/");
        csrfCookie.setHttpOnly(false); // Frontend must read this
        // csrfCookie.setSecure(true); // Should be enabled for HTTPS
        httpResponse.addCookie(csrfCookie);

        // Validate unsafe methods
        if (UNSAFE_METHODS.contains(httpRequest.getMethod().toUpperCase())) {
            String headerToken = httpRequest.getHeader(CSRF_TOKEN_HEADER_NAME);
            if (headerToken == null || !headerToken.equals(token)) {
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
                return;
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
