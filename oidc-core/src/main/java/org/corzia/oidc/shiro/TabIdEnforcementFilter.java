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

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.corzia.oidc.OidcConstants;

/**
 * Filter that enforces the "Master" tabId from the session store.
 * If a session is established and has a stored tabId, it overrides any tabId
 * provided in the URL or headers.
 */
public class TabIdEnforcementFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(false);

        if (session != null) {
            String masterTabId = (String) session.getAttribute(OidcConstants.ATTR_TAB_ID);
            if (masterTabId != null) {
                // Wrap the request to enforce the master Tab ID
                httpRequest = new TabIdHttpServletRequestWrapper(httpRequest, masterTabId);
            }
        }

        chain.doFilter(httpRequest, response);
    }

    private static class TabIdHttpServletRequestWrapper extends HttpServletRequestWrapper {
        private final String masterTabId;

        public TabIdHttpServletRequestWrapper(HttpServletRequest request, String masterTabId) {
            super(request);
            this.masterTabId = masterTabId;
        }

        @Override
        public String getParameter(String name) {
            if (OidcConstants.PARAM_TAB_ID.equals(name)) {
                return masterTabId;
            }
            return super.getParameter(name);
        }

        @Override
        public String getHeader(String name) {
            if (OidcConstants.HEADER_TAB_ID.equalsIgnoreCase(name)) {
                return masterTabId;
            }
            return super.getHeader(name);
        }
    }
}
