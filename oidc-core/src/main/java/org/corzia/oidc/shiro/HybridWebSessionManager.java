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

import java.io.Serializable;
import java.util.UUID;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SimpleSession;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionContext;
import org.corzia.oidc.OidcConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HybridWebSessionManager extends DefaultWebSessionManager {

    private static final Logger log = LoggerFactory.getLogger(HybridWebSessionManager.class);

    // HybridWebSessionManager internal constants (optional to keep here or move to
    // OidcConstants)
    // User requested to make constants of API strings, so let's use OidcConstants
    // where possible.

    public HybridWebSessionManager() {
        super();
        setSessionIdCookieEnabled(false);
        setSessionIdUrlRewritingEnabled(false);
    }

    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String browserId = getCookieValue(httpRequest, OidcConstants.COOKIE_BROWSER_ID);
        String tabId = resolveTabId(httpRequest);

        log.debug("getSessionId inputs - Cookie: {}, TabId: {}", browserId, tabId);

        if (browserId != null) {
            String composite = browserId + "_" + tabId;
            System.out.println("DEBUG: getSessionId resolved: " + composite);
            return composite;
        }
        return null;
    }

    @Override
    protected Session doCreateSession(SessionContext context) {
        WebSessionContext wsc = (WebSessionContext) context;
        HttpServletRequest request = (HttpServletRequest) wsc.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) wsc.getServletResponse();

        String browserId = getCookieValue(request, OidcConstants.COOKIE_BROWSER_ID);
        if (browserId == null) {
            browserId = UUID.randomUUID().toString();
            setCookie(response, OidcConstants.COOKIE_BROWSER_ID, browserId);
            log.debug("Generated new Browser ID: {}", browserId);
        }

        String tabId = resolveTabId(request);
        String compositeId = browserId + "_" + tabId;

        log.debug("doCreateSession: Creating session with ID {}", compositeId);

        SimpleSession session = new SimpleSession();
        session.setId(compositeId);
        session.setHost(wsc.getHost());
        session.setAttribute(OidcConstants.ATTR_TAB_ID, tabId);

        ((org.apache.shiro.session.mgt.DefaultSessionManager) this).getSessionDAO().create(session);

        return session;
    }

    protected String resolveTabId(HttpServletRequest request) {
        String tabId = request.getHeader(OidcConstants.HEADER_TAB_ID);
        if (tabId == null || tabId.isBlank()) {
            tabId = request.getParameter(OidcConstants.PARAM_TAB_ID);
        }
        if (tabId == null || tabId.isBlank()) {
            String state = request.getParameter(OidcConstants.PARAM_STATE);
            if (state != null && state.contains(":")) {
                tabId = state.split(":")[0];
            }
        }
        return (tabId == null || tabId.isBlank()) ? "default" : tabId;
    }

    // onStart is typically called by onStart(Session, SessionContext) in
    // AbstractNativeSessionManager
    // If override fails, the signature might be (Session) or (Session,
    // SessionContext).
    // Let's remove the override and rely on setSessionIdCookieEnabled(false) to
    // prevent cookie writing.

    private String getCookieValue(HttpServletRequest req, String name) {
        if (req.getCookies() == null)
            return null;
        for (jakarta.servlet.http.Cookie c : req.getCookies()) {
            if (name.equals(c.getName()))
                return c.getValue();
        }
        return null;
    }

    private void setCookie(HttpServletResponse res, String name, String val) {
        jakarta.servlet.http.Cookie c = new jakarta.servlet.http.Cookie(name, val);
        c.setPath("/");
        c.setHttpOnly(true);
        c.setMaxAge(-1); // Session scope
        res.addCookie(c);
    }
}
