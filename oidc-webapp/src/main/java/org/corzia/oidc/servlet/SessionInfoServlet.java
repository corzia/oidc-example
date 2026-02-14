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
package org.corzia.oidc.servlet;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.corzia.oidc.OidcConstants;
import org.corzia.oidc.UserInfo;
import org.corzia.oidc.internal.user.OidcUserDirectory;
import org.json.JSONObject;

@WebServlet("/api/session")
public class SessionInfoServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(SessionInfoServlet.class);
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            Subject subject = SecurityUtils.getSubject();
            resp.setContentType(OidcConstants.TYPE_JSON);

            String tabId = null;
            Session session = subject.getSession(false);
            if (session != null) {
                tabId = (String) session.getAttribute(OidcConstants.ATTR_TAB_ID);
            }
            if (tabId == null) {
                tabId = req.getHeader(OidcConstants.HEADER_TAB_ID);
            }

            String browserId = null;
            if (req.getCookies() != null) {
                for (jakarta.servlet.http.Cookie c : req.getCookies()) {
                    if (OidcConstants.COOKIE_BROWSER_ID.equals(c.getName())) {
                        browserId = c.getValue();
                    }
                }
            }

            JSONObject json = new JSONObject();
            json.put(OidcConstants.JKEY_SUCCESS, true); // Added success for consistency
            json.put(OidcConstants.JKEY_AUTHENTICATED, subject.isAuthenticated());
            json.put(OidcConstants.JKEY_USER,
                    subject.getPrincipal() != null ? subject.getPrincipal().toString() : null);
            json.put(OidcConstants.JKEY_SESSION_ID, session != null ? session.getId() : null);
            json.put(OidcConstants.JKEY_TAB_ID, tabId);
            json.put(OidcConstants.JKEY_BROWSER_ID, browserId);

            if (subject.isAuthenticated()) {
                Object principal = subject.getPrincipal();
                if (principal instanceof UserInfo) {
                    json.put(OidcConstants.JKEY_USER_INFO, ((UserInfo) principal).toJson());
                } else if (principal instanceof String) {
                    String username = (String) principal;
                    UserInfo userInfo = OidcUserDirectory.get(username);
                    if (userInfo != null) {
                        json.put(OidcConstants.JKEY_USER_INFO, userInfo.toJson());
                    }
                }
            }

            resp.getWriter().write(json.toString());
        } catch (Exception e) {
            log.error("Failed to retrieve session info", e);
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write("{\"" + OidcConstants.JKEY_SUCCESS + "\": false, \"" + OidcConstants.JKEY_MESSAGE
                    + "\": \"Internal server error\"}");
        }
    }
}