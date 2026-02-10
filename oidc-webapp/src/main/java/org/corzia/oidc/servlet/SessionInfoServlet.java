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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.session.Session;
import org.corzia.oidc.OidcUserDirectory;
import org.corzia.oidc.UserInfo;
import org.json.JSONObject;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/api/session")
public class SessionInfoServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            Subject subject = SecurityUtils.getSubject();
            resp.setContentType("application/json");

            String tabId = null;
            Session session = subject.getSession(false);
            if (session != null) {
                tabId = (String) session
                        .getAttribute(org.corzia.oidc.config.HybridWebSessionManager.SESSION_ATTR_TAB_ID);
            }
            if (tabId == null) {
                tabId = req.getHeader("X-Tab-Id");
            }

            String browserId = null;
            if (req.getCookies() != null) {
                for (jakarta.servlet.http.Cookie c : req.getCookies()) {
                    if ("OIDC_BROWSER_ID".equals(c.getName())) {
                        browserId = c.getValue();
                    }
                }
            }

            JSONObject json = new JSONObject();
            json.put("authenticated", subject.isAuthenticated());
            json.put("user", subject.getPrincipal() != null ? subject.getPrincipal().toString() : null);
            json.put("sessionId", session != null ? session.getId() : null);
            json.put("tabId", tabId);
            json.put("browserId", browserId);

            if (subject.isAuthenticated()) {
                Object principal = subject.getPrincipal();
                if (principal instanceof UserInfo) {
                    json.put("userInfo", ((UserInfo) principal).toJson());
                } else if (principal instanceof String) {
                    String username = (String) principal;
                    UserInfo userInfo = OidcUserDirectory.get(username);
                    if (userInfo != null) {
                        json.put("userInfo", userInfo.toJson());
                    }
                }
            }

            resp.getWriter().write(json.toString());
        } catch (Exception e) {
            org.slf4j.LoggerFactory.getLogger(SessionInfoServlet.class).error("Failed to retrieve session info", e);
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write("{\"success\": false, \"message\": \"Internal server error\"}");
        }
    }
}
