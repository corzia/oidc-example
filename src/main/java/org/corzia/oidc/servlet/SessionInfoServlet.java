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
        Subject subject = SecurityUtils.getSubject();

        resp.setContentType("application/json");

        String tabId = req.getHeader("X-Tab-Id");
        String browserId = null;
        if (req.getCookies() != null) {
            for (jakarta.servlet.http.Cookie c : req.getCookies()) {
                if ("OIDC_BROWSER_ID".equals(c.getName())) {
                    browserId = c.getValue();
                }
            }
        }

        resp.getWriter().write("{"
                + "\"authenticated\": " + subject.isAuthenticated() + ", "
                + "\"user\": \"" + (subject.getPrincipal() != null ? subject.getPrincipal() : "null") + "\", "
                + "\"sessionId\": \"" + (subject.getSession(false) != null ? subject.getSession(false).getId() : "null")
                + "\", "
                + "\"tabId\": \"" + (tabId != null ? tabId : "null") + "\", "
                + "\"browserId\": \"" + (browserId != null ? browserId : "null") + "\""
                + "}");
    }
}
