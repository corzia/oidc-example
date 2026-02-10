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
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/api/login")
public class LoginServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(LoginServlet.class);

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // Simple JSON content type (assuming filters parse params or we read body)
        // For simplicity, reading query params or form data
        String user = req.getParameter("username");
        String pass = req.getParameter("password");
        String tabId = req.getHeader("X-Tab-Id");

        if (tabId == null || tabId.isBlank()) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "X-Tab-Id header is required");
            return;
        }

        Subject subject = SecurityUtils.getSubject();

        try {
            subject.login(new UsernamePasswordToken(user, pass));
            log.info("User {} logged in successfully on tab {}", user, tabId);

            resp.setContentType("application/json");
            resp.getWriter().write("{\"success\": true, \"sessionId\": \"" + subject.getSession().getId() + "\"}");

        } catch (Exception e) {
            log.error("Login failed", e);
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.getWriter().write("{\"success\": false, \"message\": \"Authentication failed\"}");
        }
    }
}
