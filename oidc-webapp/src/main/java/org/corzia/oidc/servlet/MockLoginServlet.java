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

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Serves a simple login form to simulate an external OIDC provider.
 */
@WebServlet("/portal/mock/login")
public class MockLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String state = req.getParameter("state");
        String nonce = req.getParameter("nonce");

        String csrfToken = (String) req.getSession().getAttribute("CSRF_TOKEN");

        resp.setContentType("text/html");
        resp.getWriter().write(
                "<!DOCTYPE html>" +
                        "<html lang='en'>" +
                        "<head>" +
                        "    <meta charset='UTF-8'>" +
                        "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>" +
                        "    <title>Login - Mock Provider</title>" +
                        "    <link rel='icon' type='image/png' href='" + req.getContextPath() + "/favicon.png'>" +
                        "    <link href='https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap' rel='stylesheet'>"
                        +
                        "    <style>" +
                        "        :root {" +
                        "            --primary: #6366f1; --primary-hover: #4f46e5; --bg: #0f172a;" +
                        "            --card-bg: #1e293b; --text: #f8fafc; --text-muted: #94a3b8;" +
                        "        }" +
                        "        body {" +
                        "            font-family: 'Outfit', sans-serif; background-color: var(--bg); color: var(--text);"
                        +
                        "            margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh;"
                        +
                        "        }" +
                        "        .card {" +
                        "            background-color: var(--card-bg); border-radius: 1.5rem; padding: 2.5rem;" +
                        "            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); border: 1px solid rgba(255, 255, 255, 0.1);"
                        +
                        "            width: 100%; max-width: 400px; text-align: center;" +
                        "        }" +
                        "        h1 {" +
                        "            font-size: 1.875rem; font-weight: 600; margin-bottom: 0.5rem;" +
                        "            background: linear-gradient(to right, #818cf8, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent;"
                        +
                        "        }" +
                        "        .info { color: var(--text-muted); margin-bottom: 2rem; font-size: 0.875rem; }" +
                        "        .form-group { text-align: left; margin-bottom: 1.5rem; }" +
                        "        label { display: block; margin-bottom: 0.5rem; color: var(--text-muted); font-size: 0.875rem; }"
                        +
                        "        input {" +
                        "            width: 100%; padding: 0.75rem 1rem; border-radius: 0.75rem; background: #0f172a;" +
                        "            border: 1px solid rgba(255, 255, 255, 0.1); color: white; outline: none; box-sizing: border-box;"
                        +
                        "        }" +
                        "        input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); }"
                        +
                        "        .btn {" +
                        "            width: 100%; padding: 0.875rem; border-radius: 0.75rem; border: none;" +
                        "            background: var(--primary); color: white; font-weight: 600; font-size: 1rem;" +
                        "            cursor: pointer; transition: all 0.2s;" +
                        "        }" +
                        "        .btn:hover { background: var(--primary-hover); transform: translateY(-1px); }" +
                        "        .hint { margin-top: 1.5rem; font-size: 0.75rem; color: var(--text-muted); border-top: 1px solid rgba(255, 255, 255, 0.1); padding-top: 1.5rem; }"
                        +
                        "        .hint code { color: #818cf8; background: rgba(129, 140, 248, 0.1); padding: 0.2rem 0.4rem; border-radius: 0.4rem; }"
                        +
                        "    </style>" +
                        "    <script>" +
                        "        function fillEmail(val) {" +
                        "            document.getElementById('email').value = val;" +
                        "        }" +
                        "    </script>" +
                        "</head>" +
                        "<body>" +
                        "    <div class='card'>" +
                        "        <h1>Account Login</h1>" +
                        "        <p class='info'>Simulating OIDC Provider</p>" +
                        "        <form method='POST'>" +
                        "            <input type='hidden' name='state' value='" + state + "'>" +
                        "            <input type='hidden' name='nonce' value='" + nonce + "'>" +
                        "            <input type='hidden' name='_csrf' value='" + csrfToken + "'>" +
                        "            <div class='form-group'>" +
                        "                <label for='email'>Email Address</label>" +
                        "                <input type='email' id='email' name='email' placeholder='name@company.com' required autocomplete='off'>"
                        +
                        "            </div>" +
                        "            <button type='submit' class='btn'>Continue</button>" +
                        "        </form>" +
                        "        <div class='hint'>" +
                        "            Try <code onclick=\"fillEmail('success@example.com')\" style='cursor: pointer;'>success@example.com</code> to pass,<br>"
                        +
                        "            or <code onclick=\"fillEmail('failed@example.com')\" style='cursor: pointer;'>failed@example.com</code> to fail."
                        +
                        "        </div>" +
                        "    </div>" +
                        "</body>" +
                        "</html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String email = req.getParameter("email");
        String state = req.getParameter("state");

        // Redirect back to our callback with the email as the 'code'
        java.util.Properties mockProps = org.corzia.oidc.OidcRealm.getOidcProviderConfig("mock");
        String redirectUri = mockProps.getProperty(org.corzia.oidc.OidcRealm.REDIRECT_URI);

        if (redirectUri == null || redirectUri.isBlank()) {
            // Fallback to relative path if not configured
            redirectUri = req.getContextPath() + "/portal/oidc/callback";
        }

        resp.sendRedirect(redirectUri + "?code=" + email + "&state=" + state);
    }
}
