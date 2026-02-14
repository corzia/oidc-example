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
import jakarta.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.corzia.oidc.OidcAuthenticationToken;
import org.corzia.oidc.OidcClient;
import org.corzia.oidc.OidcClientFactory;
import org.corzia.oidc.OidcConstants;
import org.corzia.oidc.OidcUserInfo;
import org.corzia.oidc.internal.user.OidcUserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@WebServlet("/portal/oidc/callback")
public class OidcCallbackServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(OidcCallbackServlet.class);
    private static final long serialVersionUID = 1L;
    private final OidcClientFactory clientFactory = OidcClientFactory.getInstance();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String code = req.getParameter(OidcConstants.PARAM_CODE);
        String state = req.getParameter(OidcConstants.PARAM_STATE);

        HttpSession session = req.getSession(false);
        if (session == null || code == null || state == null) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing auth parameters");
            return;
        }

        String expectedState = (String) session.getAttribute(OidcConstants.ATTR_OIDC_STATE);
        if (!state.equals(expectedState)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state");
            return;
        }

        String providerName = (String) session.getAttribute(OidcConstants.ATTR_OIDC_PROVIDER);
        String expectedNonce = (String) session.getAttribute(OidcConstants.ATTR_OIDC_NONCE);

        try {
            OidcClient client = clientFactory.getClient(providerName);

            OidcUserInfo userInfo = client.exchangeCodeForUserInfo(req, code, expectedNonce);

            OidcUserDirectory.put(userInfo);

            // Shiro login
            Subject subject = SecurityUtils.getSubject();
            subject.login(new OidcAuthenticationToken(userInfo));

            session.removeAttribute(OidcConstants.ATTR_OIDC_STATE);
            session.removeAttribute(OidcConstants.ATTR_OIDC_NONCE);
            session.removeAttribute(OidcConstants.ATTR_OIDC_PROVIDER);

            String finalRedirect = (String) session.getAttribute(OidcConstants.ATTR_SAVED_REQUEST);
            if (finalRedirect == null) {
                finalRedirect = req.getContextPath() + "/secure.html";
            }

            // Append tabId if we can recover it from the state
            if (state != null && state.contains(":")) {
                String tId = state.split(":")[0];
                finalRedirect += (finalRedirect.contains("?") ? "&" : "?") + "tabId=" + tId;
            }

            resp.sendRedirect(finalRedirect);
        } catch (Exception e) {
            String errorId = java.util.UUID.randomUUID().toString();
            log.error("OIDC callback failed. Error ID: " + errorId, e);

            // Generic message for the user to prevent information leakage
            String message = "Authentication failed. Please contact support.";
            String errorUrl = req.getContextPath() + "/error.html?" + OidcConstants.PARAM_MESSAGE + "="
                    + java.net.URLEncoder.encode(message, "UTF-8")
                    + "&errorId=" + errorId;

            // Append tabId if we can recover it from the state
            if (state != null && state.contains(":")) {
                String tId = state.split(":")[0];
                errorUrl += "&tabId=" + tId;
            }

            resp.sendRedirect(errorUrl);
        }
    }
}
