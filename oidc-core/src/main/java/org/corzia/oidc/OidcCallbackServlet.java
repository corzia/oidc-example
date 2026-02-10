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
package org.corzia.oidc;

import java.io.IOException;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles the callback/redirect from the OpenID Connect provider.
 *
 * <h2>Responsibility</h2>
 * <p>
 * This servlet is invoked by the identity provider (Entra, Google, ...) after
 * the user has authenticated and consented. It is responsible for:
 * </p>
 * <ol>
 * <li>Validating the {@code state} parameter (CSRF protection)</li>
 * <li>Determining which provider was used</li>
 * <li>Exchanging the authorization {@code code} for tokens via
 * {@link OidcClient}</li>
 * <li>Validating the ID token (signature, issuer, audience, expiry, nonce)</li>
 * <li>Normalizing the identity into {@link OidcUserInfo}</li>
 * <li>Logging the user into Shiro using {@link OidcAuthenticationToken}</li>
 * <li>Redirecting back to the originally requested URL or a default page</li>
 * </ol>
 *
 * <h2>Where the data comes from</h2>
 * <ul>
 * <li>{@code code} – authorization code from the provider (query
 * parameter)</li>
 * <li>{@code state} – value we generated in {@link OidcLoginServlet} and stored
 * in session</li>
 * <li>{@code oidc_provider} – provider type stored by
 * {@link OidcLoginServlet}</li>
 * <li>{@code oidc_nonce} – nonce stored by {@link OidcLoginServlet} for ID
 * token binding</li>
 * </ul>
 *
 * <h2>Interaction with Shiro and the Realm</h2>
 * <p>
 * After we obtain a validated {@link OidcUserInfo}, we:
 * </p>
 * <ol>
 * <li>Optionally store it in a shared {@link OidcUserDirectory} for later role
 * mapping</li>
 * <li>Create an {@link OidcAuthenticationToken}</li>
 * <li>Call
 * {@link Subject#login(org.apache.shiro.authc.AuthenticationToken)}</li>
 * </ol>
 *
 * <p>
 * The {@code OidcRealm} then:
 * </p>
 * <ul>
 * <li>Accepts this token</li>
 * <li>Creates a Shiro {@code Subject} based on the principal</li>
 * <li>On authorization, looks up {@link OidcUserInfo} to map groups →
 * roles</li>
 * </ul>
 */
@WebServlet("/portal/oidc/callback")
public class OidcCallbackServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(OidcCallbackServlet.class);
    private static final long serialVersionUID = 1L;
    private OidcClientFactory clientFactory;

    public OidcCallbackServlet() {
        clientFactory = OidcRealm.getClientFactory();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String code = req.getParameter("code");
        String state = req.getParameter("state");

        HttpSession session = req.getSession(false);
        if (session == null || code == null || state == null) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing auth parameters");
            return;
        }

        String expectedState = (String) session.getAttribute("oidc_state");
        if (!state.equals(expectedState)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state");
            return;
        }

        String providerName = (String) session.getAttribute("oidc_provider");
        String expectedNonce = (String) session.getAttribute("oidc_nonce");

        try {
            OidcClient client = clientFactory.getClient(providerName);

            OidcUserInfo userInfo = client.exchangeCodeForUserInfo(req, code, expectedNonce);

            OidcUserDirectory.put(userInfo);

            // Shiro login
            Subject subject = SecurityUtils.getSubject();
            subject.login(new OidcAuthenticationToken(userInfo));

            session.removeAttribute("oidc_state");
            session.removeAttribute("oidc_nonce");
            session.removeAttribute("oidc_provider");

            String finalRedirect = (String) session.getAttribute("shiroSavedRequestUrl");
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
            String errorUrl = req.getContextPath() + "/error.html?message="
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
