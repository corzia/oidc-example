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
import java.util.UUID;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Entry point for starting an OpenID Connect authentication flow.
 *
 * <h2>Responsibility</h2>
 * <p>
 * This servlet does <b>not</b> authenticate the user itself. Instead, it:
 * </p>
 * <ol>
 * <li>Chooses which OIDC provider to use (Entra, Google, ...)</li>
 * <li>Generates {@code state} and {@code nonce} values for security</li>
 * <li>Stores those values in the HTTP session</li>
 * <li>Asks the corresponding {@link OidcClient} to build an authorization
 * URL</li>
 * <li>Redirects the browser to that URL</li>
 * </ol>
 *
 * <p>
 * After the user signs in at the identity provider, the browser is redirected
 * back to {@code /oidc/callback}, which is handled by
 * {@link OidcCallbackServlet}.
 * </p>
 *
 * <h2>How the provider is selected</h2>
 * <p>
 * The provider is selected using the {@code provider} request parameter, e.g.:
 * </p>
 * <ul>
 * <li>{@code /oidc/login?provider=entra}</li>
 * <li>{@code /oidc/login?provider=google}</li>
 * </ul>
 *
 * <p>
 * If the parameter is missing, a default (e.g. ENTRA) can be used.
 * The actual {@link OidcClient} instance is resolved via
 * {@link OidcClientFactory}.
 * </p>
 *
 * <h2>State & nonce</h2>
 * <ul>
 * <li><b>state</b> – protects against CSRF; validated in the callback.</li>
 * <li><b>nonce</b> – binds the ID token to this particular login attempt; also
 * validated in the callback.</li>
 * </ul>
 */
@WebServlet("/portal/oidc/login")
public class OidcLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private OidcClientFactory clientFactory;

    public OidcLoginServlet() {
        clientFactory = OidcRealm.getClientFactory();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String providerParam = req.getParameter("provider");
        if (providerParam == null) {
            // default if you want
            providerParam = "ENTRA";
        }

        String providerName = providerParam.toLowerCase();

        HttpSession session = req.getSession(true);
        String tabId = req.getParameter("tabId");
        String stateValue = UUID.randomUUID().toString();
        // Embed tabId in state so we can recover it in the callback hit
        String state = (tabId != null ? tabId + ":" : "") + stateValue;
        String nonce = UUID.randomUUID().toString();

        session.setAttribute("oidc_state", state);
        session.setAttribute("oidc_nonce", nonce);
        session.setAttribute("oidc_provider", providerName);

        OidcClient client = clientFactory.getClient(providerName);
        if (!client.isConfigured()) {
            resp.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            resp.setContentType("text/plain");
            resp.getWriter().write("Provider '" + providerName + "' is not configured. "
                    + "Please check oidc-providers.properties on the server.");
            return;
        }

        String authorizeUrl = client.buildAuthorizationUrl(req, state, nonce);

        resp.sendRedirect(authorizeUrl);
    }
}
