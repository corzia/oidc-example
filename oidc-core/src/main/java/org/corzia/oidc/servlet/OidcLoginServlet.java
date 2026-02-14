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
import java.util.UUID;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.corzia.oidc.OidcClient;
import org.corzia.oidc.OidcClientFactory;
import org.corzia.oidc.OidcConstants;

@WebServlet("/portal/oidc/login")
public class OidcLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final OidcClientFactory clientFactory = OidcClientFactory.getInstance();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String providerParam = req.getParameter(OidcConstants.PARAM_PROVIDER);
        if (providerParam == null) {
            // default if you want
            providerParam = "ENTRA";
        }

        String providerName = providerParam.toLowerCase();

        HttpSession session = req.getSession(true);
        String tabId = req.getParameter(OidcConstants.PARAM_TAB_ID);
        String stateValue = UUID.randomUUID().toString();
        // Embed tabId in state so we can recover it in the callback hit
        String state = (tabId != null ? tabId + ":" : "") + stateValue;
        String nonce = UUID.randomUUID().toString();

        session.setAttribute(OidcConstants.ATTR_OIDC_STATE, state);
        session.setAttribute(OidcConstants.ATTR_OIDC_NONCE, nonce);
        session.setAttribute(OidcConstants.ATTR_OIDC_PROVIDER, providerName);

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
