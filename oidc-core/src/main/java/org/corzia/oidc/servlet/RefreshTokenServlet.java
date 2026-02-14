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
import org.corzia.oidc.*;
import org.corzia.oidc.shiro.*;
import org.corzia.oidc.internal.user.*;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.corzia.oidc.OidcUserInfo;
import org.corzia.oidc.internal.user.OidcUserDirectory;
import org.corzia.oidc.internal.utils.HttpUtils;
import org.corzia.oidc.internal.utils.TokenResponse;
import org.corzia.oidc.OidcClient;
import org.corzia.oidc.OidcClientFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Servlet that attempts to refresh the access token using the stored refresh
 * token.
 * It reads the current authenticated user's OidcUserInfo, extracts the refresh
 * token,
 * and calls the provider's token endpoint via
 * {@link HttpUtils#refreshAccessToken}.
 *
 * For simplicity this implementation supports ENTRA and GOOGLE providers.
 * If the refresh token is missing or the provider is unsupported, a 400
 * response is returned.
 */
public class RefreshTokenServlet extends jakarta.servlet.http.HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(RefreshTokenServlet.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not authenticated");
            return;
        }
        String username = (String) subject.getPrincipal();
        org.corzia.oidc.UserInfo userInfo = OidcUserDirectory.get(username);
        if (userInfo == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "User info not found");
            return;
        }
        if (!(userInfo instanceof OidcUserInfo oidcUserInfo)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "User is not an OIDC user");
            return;
        }

        String refreshToken = oidcUserInfo.getRefreshToken();
        if (refreshToken == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No refresh token available");
            return;
        }
        String providerName = oidcUserInfo.getProviderName();
        try {
            OidcClient client = OidcClientFactory.getInstance().getClient(providerName);
            TokenResponse newTokens = HttpUtils.refreshAccessToken(
                    client.tokenEndpoint(),
                    client.clientId(),
                    client.clientSecret(),
                    refreshToken);

            // Update stored user info with new tokens (simplified)
            OidcUserInfo updated = new OidcUserInfo(
                    oidcUserInfo.getProviderName(),
                    oidcUserInfo.getSubject(),
                    oidcUserInfo.getUsername(),
                    oidcUserInfo.getEmail(),
                    oidcUserInfo.getFullName(),
                    oidcUserInfo.getGivenName(),
                    oidcUserInfo.getFamilyName(),
                    oidcUserInfo.getPicture(),
                    oidcUserInfo.getTenantId(),
                    oidcUserInfo.getLocale(),
                    oidcUserInfo.isEmailVerified(),
                    oidcUserInfo.getGroups(),
                    newTokens.getIdToken(),
                    newTokens.getAccessToken(),
                    newTokens.getRefreshToken(),
                    oidcUserInfo.getClaims());
            OidcUserDirectory.put(username, updated);
            response.setContentType("application/json");
            PrintWriter out = response.getWriter();
            out.print("{\"status\":\"refreshed\",\"accessToken\":\"" + newTokens.getAccessToken() + "\"}");
            out.flush();
        } catch (Exception e) {
            log.error("Refresh failed for user {}", username, e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Refresh failed. Please sign in again.");
        }
    }
}
