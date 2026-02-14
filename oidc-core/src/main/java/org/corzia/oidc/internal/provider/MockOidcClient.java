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
package org.corzia.oidc.internal.provider;
import org.corzia.oidc.*;
import org.corzia.oidc.shiro.*;
import org.corzia.oidc.internal.utils.*;
import org.corzia.oidc.internal.jwks.*;

import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.corzia.oidc.AbstractOidcClient;
import org.corzia.oidc.OidcUserInfo;

/**
 * Mock OIDC Client that mimics a real provider flow but stays local.
 * It redirects to a local MockLoginServlet.
 */
public class MockOidcClient extends AbstractOidcClient {

    private boolean enabled = false;

    public MockOidcClient() {
        super("mock");
    }

    @Override
    public void configure(Properties props) {
        super.configure(props);
        this.enabled = "true".equalsIgnoreCase(props.getProperty("enabled"));
    }

    @Override
    public boolean isConfigured() {
        return enabled;
    }

    @Override
    public String getName() {
        return "mock";
    }

    @Override
    public String buildAuthorizationUrl(HttpServletRequest req, String state, String nonce) {
        // Redirect to our local mock login page
        String contextPath = req.getContextPath();
        return contextPath + "/portal/mock/login?state=" + state + "&nonce=" + nonce;
    }

    @Override
    public OidcUserInfo exchangeCodeForUserInfo(HttpServletRequest req, String code, String expectedNonce)
            throws Exception {

        // In our mock, 'code' is the email entered in the mock login page
        if ("failed@example.com".equalsIgnoreCase(code)) {
            throw new Exception("Mock login failed for: " + code);
        }

        if ("success@example.com".equalsIgnoreCase(code)) {
            return new OidcUserInfo(
                    getName(),
                    "mock-sub-" + UUID.randomUUID(),
                    "success_user",
                    "success@example.com",
                    "Success Mock User", // fullName
                    "Success", // givenName
                    "User", // familyName
                    null, // picture
                    null, // tenantId
                    null, // locale
                    true, // emailVerified
                    java.util.Set.of("MOCK_USER", "OFFLINE_ACCESS"),
                    "mock.id.token",
                    "mock.access.token",
                    "mock.refresh.token",
                    Map.of("name", "Success Mock User", "email_verified", true));
        }

        throw new Exception("Unknown mock user: " + code);
    }
}
