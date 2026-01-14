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

import org.apache.shiro.authc.AuthenticationToken;

/**
 * Shiro {@link AuthenticationToken} implementation that wraps an
 * {@link OidcUserInfo} produced by an OpenID Connect login flow.
 * <p>
 * Conceptually, this token represents "a user that has successfully
 * authenticated with an external OIDC identity provider, and we now
 * want to log them into Shiro".
 * </p>
 *
 * <p>
 * Credentials in this case are not a password, but the already validated
 * ID token (JWT). The {@link com.example.security.oidc.OidcRealm} trusts
 * the ID token once it has been verified by the OIDC client.
 * </p>
 */
public class OidcAuthenticationToken implements AuthenticationToken {

    private static final long serialVersionUID = 1L;
	private final OidcUserInfo userInfo;

    /**
     * @param userInfo normalized user information from the IdP
     */
    public OidcAuthenticationToken(OidcUserInfo userInfo) {
        this.userInfo = userInfo;
    }

    /**
     * @return full OIDC user info object for advanced use (e.g. roles mapping).
     */
    public OidcUserInfo getUserInfo() {
        return userInfo;
    }

    /**
     * @return principal used by Shiro, typically a username or email.
     */
    @Override
    public Object getPrincipal() {
        return userInfo.getUsername();
    }
    /**
     * @return credentials used by Shiro for this login; here we expose the ID token,
     *         but the Realm does not need to re-verify it if the OIDC client already did.
     */
    @Override
    public Object getCredentials() {
        return userInfo.getIdToken();
    }
}
