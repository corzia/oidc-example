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
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import com.nimbusds.jwt.JWTClaimsSet;
import org.corzia.oidc.AbstractOidcClient;
import org.corzia.oidc.OidcUserInfo;
import org.corzia.oidc.internal.utils.HttpUtils;
import org.corzia.oidc.internal.utils.TokenResponse;

/**
 * OIDC client implementation for Okta.
 */
public class OktaOidcClient extends AbstractOidcClient {

    public OktaOidcClient() {
        super("okta");
    }

    @Override
    public String buildAuthorizationUrl(HttpServletRequest request, String state, String nonce) {
        return authorizationEndpoint()
                + "?client_id=" + url(clientId())
                + "&response_type=code"
                + "&redirect_uri=" + url(redirectUri())
                + "&scope=" + url(scope())
                + "&state=" + url(state)
                + "&nonce=" + url(nonce);
    }

    @Override
    public OidcUserInfo exchangeCodeForUserInfo(HttpServletRequest request,
            String code,
            String expectedNonce) throws Exception {

        TokenResponse token = HttpUtils.exchangeCode(
                tokenEndpoint(),
                clientId(),
                clientSecret(),
                code,
                redirectUri());

        JWTClaimsSet claims = validateIdToken(token.getIdToken(), expectedNonce);
        Map<String, Object> claimMap = claims.getClaims();

        String email = (String) claimMap.get("email");
        String subject = (String) claimMap.get("sub");
        String fullName = (String) claimMap.get("name");
        String givenName = (String) claimMap.get("given_name");
        String familyName = (String) claimMap.get("family_name");
        String picture = (String) claimMap.get("picture");
        String locale = (String) claimMap.get("locale");
        boolean emailVerified = Boolean.TRUE.equals(claimMap.get("email_verified"));

        return new OidcUserInfo(
                getName(),
                subject,
                email,
                email,
                fullName,
                givenName,
                familyName,
                picture,
                null, // tenantId not typical in Okta
                locale,
                emailVerified,
                Set.of(),
                token.getIdToken(),
                token.getAccessToken(),
                token.getRefreshToken(),
                claimMap);
    }
}
