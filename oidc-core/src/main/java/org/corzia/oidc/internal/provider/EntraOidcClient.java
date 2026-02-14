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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import com.nimbusds.jwt.JWTClaimsSet;
import org.corzia.oidc.AbstractOidcClient;
import org.corzia.oidc.OidcUserInfo;
import org.corzia.oidc.internal.utils.HttpUtils;
import org.corzia.oidc.internal.utils.TokenResponse;

public class EntraOidcClient extends AbstractOidcClient {

        public EntraOidcClient() {
                super("entra");
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

                String username = (String) claimMap.getOrDefault(
                                "preferred_username",
                                claimMap.get("email"));

                String subject = (String) claimMap.get("oid");

                @SuppressWarnings("unchecked")
                Set<String> groups = claimMap.containsKey("groups")
                                ? new HashSet<>((List<String>) claimMap.get("groups"))
                                : Set.of();

                String fullName = (String) claimMap.get("name");
                String givenName = (String) claimMap.get("given_name");
                String familyName = (String) claimMap.get("family_name");
                String picture = (String) claimMap.get("picture");
                String tenantId = (String) claimMap.get("tid");
                String locale = (String) claimMap.get("locale");
                boolean emailVerified = Boolean.TRUE.equals(claimMap.get("email_verified"));

                return new OidcUserInfo(
                                getName(),
                                subject,
                                username,
                                (String) claimMap.get("email"),
                                fullName,
                                givenName,
                                familyName,
                                picture,
                                tenantId,
                                locale,
                                emailVerified,
                                groups,
                                token.getIdToken(),
                                token.getAccessToken(),
                                token.getRefreshToken(),
                                claimMap);
        }

}
