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
package org.corzia.oidc.api;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class ApiTokenRealm extends AuthorizingRealm {

    public ApiTokenRealm() {
        setAuthenticationTokenClass(BearerToken.class);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        BearerToken bearerToken = (BearerToken) token;
        String tokenString = bearerToken.getToken();

        try {
            com.nimbusds.jwt.SignedJWT signedJWT = com.nimbusds.jwt.SignedJWT.parse(tokenString);
            com.nimbusds.jwt.JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            java.util.Date expirationTime = claims.getExpirationTime();
            if (expirationTime != null && new java.util.Date().after(expirationTime)) {
                throw new AuthenticationException("Token expired");
            }

            String subject = claims.getSubject();
            if (subject == null) {
                throw new AuthenticationException("Token has no subject");
            }

            return new SimpleAuthenticationInfo(subject, tokenString, getName());
        } catch (java.text.ParseException e) {
            throw new AuthenticationException("Invalid token format", e);
        }
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // Retrieve roles/permissions relative to the API token if needed
        return new SimpleAuthorizationInfo();
    }
}
