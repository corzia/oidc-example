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

import java.util.Properties;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.corzia.oidc.jwks.JwksKeyCache;

/**
 * Convenience base class for {@link OidcClient} implementations.
 * <p>
 * This class provides shared functionality that almost all providers need:
 * </p>
 * <ul>
 * <li>Caching and resolving signing keys from a JWKS endpoint</li>
 * <li>ID token signature verification</li>
 * <li>Standard OIDC claim validation (issuer, audience, expiry, nonce)</li>
 * </ul>
 *
 * <p>
 * Concrete subclasses only need to implement provider-specific details,
 * such as endpoints, issuer and scopes, and then call
 * {@link #validateIdToken(String, String)} when they receive an ID token.
 * </p>
 */

public abstract class AbstractOidcClient implements OidcClient {

    private JwksKeyCache jwksKeyCache;
    protected Properties props;
    protected final String providerName;

    protected AbstractOidcClient(String providerName) {
        this.providerName = providerName;
    }

    @Override
    public void configure(Properties props) {
        this.props = props;
        this.jwksKeyCache = new JwksKeyCache(jwksUri());
    }

    /**
     * Validates the given ID token (JWT) using the provider's JWKS keys and
     * standard OIDC rules.
     * <p>
     * This method will:
     * </p>
     * <ul>
     * <li>Parse the JWT and select the appropriate key from JWKS using
     * {@code kid}</li>
     * <li>Verify the signature using RSA</li>
     * <li>Check issuer equals {@link #issuer()}</li>
     * <li>Check audience contains {@link #clientId()}</li>
     * <li>Check the token is not expired</li>
     * <li>Optionally validate the {@code nonce} claim</li>
     * </ul>
     *
     * @param idToken       raw ID token (JWT) from the provider
     * @param expectedNonce nonce stored for this auth flow (may be null to skip
     *                      nonce check)
     * @return validated {@link JWTClaimsSet}
     * @throws Exception if verification or claim validation fails
     */
    protected JWTClaimsSet validateIdToken(String idToken,
            String expectedNonce) throws Exception {

        SignedJWT jwt = SignedJWT.parse(idToken);
        JWSHeader header = jwt.getHeader();
        String kid = header.getKeyID();

        JWK jwk = jwksKeyCache.selectKey(kid);
        if (jwk == null || !(jwk instanceof RSAKey rsaKey)) {
            throw new SecurityException("No suitable JWK found for kid=" + kid);
        }

        RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        if (!jwt.verify(verifier)) {
            throw new SecurityException("Invalid ID token signature");
        }

        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        // Validate issuer, audience, expiry, nonce
        if (!issuer().equals(claims.getIssuer())) {
            throw new SecurityException("Invalid issuer: " + claims.getIssuer());
        }

        if (!claims.getAudience().contains(clientId())) {
            throw new SecurityException("Invalid audience");
        }

        Date now = new Date();
        if (claims.getExpirationTime() == null || now.after(claims.getExpirationTime())) {
            throw new SecurityException("ID token expired");
        }

        if (expectedNonce != null) {
            String tokenNonce = claims.getStringClaim("nonce");
            if (tokenNonce == null || !expectedNonce.equals(tokenNonce)) {
                throw new SecurityException("Invalid nonce");
            }
        }

        return claims;
    }

    @Override
    public String clientId() {
        return props.getProperty(OidcRealm.CLIENT_ID);
    }

    @Override
    public String clientSecret() {
        return props.getProperty(OidcRealm.CLIENT_SECRET);
    }

    @Override
    public String tokenEndpoint() {
        return props.getProperty(OidcRealm.TOKEN_ENDPOINT);
    }

    @Override
    public String imageUrl() {
        return props.getProperty(OidcRealm.IMAGE_URL);
    }

    @Override
    public boolean isConfigured() {
        return props != null && props.getProperty(OidcRealm.CLIENT_ID) != null;
    }

    @Override
    public String getName() {
        return providerName;
    }

    protected String authorizationEndpoint() {
        return props.getProperty(OidcRealm.AUTHORIZATION_ENDPOINT);
    }

    protected String jwksUri() {
        return props.getProperty(OidcRealm.JWKS_URI);
    }

    protected String issuer() {
        return props.getProperty(OidcRealm.ISSUER);
    }

    protected String redirectUri() {
        return props.getProperty(OidcRealm.REDIRECT_URI);
    }

    protected String scope() {
        return props.getProperty(OidcRealm.SCOPES);
    }

    protected String url(String val) {
        return URLEncoder.encode(val, StandardCharsets.UTF_8);
    }
}
