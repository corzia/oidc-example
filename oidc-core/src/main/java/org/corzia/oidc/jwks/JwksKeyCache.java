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
package org.corzia.oidc.jwks;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;

public class JwksKeyCache {

    private final String jwksUri;
    private volatile JWKSet jwkSet;
    private volatile long lastRefreshMillis = 0L;
    private final long refreshIntervalMillis = 5 * 60 * 1000L; // 5 minutes

    public JwksKeyCache(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    protected synchronized JWKSet getJwkSet() throws IOException, ParseException, URISyntaxException {
        long now = System.currentTimeMillis();
        if (jwkSet == null || now - lastRefreshMillis > refreshIntervalMillis) {
            try (InputStream in = URI.create(jwksUri).toURL().openStream()) {
                String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                jwkSet = JWKSet.parse(json);
                lastRefreshMillis = now;
            }
        }
        return jwkSet;
    }

    public JWK selectKey(String kid) throws IOException, ParseException, URISyntaxException {
        JWKSet set = getJwkSet();
        if (kid == null) {
            // If kid is null, just pick first RSA key; a bit naive but works in practice.
            return set.getKeys().stream()
                    .filter(jwk -> jwk.getKeyUse() == null || KeyUse.SIGNATURE.equals(jwk.getKeyUse()))
                    .findFirst()
                    .orElse(null);
        }
        return set.getKeyByKeyId(kid);
    }
}
