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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import org.junit.jupiter.api.Test;

public class JwksKeyCacheTest {

    @Test
    public void testSelectKey_ById() throws Exception {
        RSAKey key1 = new RSAKey.Builder(new Base64URL("n1"), new Base64URL("e1"))
                .keyID("kid1")
                .keyUse(KeyUse.SIGNATURE)
                .build();
        RSAKey key2 = new RSAKey.Builder(new Base64URL("n2"), new Base64URL("e2"))
                .keyID("kid2")
                .keyUse(KeyUse.SIGNATURE)
                .build();
        JWKSet set = new JWKSet(List.of(key1, key2));

        JwksKeyCache cache = new JwksKeyCache("http://example.com") {
            @Override
            protected JWKSet getJwkSet() throws IOException, ParseException, URISyntaxException {
                return set;
            }
        };

        JWK selected = cache.selectKey("kid2");
        assertNotNull(selected);
        assertEquals("kid2", selected.getKeyID());
    }

    @Test
    public void testSelectKey_FirstSignatureKeyIfIdNull() throws Exception {
        RSAKey key1 = new RSAKey.Builder(new Base64URL("n1"), new Base64URL("e1"))
                .keyID("kid1")
                .keyUse(KeyUse.SIGNATURE)
                .build();
        JWKSet set = new JWKSet(List.of(key1));

        JwksKeyCache cache = new JwksKeyCache("http://example.com") {
            @Override
            protected JWKSet getJwkSet() throws IOException, ParseException, URISyntaxException {
                return set;
            }
        };

        JWK selected = cache.selectKey(null);
        assertNotNull(selected);
        assertEquals("kid1", selected.getKeyID());
    }

    @Test
    public void testSelectKey_ReturnsNullIfNotFound() throws Exception {
        JWKSet set = new JWKSet(List.of());

        JwksKeyCache cache = new JwksKeyCache("http://example.com") {
            @Override
            protected JWKSet getJwkSet() throws IOException, ParseException, URISyntaxException {
                return set;
            }
        };

        assertNull(cache.selectKey("missing"));
    }
}
