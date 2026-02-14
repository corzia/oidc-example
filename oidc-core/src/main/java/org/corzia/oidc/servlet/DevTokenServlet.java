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

import com.nimbusds.jose.JWSAlgorithm;
import org.corzia.oidc.OidcConstants;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;

@WebServlet("/api/dev/token")
public class DevTokenServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(DevTokenServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            // Generate a dummy token signed with a random secret (validation currently
            // doesn't check signature in Realm)
            // But we sign it to make it a valid "SignedJWT" format
            JWSSigner signer = new MACSigner("00000000000000000000000000000000"); // 32 bytes

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject("dev-user")
                    .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour
                    .build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(signer);

            resp.setContentType(OidcConstants.TYPE_TEXT);
            resp.getWriter().write(signedJWT.serialize());
        } catch (Exception e) {
            log.error("Failed to generate dev token", e);
            throw new IOException(e);
        }
    }
}
