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
package org.corzia.oidc.internal.utils;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.corzia.oidc.OidcConstants;
import org.json.JSONObject;

public class HttpUtils {

        /**
         * Exchanges an authorization code for tokens.
         * 
         * @param tokenEndpoint token endpoint URL
         * @param clientId      client identifier
         * @param clientSecret  client secret
         * @param code          authorization code received from IdP
         * @param redirectUri   redirect URI used in the original request
         * @return TokenResponse containing idToken, accessToken, and optional
         *         refreshToken
         */
        public static TokenResponse exchangeCode(String tokenEndpoint,
                        String clientId,
                        String clientSecret,
                        String code,
                        String redirectUri) throws Exception {
                URL url = new URI(tokenEndpoint).toURL();
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod(OidcConstants.METHOD_POST);
                conn.setDoOutput(true);

                String body = "grant_type=authorization_code"
                                + "&client_id=" + clientId
                                + "&client_secret=" + clientSecret
                                + "&code=" + code
                                + "&redirect_uri=" + redirectUri;

                try (OutputStream os = conn.getOutputStream()) {
                        os.write(body.getBytes(StandardCharsets.UTF_8));
                }

                String json = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                JSONObject obj = new JSONObject(json);
                return new TokenResponse(
                                obj.getString("id_token"),
                                obj.getString("access_token"),
                                obj.optString("refresh_token", null));
        }

        /**
         * Refreshes an access token using a refresh token.
         * 
         * @param tokenEndpoint token endpoint URL
         * @param clientId      client identifier
         * @param clientSecret  client secret
         * @param refreshToken  the refresh token obtained earlier
         * @return TokenResponse containing new idToken, accessToken, and optional
         *         refreshToken
         */
        public static TokenResponse refreshAccessToken(String tokenEndpoint,
                        String clientId,
                        String clientSecret,
                        String refreshToken) throws Exception {
                URL url = new URI(tokenEndpoint).toURL();
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod(OidcConstants.METHOD_POST);
                conn.setDoOutput(true);

                String body = "grant_type=refresh_token"
                                + "&client_id=" + clientId
                                + "&client_secret=" + clientSecret
                                + "&refresh_token=" + refreshToken;

                try (OutputStream os = conn.getOutputStream()) {
                        os.write(body.getBytes(StandardCharsets.UTF_8));
                }

                String json = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                JSONObject obj = new JSONObject(json);
                return new TokenResponse(
                                obj.optString("id_token", null),
                                obj.optString("access_token", null),
                                obj.optString("refresh_token", null));
        }
}
