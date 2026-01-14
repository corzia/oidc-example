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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OidcUserDirectory {

    private static final Map<String, OidcUserInfo> USERS = new ConcurrentHashMap<>();

    // Store by OidcUserInfo's username
    public static void put(OidcUserInfo info) {
        USERS.put(info.getUsername(), info);
    }

    // Overload used by RefreshTokenServlet when username is known
    public static void put(String username, OidcUserInfo info) {
        USERS.put(username, info);
    }

    public static OidcUserInfo get(String username) {
        return USERS.get(username);
    }
}