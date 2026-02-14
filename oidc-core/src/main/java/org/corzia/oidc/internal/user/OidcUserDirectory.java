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
package org.corzia.oidc.internal.user;
import org.corzia.oidc.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A shared directory for looking up authenticated user information (UserInfo)
 * by username.
 */
public class OidcUserDirectory {

    private static final Map<String, UserInfo> USERS = new ConcurrentHashMap<>();

    /**
     * Stores user info by username.
     * 
     * @param info the UserInfo (or OidcUserInfo) object to store
     */
    public static void put(UserInfo info) {
        if (info != null && info.getUsername() != null) {
            USERS.put(info.getUsername(), info);
        }
    }

    /**
     * Stores user info with an explicit username key.
     * 
     * @param username the username key
     * @param info     the UserInfo object to store
     */
    public static void put(String username, UserInfo info) {
        if (username != null && info != null) {
            USERS.put(username, info);
        }
    }

    /**
     * Retrieves user info for a given username.
     * 
     * @param username the username key
     * @return the UserInfo object, or null if not found
     */
    public static UserInfo get(String username) {
        return username != null ? USERS.get(username) : null;
    }
}