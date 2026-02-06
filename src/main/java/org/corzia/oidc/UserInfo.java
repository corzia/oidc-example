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

import java.io.Serializable;
import java.util.Set;
import org.json.JSONObject;

/**
 * Common representation of an authenticated user's identity attributes.
 */
public class UserInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    protected final String username;
    protected final String email;
    protected final String fullName;
    protected final String givenName;
    protected final String familyName;
    protected final String picture;
    protected final String locale;
    protected final boolean emailVerified;
    protected final Set<String> groups;

    public UserInfo(String username, String email, String fullName, String givenName, String familyName,
            String picture, String locale, boolean emailVerified, Set<String> groups) {
        this.username = username != null ? username.trim() : null;
        this.email = email != null ? email.trim() : null;
        this.fullName = fullName;
        this.givenName = givenName;
        this.familyName = familyName;
        this.picture = picture;
        this.locale = locale;
        this.emailVerified = emailVerified;
        this.groups = groups;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getFullName() {
        return fullName;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getPicture() {
        return picture;
    }

    public String getLocale() {
        return locale;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public Set<String> getGroups() {
        return groups;
    }

    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("username", username);
        json.put("email", email);
        json.put("fullName", fullName);
        json.put("givenName", givenName);
        json.put("familyName", familyName);
        json.put("picture", picture);
        json.put("locale", locale);
        json.put("emailVerified", emailVerified);
        json.put("groups", groups);
        return json;
    }

    @Override
    public String toString() {
        if (email != null && !email.isEmpty()) {
            return username + " <" + email + ">";
        }
        return username;
    }
}
