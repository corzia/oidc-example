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

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.corzia.oidc.OidcClient;
import org.corzia.oidc.OidcClientFactory;
import org.corzia.oidc.OidcRealm;

/**
 * Servlet that returns a JSON list of configured OIDC providers.
 */
@WebServlet("/api/providers")
public class ProvidersServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        OidcClientFactory factory = OidcRealm.getClientFactory();
        Collection<OidcClient> clients = factory.getAllClients();

        String json = clients.stream()
                .filter(OidcClient::isConfigured)
                .map(c -> String.format(
                        "{\"name\": \"%s\", \"displayName\": \"%s\", \"imageUrl\": \"%s\"}",
                        c.getName(),
                        capitalize(c.getName()),
                        c.imageUrl() != null ? c.imageUrl() : ""))
                .collect(Collectors.joining(",", "[", "]"));

        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(json);
    }

    private String capitalize(String s) {
        if (s == null || s.isEmpty())
            return s;
        return s.substring(0, 1).toUpperCase() + s.substring(1).toLowerCase();
    }
}
