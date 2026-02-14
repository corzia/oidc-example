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
package org.corzia.oidc.shiro;

import org.corzia.oidc.OidcConstants;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter that validates Accept and Content-Type headers for API requests.
 * Ensures clients communicate using expected media types (JSON or
 * Form-URL-Encoded).
 */
public class ContentTypeFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // 1. Validate 'Accept' header for all API requests
        String acceptHeader = httpRequest.getHeader("Accept");
        if (acceptHeader != null && !acceptHeader.contains("*/*")
                && !acceptHeader.contains("application/json")
                && !acceptHeader.contains("application/*")) {

            httpResponse.setStatus(HttpServletResponse.SC_NOT_ACCEPTABLE); // 406
            httpResponse.setContentType("application/json");
            httpResponse.getWriter()
                    .write("{\"success\": false, \"message\": \"Only application/json is supported for responses.\"}");
            return;
        }

        // 2. Validate 'Content-Type' for state-changing requests
        String method = httpRequest.getMethod();
        if (OidcConstants.METHOD_POST.equalsIgnoreCase(method)
                || OidcConstants.METHOD_PUT.equalsIgnoreCase(method)
                || OidcConstants.METHOD_PATCH.equalsIgnoreCase(method)) {
            String contentType = httpRequest.getContentType();

            if (contentType == null || (!contentType.startsWith("application/json")
                    && !contentType.startsWith("application/x-www-form-urlencoded"))) {

                httpResponse.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE); // 415
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write(
                        "{\"success\": false, \"message\": \"Unsupported Content-Type. Expected application/json or application/x-www-form-urlencoded.\"}");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
