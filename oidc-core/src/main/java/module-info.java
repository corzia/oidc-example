module org.corzia.oidc {
    // Export public API packages
    exports org.corzia.oidc;
    exports org.corzia.oidc.api;
    exports org.corzia.oidc.config;
    exports org.corzia.oidc.entra;
    exports org.corzia.oidc.google;
    exports org.corzia.oidc.jwks;
    exports org.corzia.oidc.mock;
    exports org.corzia.oidc.okta;
    exports org.corzia.oidc.utils;

    // Transitive dependencies (types exposed in public API)
    requires transitive jakarta.servlet;
    requires transitive org.apache.shiro.core;
    requires transitive org.apache.shiro.web;
    requires transitive org.json;

    // Implementation dependencies
    requires org.slf4j;
    requires com.nimbusds.jose.jwt;
    requires io.github.bucket4j.core;
    requires osgi.core;
    requires org.osgi.service.cm;
}
