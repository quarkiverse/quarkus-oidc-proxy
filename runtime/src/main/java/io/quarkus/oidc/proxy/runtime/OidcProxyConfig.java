package io.quarkus.oidc.proxy.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.oidc-proxy")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface OidcProxyConfig {

    /**
     * OIDC service tenant identifier which can be set to select an OIDC tenant configuration.
     * The default OIDC tenant configuration is used when this property is not set.
     */
    Optional<String> tenantId();

    /**
     * OIDC proxy root path.
     */
    @WithDefault("/q/oidc")
    String rootPath();

    /**
     * OIDC proxy authorization endpoint path relative to the {@link #rootPath()}.
     */
    @WithDefault("/authorize")
    String authorizationPath();

    /**
     * OIDC proxy token endpoint path relative to the {@link #rootPath()}
     */
    @WithDefault("/token")
    String tokenPath();

    /**
     * OIDC proxy JSON Web Key Set endpoint path relative to the {@link #rootPath()}
     */
    @WithDefault("/jwks")
    String jwksPath();

    /**
     * OIDC proxy UserInfo endpoint path relative to the {@link #rootPath()}.
     * This path will not be supported if {@link #allowIdToken()} is set to `false`.
     */
    @WithDefault("/userinfo")
    String userInfoPath();

    /**
     * OIDC proxy end session path relative to the {@link #rootPath()}.
     */
    @WithDefault("/logout")
    String endSessionPath();

    /**
     * Allow to return an ID token from the authorization code grant response.
     */
    @WithDefault("true")
    boolean allowIdToken();

    /**
     * Allow to return a refresh token from the authorization code grant response.
     */
    @WithDefault("true")
    boolean allowRefreshToken();

    /**
     * Absolute external redirect URI.
     * <p/>
     * If 'quarkus.oidc.authentication.redirect-path' is configured then configuring this property is required.
     * In this case, the proxy will request a redirect to 'quarkus.oidc.authentication.redirect-path' and
     * will redirect further to the external redirect URI.
     */
    Optional<String> externalRedirectUri();

    /**
     * Absolute external post logout URI.
     * <p/>
     * If 'quarkus.oidc.logout.post-logout-path' is configured then configuring this property is required.
     * In this case, the proxy will request a post logout redirect to 'quarkus.oidc.logout.post-logout-path' and
     * will redirect further to the external post logout URI.
     */
    Optional<String> externalPostLogoutUri();

    /**
     * Client id that the external client must use. If this property is not set then the external client
     * must provide a client_id which matches `quarkus.oidc.client-id`.
     */
    Optional<String> externalClientId();

    /**
     * Client secret that the external client must use. If this property is not set then the external client
     * must provide a client_secret which matches the configured OIDC service client secret.
     * External client may not provide the client_secret if it is not configured
     * with either this property or the OIDC tenant configuration, in order to support public clients.
     */
    Optional<String> externalClientSecret();
}
