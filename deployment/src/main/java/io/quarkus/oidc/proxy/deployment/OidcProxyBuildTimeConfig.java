package io.quarkus.oidc.proxy.deployment;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Build time configuration for OIDC Proxy.
 */
@ConfigMapping(prefix = "quarkus.oidc-proxy")
@ConfigRoot(phase = ConfigPhase.BUILD_TIME)
public interface OidcProxyBuildTimeConfig {
    /**
     * If the OIDC Proxy extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();
}
