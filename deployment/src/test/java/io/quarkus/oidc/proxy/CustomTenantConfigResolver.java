package io.quarkus.oidc.proxy;

import java.net.URI;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.client.registration.ClientMetadata;
import io.quarkus.oidc.client.registration.RegisteredClient;
import io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class CustomTenantConfigResolver implements TenantConfigResolver {

    volatile RegisteredClient client;

    @Override
    public Uni<OidcTenantConfig> resolve(RoutingContext routingContext,
            OidcRequestContext<OidcTenantConfig> requestContext) {
        if (routingContext.request().path().endsWith("/web-app")) {
            return Uni.createFrom().item(createTenantConfig(client.metadata()));
        }
        return Uni.createFrom().nullItem();
    }

    void setRegisteredClient(RegisteredClient client) {
        this.client = client;
    }

    private OidcTenantConfig createTenantConfig(ClientMetadata metadata) {
        return OidcTenantConfig
                .authServerUrl("http://localhost:8080/q/oidc")
                .tenantId("web-app")
                .applicationType(ApplicationType.WEB_APP)
                .clientId(metadata.getClientId())
                .clientName(metadata.getClientName())
                .authentication().redirectPath(URI.create(metadata.getRedirectUris().get(0)).getPath())
                .cookiePath("/web-app")
                .end()
                .build();
    }
}
