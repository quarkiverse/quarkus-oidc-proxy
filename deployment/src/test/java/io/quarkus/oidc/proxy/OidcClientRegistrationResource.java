package io.quarkus.oidc.proxy;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import io.quarkus.oidc.client.registration.ClientMetadata;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrationConfig;
import io.quarkus.oidc.client.registration.OidcClientRegistrations;
import io.quarkus.oidc.client.registration.RegisteredClient;
import io.smallrye.mutiny.Uni;

@Path("/register-client")
public class OidcClientRegistrationResource {

    @Inject
    OidcClientRegistrations clientRegs;

    @Inject
    CustomTenantConfigResolver tenantResolver;

    @GET
    @Produces("text/plain")
    public String register() {
        OidcClientRegistrationConfig clientRegConfig = OidcClientRegistrationConfig.builder()
                .registrationPath("http://localhost:8080/q/oidc/client-registration")
                .build();

        Uni<OidcClientRegistration> newClientReg = clientRegs.newClientRegistration(clientRegConfig);
        Uni<RegisteredClient> registeredClientUni = newClientReg.onItem()
                .transformToUni(clientReg -> clientReg.registerClient(createClientMetadata()));
        RegisteredClient client = registeredClientUni.await().indefinitely();
        tenantResolver.setRegisteredClient(client);
        return client.metadata().getMetadataString();
    }

    private ClientMetadata createClientMetadata() {
        return ClientMetadata.builder()
                .redirectUri("http://localhost:8080/web-app")
                .tokenEndpointAuthMethod("none")
                .clientName("Dynamic Client")
                .build();
    }
}
