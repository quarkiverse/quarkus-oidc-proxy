package io.quarkus.oidc.proxy;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;

@Path("/service")
@Authenticated
public class OidcServiceResource {

    @Inject
    SecurityIdentity accessToken;

    @GET
    @Produces("text/plain")
    public String getName() {
        JsonWebToken jwt = accessToken.getPrincipal(JsonWebToken.class);
        return jwt.getClaim("typ") + " " + jwt.getName();
    }
}
