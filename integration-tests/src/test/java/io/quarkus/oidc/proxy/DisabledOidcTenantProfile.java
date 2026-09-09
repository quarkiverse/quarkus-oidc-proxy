package io.quarkus.oidc.proxy;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

public class DisabledOidcTenantProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "quarkus.keycloak.devservices.enabled", "false" // disabling keycloak dev service disables default tenant
        );
    }
}
