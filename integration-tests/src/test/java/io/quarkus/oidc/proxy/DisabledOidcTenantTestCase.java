package io.quarkus.oidc.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.URI;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.WebClient;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;

@QuarkusTest
@TestProfile(DisabledOidcTenantProfile.class)
public class DisabledOidcTenantTestCase {

    @Test
    public void testEndpointWhenOidcTenantDisabled() throws Exception {
        try (final WebClient webClient = createWebClient()) {
            // Disable auto-redirect
            webClient.getOptions().setRedirectEnabled(false);
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);

            // This is the protected endpoint redirect to the OIDC provider which is represented by OIDC proxy
            WebResponse webResponse = webClient
                    .loadWebResponse(new WebRequest(URI.create("http://localhost:8081/web-app").toURL()));

            assertNull(webResponse.getResponseHeaderValue("location"),
                    "Expected no location header from proxy since OIDC tenant is disabled");
            assertEquals(401, webResponse.getStatusCode(),
                    "Expected definitive unauthorized response since OIDC tenant to redirect is disabled");
        }
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }
}
