package io.quarkus.oidc.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.Cookie;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class OidcProxyTestCase {

    @Test
    public void testOidcProxy() throws Exception {

        try (final WebClient webClient = createWebClient()) {
            // Disable auto-redirect
            webClient.getOptions().setRedirectEnabled(false);
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);

            // This is the protected endpoint redirect to the OIDC provider which is represented by OIDC proxy
            WebResponse webResponse = webClient
                    .loadWebResponse(new WebRequest(URI.create("http://localhost:8081/web-app").toURL()));

            // Original state cookie created by `quarkus-oidc`
            Cookie stateCookie = getStateCookie(webClient);
            assertNotNull(stateCookie);
            assertEquals(stateCookie.getName(), "q_auth_web-app");

            // Confirm the OIDC proxy is the redirect target
            String oidcUrl = webResponse.getResponseHeaderValue("location");
            assertTrue(oidcUrl.startsWith("http://localhost:8081/q/oidc/authorize"));
            // `quarkus-oidc` expects the OIDC provider redirect the user back to the protected endpoint
            assertTrue(oidcUrl.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fweb-app"));
            // `quarkus-oidc` does not itself add a `prompt` parameter
            assertFalse(oidcUrl.contains("prompt="));
            // No OIDC proxy state cookie available yet
            Cookie proxyStateCookie = getProxyStateCookie(webClient);
            assertNull(proxyStateCookie);

            // This is a redirect from OIDC proxy to Keycloak but expecting a redirect
            // to the OIDC proxy managed local redirect endpoint
            webResponse = webClient.loadWebResponse(new WebRequest(URI.create(oidcUrl).toURL()));
            String keycloakUrl = webResponse.getResponseHeaderValue("location");
            assertTrue(keycloakUrl.contains("/protocol/openid-connect/auth"));
            assertTrue(keycloakUrl.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Flocal-redirect"));
            // OIDC proxy adds a `prompt=consent` parameter
            assertTrue(keycloakUrl.contains("prompt=consent"));
            assertTrue(keycloakUrl.contains("test=URL+encode"));

            // OIDC proxy state cookie must be set by now
            proxyStateCookie = getProxyStateCookie(webClient);
            assertNotNull(proxyStateCookie);
            assertEquals(proxyStateCookie.getName(), "q_proxy_auth");
            assertEquals(proxyStateCookie.getValue(), stateCookie.getValue());

            // This is a challenge from Keycloak
            HtmlPage page = webClient.getPage(keycloakUrl);

            assertEquals("Sign in to quarkus", page.getTitleText());

            HtmlForm loginForm = page.getForms().get(0);

            loginForm.getInputByName("username").setValueAttribute("alice");
            loginForm.getInputByName("password").setValueAttribute("alice");

            webResponse = loginForm.getButtonByName("login").click().getWebResponse();

            // This is a redirect from Keycloak to the OIDC proxy managed local redirect endpoint
            String localRedirectUrl = webResponse.getResponseHeaderValue("location");
            assertTrue(localRedirectUrl.startsWith("http://localhost:8081/local-redirect"));

            // This is a redirect from the OIDC proxy managed local redirect endpoint to the protected endpoint
            webResponse = webClient.loadWebResponse(new WebRequest(URI.create(localRedirectUrl).toURL()));
            String webAppRedirectUrl = webResponse.getResponseHeaderValue("location");
            assertTrue(webAppRedirectUrl.startsWith("http://localhost:8081/web-app"));

            // No session cookie is available yet
            assertNull(getSessionCookie(webClient));

            // Original state cookie is still expected
            assertNotNull(getStateCookie(webClient));
            // But the OIDC proxy state cookie must be gone by now
            assertNull(getProxyStateCookie(webClient));

            webClient.getOptions().setRedirectEnabled(true);

            // Access the protected endpoint, complete the code flow, get the  response
            TextPage textPage = webClient.getPage(webAppRedirectUrl);

            assertEquals("web-app: ID alice, service: Bearer alice", textPage.getContent());

            // Session cookie is ready
            assertNotNull(getSessionCookie(webClient));

            // Both state cookies must be null
            assertNull(getStateCookie(webClient));
            assertNull(getProxyStateCookie(webClient));

            // Logout
            textPage = webClient.getPage("http://localhost:8081/web-app/logout");
            assertEquals("You have been logged out", textPage.getContent());

            // Session cookie must be null
            assertNull(getSessionCookie(webClient));

            webClient.getCookieManager().clearCookies();
        }

    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }

    private Cookie getSessionCookie(WebClient webClient) {
        return webClient.getCookieManager().getCookie("q_session_web-app");
    }

    private Cookie getStateCookie(WebClient webClient) {
        return webClient.getCookieManager().getCookie("q_auth_web-app");
    }

    private Cookie getProxyStateCookie(WebClient webClient) {
        return webClient.getCookieManager().getCookie("q_proxy_auth");
    }
}
