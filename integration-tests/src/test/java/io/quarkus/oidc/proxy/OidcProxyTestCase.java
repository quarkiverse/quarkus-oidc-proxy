package io.quarkus.oidc.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
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
            HtmlPage page = webClient.getPage("http://localhost:8081/web-app");

            assertEquals("Sign in to quarkus", page.getTitleText());

            HtmlForm loginForm = page.getForms().get(0);

            loginForm.getInputByName("username").setValueAttribute("alice");
            loginForm.getInputByName("password").setValueAttribute("alice");

            TextPage textPage = loginForm.getButtonByName("login").click();

            assertEquals("web-app: ID alice, service: Bearer alice", textPage.getContent());

            assertNotNull(getSessionCookie(webClient));

            textPage = webClient.getPage("http://localhost:8081/web-app/logout");
            assertEquals("You have been logged out", textPage.getContent());

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
}
