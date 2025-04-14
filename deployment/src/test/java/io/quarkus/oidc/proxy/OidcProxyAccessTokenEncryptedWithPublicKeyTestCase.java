package io.quarkus.oidc.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusDevModeTest;

public class OidcProxyAccessTokenEncryptedWithPublicKeyTestCase {

    private static Class<?>[] testClasses = {
            OidcServiceResource.class,
            OidcWebAppResource.class,
            ServiceApiClient.class
    };

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(testClasses)
                    .addAsResource("application-encrypted-token-with-public-key.properties", "application.properties"));

    @Test
    public void testOidcProxy() throws Exception {

        try (final WebClient webClient = createWebClient()) {
            HtmlPage page = webClient.getPage("http://localhost:8080/web-app");

            assertEquals("Sign in to quarkus", page.getTitleText());

            HtmlForm loginForm = page.getForms().get(0);

            loginForm.getInputByName("username").setValueAttribute("alice");
            loginForm.getInputByName("password").setValueAttribute("alice");

            TextPage textPage = loginForm.getButtonByName("login").click();

            assertEquals("web-app: ID alice, code flow token: Bearer, service: Bearer alice", textPage.getContent());

            webClient.getCookieManager().clearCookies();
        }

    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }

}
