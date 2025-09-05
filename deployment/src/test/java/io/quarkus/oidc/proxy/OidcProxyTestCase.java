package io.quarkus.oidc.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.TextPage;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class OidcProxyTestCase {

    private static Class<?>[] testClasses = {
            OidcServiceResource.class,
            OidcWebAppResource.class,
            ServiceApiClient.class
    };

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(testClasses)
                    .addAsResource("application.properties"));

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

            checkWellKnownConfig(webClient);

        }

    }

    private static void checkWellKnownConfig(WebClient webClient) throws Exception {
        Response response = RestAssured.when().get("http://localhost:8080/q/oidc/.well-known/openid-configuration");
        JsonObject json = new JsonObject(response.asString());

        assertEquals("http://localhost:8080/q/oidc/authorize", json.getString("authorization_endpoint"));
        assertEquals("http://localhost:8080/q/oidc/token", json.getString("token_endpoint"));
        assertEquals("http://localhost:8080/q/oidc/jwks", json.getString("jwks_uri"));
        assertEquals("http://localhost:8080/q/oidc/logout", json.getString("end_session_endpoint"));
        assertEquals("http://localhost:8080/q/oidc/userinfo", json.getString("userinfo_endpoint"));
        assertEquals("http://localhost:8080/q/oidc/client-registration", json.getString("registration_endpoint"));
        assertTrue(json.getString("issuer").contains("http://localhost"));
        assertTrue(json.getString("issuer").contains("/realms/quarkus"));

        checkResponseTypesSupported(json.getJsonArray("response_types_supported"));
        checkSubjectTypesSupported(json.getJsonArray("subject_types_supported"));
        checkCodeChallengeMethodsSupported(json.getJsonArray("code_challenge_methods_supported"));
        checkIdTokenSigningAlorithmsSupported(json.getJsonArray("id_token_signing_alg_values_supported"));
    }

    private static void checkIdTokenSigningAlorithmsSupported(JsonArray jsonArray) {
        assertTrue(jsonArray.contains("RS256"));
        assertTrue(jsonArray.contains("ES256"));
    }

    private static void checkCodeChallengeMethodsSupported(JsonArray jsonArray) {
        assertTrue(jsonArray.contains("plain"));
        assertTrue(jsonArray.contains("S256"));
    }

    private static void checkSubjectTypesSupported(JsonArray jsonArray) {
        assertTrue(jsonArray.contains("public"));
        assertTrue(jsonArray.contains("pairwise"));
    }

    private static void checkResponseTypesSupported(JsonArray jsonArray) {
        assertTrue(jsonArray.contains("code"));
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }

}
