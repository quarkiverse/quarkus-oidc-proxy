package io.quarkus.oidc.proxy.runtime;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

import org.jboss.logging.Logger;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.oidc.OidcConfigurationMetadata;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.common.runtime.OidcClientCommonConfig.Credentials.Secret.Method;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.quarkus.oidc.runtime.TenantConfigContext;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;

public class OidcProxy {
    private static final Logger LOG = Logger.getLogger(OidcProxy.class);
    private static final String OIDC_PROXY_STATE_COOKIE = "q_proxy_auth";
    final OidcConfigurationMetadata oidcMetadata;
    final OidcTenantConfig oidcTenantConfig;
    final OidcProxyConfig oidcProxyConfig;
    final WebClient client;
    final String configuredClientSecret;
    final String httpRootPath;
    final boolean localAuthorizationCodeFlowRedirect;
    final Key tokenEncryptionKey;
    final Key tokenDecryptionKey;

    public OidcProxy(TenantConfigBean tenantConfig, OidcProxyConfig oidcProxyConfig, String httpRootPath) {
        TenantConfigContext tenantConfigContext = oidcProxyConfig.tenantId().isEmpty() ? tenantConfig.getDefaultTenant()
                : tenantConfig.getStaticTenantsConfig().get(oidcProxyConfig.tenantId().get());
        this.oidcTenantConfig = tenantConfigContext.getOidcTenantConfig();
        this.oidcMetadata = tenantConfigContext.getOidcMetadata();
        this.client = tenantConfigContext.getOidcProviderClient().getWebClient();
        this.oidcProxyConfig = oidcProxyConfig;
        this.configuredClientSecret = OidcCommonUtils.clientSecret(oidcTenantConfig.credentials);
        this.httpRootPath = httpRootPath;
        this.localAuthorizationCodeFlowRedirect = oidcTenantConfig.authentication().redirectPath().isPresent();
        this.tokenEncryptionKey = createTokenEncryptionKey(oidcProxyConfig, oidcTenantConfig, configuredClientSecret);
        this.tokenDecryptionKey = tenantConfigContext.getTokenDecryptionKey();
    }

    public void setup(Router router) {
        if (oidcTenantConfig.applicationType.orElse(ApplicationType.SERVICE) == ApplicationType.WEB_APP) {
            throw new ConfigurationException("OIDC Proxy can only be used with OIDC service applications");
        }
        if (oidcProxyConfig.externalClientSecret().isPresent() && configuredClientSecret.isEmpty()) {
            throw new ConfigurationException(
                    "OIDC service client secret must be configured to replace the external client secret during the token endpoint request");
        }

        if (oidcMetadata.getAuthorizationUri() == null || oidcMetadata.getTokenUri() == null) {
            throw new ConfigurationException(
                    "OIDC Proxy requires that at least OIDC authorization and token endpoints are configured");
        }
        Method authMethod = oidcTenantConfig.credentials.clientSecret.method.orElse(Method.BASIC);
        if (authMethod == Method.POST_JWT) {
            throw new ConfigurationException(
                    "Unsupported OIDC service client authentication method");
        }
        router.get(oidcProxyConfig.rootPath() + OidcConstants.WELL_KNOWN_CONFIGURATION)
                .handler(this::wellKnownConfig);
        if (oidcMetadata.getJsonWebKeySetUri() != null) {
            router.get(oidcProxyConfig.rootPath() + oidcProxyConfig.jwksPath()).handler(this::jwks);
        }
        if (oidcMetadata.getUserInfoUri() != null && oidcProxyConfig.allowIdToken()) {
            router.get(oidcProxyConfig.rootPath() + oidcProxyConfig.userInfoPath()).handler(this::userinfo);
        }
        router.get(oidcProxyConfig.rootPath() + oidcProxyConfig.authorizationPath()).handler(this::authorize);
        router.post(oidcProxyConfig.rootPath() + oidcProxyConfig.tokenPath()).handler(this::token);
        if (localAuthorizationCodeFlowRedirect) {
            if (!oidcProxyConfig.externalRedirectUri().isPresent()) {
                throw new ConfigurationException("oidc-proxy.external-redirect-uri property must be configured because"
                        + "the local quarkus.oidc.authentication.redirect-path is configured");
            }
            router.get(oidcTenantConfig.authentication.redirectPath.get()).handler(this::localAuthorizationCodeFlowRedirect);
        }

        if (oidcMetadata.getEndSessionUri() != null) {
            router.get(oidcProxyConfig.rootPath() + oidcProxyConfig.endSessionPath()).handler(this::endSession);
            if (oidcTenantConfig.logout().postLogoutPath().isPresent()) {
                if (!oidcProxyConfig.externalPostLogoutUri().isPresent()) {
                    throw new ConfigurationException("oidc-proxy.external-post-logout-uri property must be configured because"
                            + "the local quarkus.oidc.logout.post-logout-path is configured");
                }
                router.get(oidcTenantConfig.logout().postLogoutPath().get()).handler(this::localPostLogoutRedirect);
            }
        }
    }

    public void authorize(RoutingContext context) {
        LOG.debug("OidcProxy: authorize");
        MultiMap queryParams = context.queryParams();

        StringBuilder codeFlowParams = new StringBuilder(168); // experimentally determined to be a good size for preventing resizing and not wasting space

        // response_type
        codeFlowParams.append(OidcConstants.CODE_FLOW_RESPONSE_TYPE).append("=")
                .append(OidcConstants.CODE_FLOW_CODE);
        // client_id
        final String clientId = getClientId(queryParams.get(OidcConstants.CLIENT_ID));
        if (clientId == null) {
            LOG.error("Client id must be provided");
            badClientRequest(context);
            return;
        }
        codeFlowParams.append("&").append(OidcConstants.CLIENT_ID).append("=")
                .append(OidcCommonUtils.urlEncode(clientId));
        // scope
        String encodedScope = encodeScope(queryParams.get(OidcConstants.TOKEN_SCOPE));
        if (encodedScope != null) {
            codeFlowParams.append("&").append(OidcConstants.TOKEN_SCOPE).append("=")
                    .append(encodedScope);
        }

        // state
        final String state = queryParams.get(OidcConstants.CODE_FLOW_STATE);
        if (state == null) {
            LOG.error("State must be provided");
            badClientRequest(context);
            return;
        }
        codeFlowParams.append("&").append(OidcConstants.CODE_FLOW_STATE).append("=")
                .append(state);

        if (localAuthorizationCodeFlowRedirect) {
            OidcUtils.createCookie(context, oidcTenantConfig, OIDC_PROXY_STATE_COOKIE, state,
                    oidcTenantConfig.authentication().stateCookieAge().getSeconds());
        }

        // nonce
        final String nonce = queryParams.get(OidcConstants.NONCE);
        if (nonce != null) {
            codeFlowParams.append("&").append(OidcConstants.NONCE).append("=")
                    .append(nonce);
        }

        // prompt
        final String prompt = queryParams.get("prompt");
        if (prompt != null) {
            codeFlowParams.append("&").append("prompt").append("=")
                    .append(prompt);
        }

        // redirect_uri
        final String redirectUri = getRedirectUri(context, queryParams.get(OidcConstants.CODE_FLOW_REDIRECT_URI));
        if (redirectUri == null) {
            LOG.error("Redirect URI must be provided");
            badClientRequest(context);
            return;
        }
        codeFlowParams.append("&").append(OidcConstants.CODE_FLOW_REDIRECT_URI).append("=")
                .append(OidcCommonUtils
                        .urlEncode(redirectUri));

        String authorizationURL = oidcMetadata.getAuthorizationUri() + "?" + codeFlowParams.toString();

        context.response().setStatusCode(HttpResponseStatus.FOUND.code());
        context.response().putHeader(HttpHeaders.LOCATION, authorizationURL);
        context.response().end();
    }

    public void endSession(RoutingContext context) {
        LOG.debug("OidcProxy: end session");
        MultiMap queryParams = context.queryParams();

        StringBuilder endSessionParams = new StringBuilder(168); // experimentally determined to be a good size for preventing resizing and not wasting space

        // ID token hint
        final String idTokenHint = queryParams.get(OidcConstants.LOGOUT_ID_TOKEN_HINT);
        if (idTokenHint != null) {
            endSessionParams.append(OidcConstants.LOGOUT_ID_TOKEN_HINT).append("=").append(idTokenHint);
        }

        // redirect_uri
        final String postLogoutUri = getPostLogoutUri(context, queryParams.get(oidcTenantConfig.logout().postLogoutUriParam()));
        if (postLogoutUri != null) {
            if (!endSessionParams.isEmpty()) {
                endSessionParams.append("&");
            }
            endSessionParams.append(oidcTenantConfig.logout().postLogoutUriParam()).append("=").append(postLogoutUri);
        }

        if (!oidcTenantConfig.logout().extraParams().isEmpty()) {
            for (Map.Entry<String, String> entry : oidcTenantConfig.logout().extraParams().entrySet()) {
                if (!endSessionParams.isEmpty()) {
                    endSessionParams.append("&");
                }
                endSessionParams.append(entry.getKey()).append("=").append(OidcCommonUtils.urlEncode(entry.getValue()));
            }
        }

        String endSessionURL = oidcMetadata.getEndSessionUri() + "?" + endSessionParams.toString();

        context.response().setStatusCode(HttpResponseStatus.FOUND.code());
        context.response().putHeader(HttpHeaders.LOCATION, endSessionURL);
        context.response().end();
    }

    public void localAuthorizationCodeFlowRedirect(RoutingContext context) {
        LOG.debug("OidcProxy: local authorization code flow redirect");
        MultiMap queryParams = context.queryParams();

        StringBuilder codeFlowParams = new StringBuilder(168); // experimentally determined to be a good size for preventing resizing and not wasting space

        String code = queryParams.get(OidcConstants.CODE_FLOW_CODE);
        if (code != null) {
            if (tokenEncryptionKey != null) {
                // Encrypt code
                try {
                    code = OidcUtils.encryptString(code, tokenEncryptionKey, getEncryptionAlgorithm());
                } catch (Throwable tex) {
                    LOG.error("Code can not be encrypted");
                    context.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code());
                    context.response().end();
                    return;
                }
            }
            // code
            codeFlowParams.append(OidcConstants.CODE_FLOW_CODE).append("=").append(code);
            // state
            String state = queryParams.get(OidcConstants.CODE_FLOW_STATE);
            if (state == null) {
                LOG.error("State query parameter is missing");
                context.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code());
                context.response().end();
                return;
            }
            String oidcProxyState = OidcUtils.removeCookie(context, oidcTenantConfig, OIDC_PROXY_STATE_COOKIE);
            if (oidcProxyState == null) {
                LOG.error("Proxy state cookie is missing or could not be retrieved");
                context.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code());
                context.response().end();
                return;
            }
            if (!oidcProxyState.equals(state)) {
                LOG.error("State query parameter is not equal to the proxy state");
                context.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code());
                context.response().end();
                return;
            }

            codeFlowParams.append("&").append(OidcConstants.CODE_FLOW_STATE).append("=").append(state);

        } else {
            String error = queryParams.get(OidcConstants.CODE_FLOW_ERROR);
            codeFlowParams.append(OidcConstants.CODE_FLOW_ERROR).append("=").append(error);
            String errorDescription = queryParams.get(OidcConstants.CODE_FLOW_ERROR_DESCRIPTION);
            if (errorDescription != null) {
                codeFlowParams.append(OidcConstants.CODE_FLOW_ERROR_DESCRIPTION).append("=")
                        .append(OidcCommonUtils.urlEncode(errorDescription));
            }
        }

        String redirectURL = oidcProxyConfig.externalRedirectUri().get() + "?" + codeFlowParams.toString();

        context.response().setStatusCode(HttpResponseStatus.FOUND.code());
        context.response().putHeader(HttpHeaders.LOCATION, redirectURL);
        context.response().end();
    }

    public void localPostLogoutRedirect(RoutingContext context) {
        LOG.debug("OidcProxy: local post logout redirect");

        context.response().setStatusCode(HttpResponseStatus.FOUND.code());
        context.response().putHeader(HttpHeaders.LOCATION, oidcProxyConfig.externalPostLogoutUri().get());
        context.response().end();
    }

    public void token(RoutingContext context) {
        OidcUtils.getFormUrlEncodedData(context)
                .onItem().transformToUni(new Function<MultiMap, Uni<? extends Void>>() {
                    @Override
                    public Uni<Void> apply(MultiMap requestParams) {
                        LOG.debug("OidcProxy: Token exchange: start");
                        HttpRequest<Buffer> request = client.postAbs(oidcMetadata.getTokenUri());
                        request.putHeader(String.valueOf(HttpHeaders.CONTENT_TYPE), String
                                .valueOf(HttpHeaders.APPLICATION_X_WWW_FORM_URLENCODED));
                        request.putHeader(String.valueOf(HttpHeaders.ACCEPT), "application/json");

                        Buffer buffer = Buffer.buffer();

                        // grant type
                        String grantType = requestParams.get(OidcConstants.GRANT_TYPE);
                        if (!OidcConstants.AUTHORIZATION_CODE.equals(grantType)
                                && !OidcConstants.REFRESH_TOKEN_GRANT.equals(grantType)) {
                            LOG.errorf("Unsupported grant: %s", grantType);
                            return badClientRequest(context);
                        }
                        encodeForm(buffer, OidcConstants.GRANT_TYPE, grantType);

                        // client id and secret
                        String clientId = null;
                        String clientSecret = null;

                        // check Authorization header
                        String authHeader = context.request().getHeader(HttpHeaderNames.AUTHORIZATION);
                        if (authHeader != null) {
                            LOG.debug("OidcProxy: Authorization header");
                            String[] clientIdAndSecret = getClientIdAndSecretFromAuthorization(authHeader);
                            clientId = getClientId(clientIdAndSecret[0]);
                            clientSecret = clientIdAndSecret[1];
                        } else {
                            LOG.debug("OidcProxy: POST authentication");
                            clientId = getClientId(requestParams.get(OidcConstants.CLIENT_ID));
                            clientSecret = requestParams.get(OidcConstants.CLIENT_SECRET);
                        }
                        if (clientId == null) {
                            LOG.error("Client id must be provided");
                            return badClientRequest(context);
                        }

                        if (oidcProxyConfig.externalClientSecret().isPresent()) {
                            if (oidcProxyConfig.externalClientSecret().get().equals(clientSecret)) {
                                clientSecret = configuredClientSecret;
                            } else {
                                LOG.error("Provided client secret does not match the external client secret property");
                                return badClientRequest(context);
                            }
                        }
                        if (configuredClientSecret != null && !configuredClientSecret.equals(clientSecret)) {
                            LOG.error("Provided client secret does not match the OIDC service client secret property");
                            return badClientRequest(context);
                        }

                        Method authMethod = oidcTenantConfig.credentials.clientSecret.method.orElse(Method.BASIC);
                        if (authMethod == Method.BASIC) {
                            String encodedClientIdAndSecret = new String(Base64.getEncoder().encode(
                                    (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)),
                                    StandardCharsets.UTF_8);
                            request.putHeader(String.valueOf(HttpHeaders.AUTHORIZATION),
                                    "Basic " + encodedClientIdAndSecret);
                        } else if (authMethod == Method.POST) {
                            encodeForm(buffer, OidcConstants.CLIENT_ID, clientId);
                            encodeForm(buffer, OidcConstants.CLIENT_SECRET, clientSecret);
                        } else if (authMethod == Method.QUERY) {
                            request.addQueryParam(OidcConstants.CLIENT_ID, OidcCommonUtils.urlEncode(clientId));
                            request.addQueryParam(OidcConstants.CLIENT_SECRET, OidcCommonUtils.urlEncode(clientSecret));
                        }

                        if (!requestParams.contains(OidcConstants.REFRESH_TOKEN_VALUE)) {
                            // code
                            String code = requestParams.get(OidcConstants.CODE_FLOW_CODE);
                            if (code == null) {
                                LOG.error("Authorization code must be provided");
                                return badClientRequest(context);
                            }
                            if (localAuthorizationCodeFlowRedirect && tokenEncryptionKey != null) {
                                try {
                                    code = OidcUtils.decryptString(code, tokenDecryptionKey, getEncryptionAlgorithm());
                                } catch (Throwable tex) {
                                    LOG.error("Code can not be decrypted");
                                    return serverError(context);
                                }
                            }
                            encodeForm(buffer, OidcConstants.CODE_FLOW_CODE, code);
                            // code
                            final String redirectUri = getRedirectUri(context,
                                    requestParams.get(OidcConstants.CODE_FLOW_REDIRECT_URI));
                            if (redirectUri == null) {
                                LOG.error("Redirect URI must be provided");
                                return badClientRequest(context);
                            }
                            encodeForm(buffer, OidcConstants.CODE_FLOW_REDIRECT_URI, redirectUri);
                        } else {
                            // refresh token
                            String refreshToken = requestParams.get(OidcConstants.REFRESH_TOKEN_VALUE);
                            if (refreshToken == null) {
                                LOG.error("Refresh token must be provided");
                                return badClientRequest(context);
                            }
                            if (tokenEncryptionKey != null) {
                                try {
                                    refreshToken = OidcUtils.decryptString(refreshToken, tokenDecryptionKey,
                                            getEncryptionAlgorithm());
                                } catch (Throwable tex) {
                                    LOG.error("Refresh token can not be decrypted");
                                    return serverError(context);
                                }
                            }
                            encodeForm(buffer, OidcConstants.REFRESH_TOKEN_VALUE, refreshToken);
                        }

                        Uni<HttpResponse<Buffer>> response = request.sendBuffer(buffer);
                        return response.onItemOrFailure()
                                .transformToUni(new BiFunction<HttpResponse<Buffer>, Throwable, Uni<? extends Void>>() {
                                    @Override
                                    public Uni<Void> apply(HttpResponse<Buffer> t, Throwable u) {
                                        LOG.debug("OidcProxy: Token exchange: end");

                                        JsonObject body = t.bodyAsJsonObject();
                                        if (!oidcProxyConfig.allowIdToken()) {
                                            body.remove(OidcConstants.ID_TOKEN_VALUE);
                                        }
                                        if (!oidcProxyConfig.allowRefreshToken()) {
                                            body.remove(OidcConstants.REFRESH_TOKEN_VALUE);
                                        }
                                        if (tokenEncryptionKey != null) {
                                            // Encrypt access token
                                            try {
                                                String originalAccessToken = (String) body
                                                        .remove(OidcConstants.ACCESS_TOKEN_VALUE);
                                                if (originalAccessToken != null) {
                                                    String encryptedAccessToken = OidcUtils.encryptString(originalAccessToken,
                                                            tokenEncryptionKey, getEncryptionAlgorithm());
                                                    body.put(OidcConstants.ACCESS_TOKEN_VALUE, encryptedAccessToken);
                                                }
                                            } catch (Throwable tex) {
                                                LOG.error("Access token can not be encrypted");
                                                return serverError(context);
                                            }
                                            // Encrypt refresh token
                                            try {
                                                String originalRefreshToken = (String) body
                                                        .remove(OidcConstants.REFRESH_TOKEN_VALUE);
                                                if (originalRefreshToken != null) {
                                                    String encryptedAccessToken = OidcUtils.encryptString(originalRefreshToken,
                                                            tokenEncryptionKey, getEncryptionAlgorithm());
                                                    body.put(OidcConstants.REFRESH_TOKEN_VALUE, encryptedAccessToken);
                                                }
                                            } catch (Throwable tex) {
                                                LOG.error("Access token can not be encrypted");
                                                return serverError(context);
                                            }
                                        }
                                        endJsonResponse(context, body.toString());
                                        return Uni.createFrom().voidItem();
                                    }
                                });
                    }

                }).subscribe().with(new Consumer<Void>() {
                    @Override
                    public void accept(Void response) {
                    }
                });
    }

    public void jwks(RoutingContext context) {
        LOG.debug("OidcProxy: Get JWK");
        HttpRequest<Buffer> request = client.getAbs(oidcMetadata.getJsonWebKeySetUri());
        request.putHeader(String.valueOf(HttpHeaders.ACCEPT), "application/json");
        request.send()
                .subscribe().with(new Consumer<HttpResponse<Buffer>>() {
                    @Override
                    public void accept(HttpResponse<Buffer> response) {
                        endJsonResponse(context, response.bodyAsString());
                    }
                });
    }

    public void userinfo(RoutingContext context) {
        LOG.debug("OidcProxy: Get UserInfo");

        String authHeader = context.request().getHeader(HttpHeaderNames.AUTHORIZATION);
        if (authHeader == null) {
            LOG.error("Authorization header must be provided");
            badClientRequest(context);
            return;
        }

        if (!authHeader.contains("Bearer")) {
            LOG.error("Authorization Bearer scheme must be used");
            badClientRequest(context);
            return;
        }

        HttpRequest<Buffer> request = client.getAbs(oidcMetadata.getUserInfoUri());
        request.putHeader(String.valueOf(HttpHeaderNames.AUTHORIZATION), authHeader);
        request.putHeader(String.valueOf(HttpHeaders.ACCEPT), "application/json");
        request.send()
                .subscribe().with(new Consumer<HttpResponse<Buffer>>() {
                    @Override
                    public void accept(HttpResponse<Buffer> response) {
                        endJsonResponse(context, response.bodyAsString());
                    }
                });
    }

    public void wellKnownConfig(RoutingContext context) {
        LOG.debug("OidcProxy: Well Known Configuration");
        JsonObject json = new JsonObject();
        json.put(OidcConfigurationMetadata.AUTHORIZATION_ENDPOINT,
                buildUri(context, oidcProxyConfig.rootPath() + oidcProxyConfig.authorizationPath()));
        json.put(OidcConfigurationMetadata.TOKEN_ENDPOINT,
                buildUri(context, oidcProxyConfig.rootPath() + oidcProxyConfig.tokenPath()));
        if (oidcMetadata.getJsonWebKeySetUri() != null) {
            json.put(OidcConfigurationMetadata.JWKS_ENDPOINT,
                    buildUri(context, oidcProxyConfig.rootPath() + oidcProxyConfig.jwksPath()));
        }
        if (oidcMetadata.getEndSessionUri() != null) {
            json.put(OidcConfigurationMetadata.END_SESSION_ENDPOINT,
                    buildUri(context, oidcProxyConfig.rootPath() + oidcProxyConfig.endSessionPath()));
        }
        if (oidcMetadata.getUserInfoUri() != null && oidcProxyConfig.allowIdToken()) {
            json.put(OidcConfigurationMetadata.USERINFO_ENDPOINT,
                    buildUri(context, oidcProxyConfig.rootPath() + oidcProxyConfig.userInfoPath()));
        }
        if (oidcMetadata.getIssuer() != null) {
            json.put(OidcConfigurationMetadata.ISSUER, oidcMetadata.getIssuer());
        }
        endJsonResponse(context, json.toString());
    }

    private Uni<Void> badClientRequest(RoutingContext context) {
        context.response().setStatusCode(400);
        context.response().end();
        return Uni.createFrom().voidItem();
    }

    private Uni<Void> serverError(RoutingContext context) {
        context.response().setStatusCode(500);
        context.response().end();
        return Uni.createFrom().voidItem();
    }

    private static void endJsonResponse(RoutingContext context, String jsonResponse) {
        context.response().setStatusCode(HttpResponseStatus.OK.code());
        context.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        context.end(jsonResponse);
    }

    public static void encodeForm(Buffer buffer, String name, String value) {
        if (buffer.length() != 0) {
            buffer.appendByte((byte) '&');
        }
        buffer.appendString(name);
        buffer.appendByte((byte) '=');
        buffer.appendString(OidcCommonUtils.urlEncode(value));
    }

    private String getClientId(String providedClientId) {
        if (oidcProxyConfig.externalClientId().isPresent()) {
            if (oidcProxyConfig.externalClientId().get().equals(providedClientId)) {
                return oidcTenantConfig.clientId.get();
            } else {
                LOG.errorf("Provided client id '%s' does not match the external client id '%s' property", providedClientId,
                        oidcProxyConfig.externalClientId().get());
                return null;
            }
        }
        if (oidcTenantConfig.clientId.isPresent() && !oidcTenantConfig.clientId.get().equals(providedClientId)) {
            LOG.error("Provided client id does not match the OIDC service client id property");
            return null;
        }
        return providedClientId;
    }

    private String getRedirectUri(RoutingContext context, String redirectUri) {
        if (localAuthorizationCodeFlowRedirect) {
            return buildUri(context, oidcTenantConfig.authentication.redirectPath.get());
        } else {
            return redirectUri;
        }
    }

    private String getPostLogoutUri(RoutingContext context, String postLogoutUri) {
        if (oidcTenantConfig.logout().postLogoutPath().isPresent()) {
            return OidcCommonUtils.urlEncode(buildUri(context, oidcTenantConfig.logout().postLogoutPath().get()));
        } else {
            return postLogoutUri;
        }
    }

    private String encodeScope(String providedScope) {
        final String scopeSeparator = oidcTenantConfig.authentication.scopeSeparator.orElse(OidcUtils.DEFAULT_SCOPE_SEPARATOR);
        Set<String> scopes = new HashSet<>(OidcUtils.getAllScopes(oidcTenantConfig));
        scopes.addAll(providedScope != null && !providedScope.isEmpty() ? Arrays.asList(providedScope.split(scopeSeparator))
                : List.of());
        if (oidcTenantConfig.authentication.addOpenidScope.orElse(true)) {
            scopes.add(OidcConstants.OPENID_SCOPE);
        } else {
            scopes.remove(OidcConstants.OPENID_SCOPE);
        }
        if (!scopes.isEmpty()) {
            return OidcCommonUtils.urlEncode(String.join(scopeSeparator, scopes));
        } else {
            return null;
        }
    }

    private String buildUri(RoutingContext context, String path) {
        final String authority = URI.create(context.request().absoluteURI()).getAuthority();
        final String scheme = oidcTenantConfig.authentication.forceRedirectHttpsScheme.isPresent() ? "https"
                : context.request().scheme();
        return new StringBuilder(scheme).append("://")
                .append(authority)
                .append(httpRootPath)
                .append(path)
                .toString();
    }

    private String[] getClientIdAndSecretFromAuthorization(String authHeader) {
        if (authHeader != null && (authHeader.startsWith("Basic") || authHeader.startsWith("Basic"))) {
            String plainIdSecret = new String(Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
            return plainIdSecret.split(":");
        }
        return null;
    }

    private KeyEncryptionAlgorithm getEncryptionAlgorithm() {
        // TODO: make it configurable
        return tokenEncryptionKey instanceof PublicKey ? KeyEncryptionAlgorithm.RSA_OAEP : KeyEncryptionAlgorithm.A256GCMKW;
    }

    private static Key createTokenEncryptionKey(OidcProxyConfig oidcProxyConfig, OidcTenantConfig oidcTenantConfig,
            String configuredClientSecret) {
        if (oidcTenantConfig.token().decryptAccessToken()) {
            if (oidcProxyConfig.tokenEncryptionKeyLocation().isPresent()) {
                try {
                    return KeyUtils.readEncryptionKey(oidcProxyConfig.tokenEncryptionKeyLocation().get(), null);
                } catch (Throwable ex) {
                    throw new ConfigurationException(
                            "Token encryption key can not be read from " + oidcProxyConfig.tokenEncryptionKeyLocation().get(),
                            ex);
                }
            }
            if (!configuredClientSecret.isEmpty()) {
                return OidcUtils.createSecretKeyFromDigest(configuredClientSecret);
            }
            throw new ConfigurationException(
                    "Token encryption key must be available for the OIDC proxy to use it to encrypt tokens"
                            + "because OIDC service expects encrypted access tokens.");
        }
        return null;
    }
}
