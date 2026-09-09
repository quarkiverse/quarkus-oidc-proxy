package io.quarkus.oidc.proxy.runtime;

import org.jboss.logging.Logger;

import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.oidc.runtime.TenantConfigBean;
import io.quarkus.oidc.runtime.TenantConfigContext;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.vertx.ext.web.Router;

@Recorder
public class OidcProxyRecorder {

    private static final Logger LOG = Logger.getLogger(OidcProxyRecorder.class);

    final RuntimeValue<OidcProxyConfig> oidcProxyConfig;

    public OidcProxyRecorder(RuntimeValue<OidcProxyConfig> oidcProxyConfig) {
        this.oidcProxyConfig = oidcProxyConfig;
    }

    public void setupRoutes(BeanContainer beanContainer, RuntimeValue<Router> routerValue, String httpRootPath) {
        TenantConfigBean oidcTenantBean = beanContainer.beanInstance(TenantConfigBean.class);
        TenantConfigContext tenantConfigContext = oidcProxyConfig.getValue().tenantId().isEmpty()
                ? oidcTenantBean.getDefaultTenant()
                : oidcTenantBean.getStaticTenantsConfig().get(oidcProxyConfig.getValue().tenantId().get());
        if (tenantConfigContext.getOidcTenantConfig().tenantEnabled()) {
            OidcProxy proxy = new OidcProxy(oidcTenantBean, oidcProxyConfig.getValue(), httpRootPath);
            Router router = routerValue.getValue();
            proxy.setup(router);
        } else {
            LOG.debugf("Skipping OIDC proxy for the disabled tenant '%s'",
                    oidcTenantBean.getDefaultTenant().getOidcTenantConfig().clientName().orElse("default"));
        }
    }
}
