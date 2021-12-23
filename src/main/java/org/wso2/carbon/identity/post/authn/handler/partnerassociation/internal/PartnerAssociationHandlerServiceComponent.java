package org.wso2.carbon.identity.post.authn.handler.partnerassociation.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.post.authn.handler.partnerassociation.PartnerAssociationHandler;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.post.authn.partnerassociation.handler",
        immediate = true
)
public class PartnerAssociationHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(PartnerAssociationHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {
        try {
            PartnerAssociationHandler partnerAssociationHandler =
                    new PartnerAssociationHandler();
            context.getBundleContext().registerService(PostAuthenticationHandler.class.getName(),
                    partnerAssociationHandler, null);

        } catch (Throwable e) {
            log.error("Error while activating partnerassociation post authentication handler.", e);
        }
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "identity.core.init.event.service",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    public static RealmService getRealmService() {
        return PartnerAssociationHandlerServiceDataHolder.getInstance().getRealmService();
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Application Authentication Framework bundle");
        }
        PartnerAssociationHandlerServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the Application Authentication Framework bundle");
        }
        PartnerAssociationHandlerServiceDataHolder.getInstance().setRealmService(null);
    }

    public static RegistryService getRegistryService() {
        return PartnerAssociationHandlerServiceDataHolder.getInstance().getRegistryService();
    }

    @Reference(
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is set in the Application Authentication Framework bundle");
        }
        PartnerAssociationHandlerServiceDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService is unset in the Application Authentication Framework bundle");
        }
        PartnerAssociationHandlerServiceDataHolder.getInstance().setRegistryService(null);
    }
}

