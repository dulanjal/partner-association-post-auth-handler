package org.wso2.carbon.identity.post.authn.handler.partnerassociation.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class PartnerAssociationHandlerServiceDataHolder {
    private static PartnerAssociationHandlerServiceDataHolder instance = new PartnerAssociationHandlerServiceDataHolder();
    private RealmService realmService = null;
    private RegistryService registryService = null;

    public static PartnerAssociationHandlerServiceDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }
}
