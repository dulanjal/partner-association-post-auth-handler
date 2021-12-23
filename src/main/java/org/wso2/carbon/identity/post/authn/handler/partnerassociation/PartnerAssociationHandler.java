package org.wso2.carbon.identity.post.authn.handler.partnerassociation;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.post.authn.handler.partnerassociation.internal.PartnerAssociationHandlerServiceComponent;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserRealm;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PartnerAssociationHandler extends AbstractPostAuthnHandler {

    private static final Log log = LogFactory.getLog(PartnerAssociationHandler.class);
    private final String APP_NAME = "MemberZone";
    private final String LOCAL_ATTR = "http://wso2.org/claims/userid";
    private final String MAPPING_ATTR = "partnerAccId";
    private final String BACK_END_URL = "http://localhost:8000";

    @Override
    public String getName() {
        return "PartnerAssociationHandler";
    }

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest httpServletRequest,
                                             HttpServletResponse httpServletResponse,
                                             AuthenticationContext authenticationContext)
            throws PostAuthenticationFailedException {

        // Engage this handler only if the application is MemberZone and there are two authentication steps
        if (!APP_NAME.equalsIgnoreCase(authenticationContext.getSequenceConfig().getApplicationId())
                || authenticationContext.getSequenceConfig().getStepMap().size() != 2) {
            return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
        }

        AuthenticatedUser localUser = null;
        String localAttribute = null;
        AuthenticatedUser partnerUser = null;
        String partnerAttribute = null;

        try {
            for (Map.Entry<Integer, StepConfig> stepEntry : authenticationContext.getSequenceConfig().getStepMap().entrySet()) {
                StepConfig stepConfig = stepEntry.getValue();
                // Get the username from the first step (i.e. authenticated from "LOCAL" IdP)
                if ("LOCAL".equalsIgnoreCase(stepConfig.getAuthenticatedIdP())) {
                    localUser = stepConfig.getAuthenticatedUser();
                    if (localUser != null) {
                        // Query any necessary attribute from the local user store
                        localAttribute = getAttributeFromUserStore(localUser, LOCAL_ATTR);
                        //if (localAttribute == null || localAttribute.isEmpty()) {
                            throw new PartnerAssociationException("Could not retrieve local attribute value");
                        //}
                    } else {
                        throw new PartnerAssociationException("Could not retrieve local user");
                    }
                } else {
                    // Get the username from the second step (i.e. authenticated from a Partner IdP)
                    partnerUser = stepConfig.getAuthenticatedUser();
                    if (partnerUser != null) {
                        // Get the required attribute from the attributes map of the second step
                        for (Map.Entry<ClaimMapping, String> attrEntry : partnerUser.getUserAttributes().entrySet()) {
                            if (MAPPING_ATTR.equalsIgnoreCase(attrEntry.getKey().getLocalClaim().getClaimUri())) {
                                partnerAttribute = attrEntry.getValue();
                            }
                        }
                        if (partnerAttribute == null || partnerAttribute.isEmpty()) {
                            throw new PartnerAssociationException("Could not retrieve partner attribute value");
                        }
                    } else {
                        throw new PartnerAssociationException("Could not retrieve partner user");
                    }
                }
            }
            // Call the backend service
            Map<String, String> reqParams = new HashMap<String, String>();
            reqParams.put("local-attribute", localAttribute);
            reqParams.put("partner-attribute", partnerAttribute);
            sendBackendReq(reqParams);
        } catch (PartnerAssociationException e) {
            log.error(e.getMessage(), e);
            throw new PostAuthenticationFailedException("Partner Association Failed", "Partner Association Failed");
        }

        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
    }

    private String getAttributeFromUserStore(AuthenticatedUser user, String claimUri) throws PartnerAssociationException {
        String attributeValue = null;
        String tenantDomain = user.getTenantDomain();
        String tenantAwareUserName = user.getUserName();
        UserRealm realm = getUserRealm(tenantDomain);
        if (realm == null) {
            log.warn("No valid tenant domain provider. No claims found");
        }
        UserStoreManager userStore = getUserStoreManager(tenantDomain, realm, user.getUserStoreDomain());
        try {
            attributeValue = userStore.getUserClaimValue(tenantAwareUserName, claimUri, null);
        } catch (UserStoreException e) {
            throw new PartnerAssociationException("Error occurred while getting attribute from user store", e);
        }
        return attributeValue;
    }

    private void sendBackendReq(Map reqParams) throws PartnerAssociationException {
        URL url = null;
        try {
            url = new URL(BACK_END_URL);
            HttpURLConnection con = null;
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            DataOutputStream out = new DataOutputStream(con.getOutputStream());
            out.writeBytes(getParamsString(reqParams));
            out.flush();
            out.close();
            con.getResponseCode();
        } catch (IOException e) {
            throw new PartnerAssociationException("Error occurred while sending the backend request", e);
        }
    }

    public String getParamsString(Map<String, String> params) throws PartnerAssociationException {
        StringBuilder result = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            try {
                result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
                result.append("=");
                result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
                result.append("&");
            } catch (UnsupportedEncodingException e) {
                throw new PartnerAssociationException("Error occurred while building the backend request", e);
            }
        }
        String resultString = result.toString();
        return resultString.length() > 0
                ? resultString.substring(0, resultString.length() - 1)
                : resultString;
    }

    private UserRealm getUserRealm(String tenantDomain) throws PartnerAssociationException {
        UserRealm realm;
        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(
                    PartnerAssociationHandlerServiceComponent.getRegistryService(),
                    PartnerAssociationHandlerServiceComponent.getRealmService(), tenantDomain);
        } catch (CarbonException e) {
            throw new PartnerAssociationException("Error occurred while retrieving the Realm for " +
                    tenantDomain + " to handle local claims", e);
        }
        return realm;
    }

    private UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain) throws
            PartnerAssociationException {
        UserStoreManager userStore = null;
        try {
            userStore = realm.getUserStoreManager();
            if (StringUtils.isNotBlank(userDomain)) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userDomain);
            }
            if (userStore == null) {
                // To avoid NPEs
                throw new PartnerAssociationException("Invalid user store domain name : " + userDomain + " in tenant : "
                        + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new PartnerAssociationException("Error occurred while retrieving the UserStoreManager " +
                    "from Realm for " + tenantDomain + " to handle local claims", e);
        }
        return userStore;
    }
}
