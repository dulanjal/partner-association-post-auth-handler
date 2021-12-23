# Partner Association Post Authentication Handler

This is a sample Post Authentication Handler that work alongside an Adaptive Authentication script to call a backend 
endpoint and associate a user attribute from the local IdP with an attribute of same physical user from a partner IdP.

It is the responsibility of the application (i.e. Service Provider) to send a custom parameter named 'pidp' (i.e. Partner IdP)
in the authentication request with the value of an external IdP's name that is already registered with the local IdP. 

This flow is tested with WSO2 Identity Server v5.9.0.

## Table of contents

- [Download and install](#download-and-install)
- [Getting started](#getting-started)

## Download and install

### Install from source

#### Prerequisites

* [Maven](https://maven.apache.org/download.cgi)
* [Java](http://www.oracle.com/technetwork/java/javase/downloads)

1. Get a clone or download source from this repository
2. Run the Maven command `mvn clean install` from within the partner-association-post-auth-handler directory.

## Getting started

In the following instructions, WSO2 IS installation directory will be referred as `<IS_HOME>`

1. Copy `partner-association-post-auth-handler/target/org.wso2.carbon.identity.post.authn.handler.partnerassociation-1.0.0-SNAPSHOT` to `<IS_HOME>/repository/components/dropins` and restart the server.
2. Go to the 'Identity Providers' UI in IS and configure the Partner IdPs.
3. Go to the respective Service Provider's configuration, and in 'Local & Outbound Authentication Configuration', select 'Advanced Configuration'. Under 'Authentication Step Configuration', configure Basic Authenticator for the first step. And for the 2nd step, add the registered Partner IdPs.
4. In 'Script Based Adaptive Authentication' section, paste the following script. 
   NOTE: 
   * Make sure to change the `pidpList` variable and configure the names of the IdPs you registered. 'PartnerIdP1' and 'PartnerIdP2' are used just for example.
   * Make sure to change the attribute name returned from your Partner IdP. In this script 'xaccountId' and 'yaccountId' are used just for example.

```
// Global varialble to maintain the list of registered Partner IdP names
var pidpList = ['PartnerIdP1','PartnerIdP2'];

/* Global varialble to maintain the value of 'pidp' (i.e. Partner IdP)
   parameter from the authentication request */
var pidpFromReq;

function onLoginRequest(context) {
    /* Read the 'pidp' parameter from the authentication request 
    and store it in the global variable */
    var pidpParam = context.request.params.pidp;
    if (pidpParam != null && pidpParam.length > 0) {
        pidpFromReq = pidpParam[0];
    }
    
    executeStep(1, {
        onSuccess: function (context) {
            /* If the 'pidp' is a valid IdP, execute that as the 2nd step.
               Else, ignore the 2nd step. */
            if (pidpFromReq != null && pidpList.indexOf(pidpFromReq) >= 0) {
                executeStep(2,{authenticationOptions:[{idp:pidpFromReq}]}, {
                    onSuccess: function (context) {
                        // Read the IdP specific attributes
                        var pUser = context.steps[2].subject;
                        var remoteAttr; 
                        if (context.steps[2].idp === "PartnerIdP1") {
                            remoteAttr = pUser.remoteClaims.xaccountId;
                        }
                        if (context.steps[2].idp === "PartnerIdP2") {
                            remoteAttr = pUser.remoteClaims.yaccountId;
                        }
                        /* Map the remote attribute to an attribute known by the 
                        Partner Association Post-Authentication Handler */
                        if(remoteAttr) {
                            pUser.remoteClaims.partnerAccId = remoteAttr;
                        }
                    }
                });
            } 
        }
    });
}

```
5. To mock the backend service following command can be used: `while : ; do (echo -ne "HTTP/1.1 200 OK\r\n";) | nc -l 8000 ; done`
6. Send an OIDC Request with the custom "pidp" parameter that specify the Partner IdP's name as following: 
`https://<IS_HOST>:<IS_PORT>/oauth2/authorize?scope=openid&response_type=code&redirect_uri=<client-redirect-uri>&client_id=<client-id>&pidp=<idp-name>`
E.g.: `https://localhost:9443/oauth2/authorize?scope=openid&response_type=code&redirect_uri=http://localhost:8080/playground2/oauth2client&client_id=ZHLUdHW5Jlfi21TcCTWTwxuBHO4a&pidp=PartnerIdP1`



