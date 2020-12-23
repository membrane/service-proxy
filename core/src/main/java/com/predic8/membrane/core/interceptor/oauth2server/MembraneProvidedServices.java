/* Copyright 2019 predic8 GmbH, www.predic8.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */
package com.predic8.membrane.core.interceptor.oauth2server;

import com.bornium.impl.BearerTokenProvider;
import com.bornium.security.oauth2openid.providers.*;
import com.bornium.security.oauth2openid.server.*;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.predic8.membrane.core.interceptor.oauth2.ClaimList;
import com.predic8.membrane.core.interceptor.oauth2.ClientList;
import com.predic8.membrane.core.interceptor.oauth2server.providers.*;
import com.predic8.membrane.core.interceptor.session.SessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class MembraneProvidedServices implements ProvidedServices {

    private final AuthenticationProvider authenticationProvider;
    private final TokenPersistenceProvider tokenPersistenceProvider;
    private final GrantContextProvider grantContextProvider;
    private final ConsentProvider consentProvider;
    private final String subClaimName;
    Logger log = LoggerFactory.getLogger(MembraneProvidedServices.class);

    public Cache<String,Map<String,String>> verifiedUsers = CacheBuilder
            .newBuilder()
            .expireAfterAccess(1, TimeUnit.HOURS)
            .build();

    private com.predic8.membrane.core.interceptor.authentication.session.UserDataProvider userDataProvider;
    private String issuer;
    private String contextPath;
    private EndpointFactory factory;
    private ConfigProvider configProvider;
    private UserDataProvider userDataProvider1;
    private ClientDataProvider clientDataProvider;
    private SessionProvider sessionProvider;

    public MembraneProvidedServices(SessionManager sessionManager,
                                    ClientList clientList,
                                    com.predic8.membrane.core.interceptor.authentication.session.UserDataProvider userDataProvider,
                                    String subClaimName,
                                    String issuer,
                                    ClaimList claimList,
                                    String contextPath,
                                    EndpointFactory factory){
        this.userDataProvider = userDataProvider;
        this.issuer = issuer;
        this.contextPath = contextPath;
        this.factory = factory;
        this.subClaimName = subClaimName;

        authenticationProvider = new MembraneAuthenticationProvider();

        configProvider = new MembraneConfigProvider(claimList);
        tokenPersistenceProvider = new MembraneTokenPersistenceProvider();
        userDataProvider1 = new MembraneUserDataProvider(this, userDataProvider, subClaimName);
        clientDataProvider = new MembraneClientDataProvider(clientList);
        sessionProvider = new MembraneSessionProvider(sessionManager);
        grantContextProvider = new MembraneGrantContextProvider();
        consentProvider = new MembraneConsentProvider();
    }

    @Override
    public ConsentProvider getConsentProvider() {
        return consentProvider;
    }

    @Override
    public GrantContextProvider getGrantContextProvider() {
        return grantContextProvider;
    }

    @Override
    public SessionProvider getSessionProvider() {
        return sessionProvider;
    }

    @Override
    public ClientDataProvider getClientDataProvider() {

        return clientDataProvider;
    }

    @Override
    public UserDataProvider getUserDataProvider() {
        return userDataProvider1;
    }

    @Override
    public TokenPersistenceProvider getTokenPersistenceProvider() {
        return tokenPersistenceProvider;
    }

    @Override
    public TimingProvider getTimingProvider() {
        return new DefaultTimingProvider();
    }

    @Override
    public TokenProvider getTokenProvider() {
        return new BearerTokenProvider();
    }

    @Override
    public ConfigProvider getConfigProvider() {
        return configProvider;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public String getContextPath() {
        return contextPath;
    }

    @Override
    public String getSubClaimName() {
        return subClaimName;
    }

    @Override
    public EndpointFactory getEndpointFactory() {
        return factory;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

}
