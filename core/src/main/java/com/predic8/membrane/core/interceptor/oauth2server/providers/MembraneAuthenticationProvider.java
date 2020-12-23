package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.http.Exchange;
import com.bornium.http.ResponseBuilder;
import com.bornium.security.oauth2openid.Constants;
import com.bornium.security.oauth2openid.providers.AuthenticationProvider;
import com.bornium.security.oauth2openid.providers.LoginResult;
import com.bornium.security.oauth2openid.server.AuthorizationServer;
import com.google.common.collect.ImmutableMap;
import com.predic8.membrane.core.util.URLParamUtil;

import java.util.function.Consumer;

public class MembraneAuthenticationProvider implements AuthenticationProvider {
    @Override
    public void initiateAuthenticationAndConsent(String grantContextId, boolean skipConsentCheck, Exchange exchange, AuthorizationServer authorizationServer, Consumer<LoginResult> consumer) {
        exchange.setResponse(new ResponseBuilder().redirectTempWithGet("/login/login?"+ URLParamUtil.encode(ImmutableMap.<String,String>builder()
                .put(Constants.GRANT_CONTEXT_ID, grantContextId)
                .put("target","")
                .build())).build());
    }
}
