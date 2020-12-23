package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.security.oauth2openid.providers.ConsentProvider;
import com.bornium.security.oauth2openid.server.ConsentContext;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.util.Map;
import java.util.concurrent.ExecutionException;

public class MembraneConsentProvider implements ConsentProvider {
    Cache<String, Cache<String, ConsentContext>> userToClientIdToGivenScopes = CacheBuilder.newBuilder().build();

    @Override
    public void persist(ConsentContext ctx) {
        try {
            Cache<String, ConsentContext> clients = userToClientIdToGivenScopes.get(ctx.getUsername(), () -> CacheBuilder.newBuilder().build());
            clients.put(ctx.getClientId(), ctx);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Map<String, ConsentContext> getConsentFor(String username) {
        try {
            return userToClientIdToGivenScopes.get(username, () -> CacheBuilder.newBuilder().build()).asMap();
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }
}
