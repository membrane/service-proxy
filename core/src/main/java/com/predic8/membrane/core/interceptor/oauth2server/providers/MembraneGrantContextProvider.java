package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.security.oauth2openid.providers.GrantContext;
import com.bornium.security.oauth2openid.providers.GrantContextProvider;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class MembraneGrantContextProvider extends GrantContextProvider {

    Cache<String, GrantContext> ctxs = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();

    @Override
    public GrantContext create() {
        return new GrantContext() {

            Map<String, String> state = new HashMap<>();

            @Override
            public String getValue(String key) {
                return state.get(key);
            }

            @Override
            public void putValue(String key, String value) {
                state.put(key, value);
            }

            @Override
            public Set<String> allKeys() {
                return state.keySet();
            }

            @Override
            public void removeValue(String key) {
                state.remove(key);
            }

            @Override
            public void clear() {
                state.clear();
            }
        };
    }

    @Override
    public void persist(GrantContext ctx) {
        try {
            ctxs.put(ctx.getIdentifier(), ctx);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public void invalidationHint(String... identifiers) {
        Arrays.stream(identifiers).forEach(id -> ctxs.invalidate(id));
    }

    @Override
    public Optional<GrantContext> findById(String identifier) {
        if (identifier == null)
            return Optional.empty();

        GrantContext ctx = ctxs.getIfPresent(identifier);
        if (ctx != null) {
            try {
                return Optional.ofNullable(ctx);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        return Optional.empty();
    }
}
