package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.impl.InMemoryToken;
import com.bornium.impl.InMemoryTokenManager;
import com.bornium.security.oauth2openid.providers.TokenPersistenceProvider;
import com.bornium.security.oauth2openid.token.Token;
import com.bornium.security.oauth2openid.token.TokenManager;

import java.time.Duration;
import java.time.LocalDateTime;

public class MembraneTokenPersistenceProvider implements TokenPersistenceProvider {
    @Override
    public Token createToken(String value, String username, String clientId, LocalDateTime issued, Duration validFor, String claims, String scope, String redirectUri, String nonce) {
        return new InMemoryToken(value, username, clientId, issued, validFor, claims, scope, redirectUri, nonce) {
        };
    }

    @Override
    public TokenManager createTokenManager(String tokenManagerId) {
        return new InMemoryTokenManager();
    }
}
