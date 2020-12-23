package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.security.oauth2openid.providers.ClientDataProvider;
import com.predic8.membrane.core.interceptor.oauth2.ClientList;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class MembraneClientDataProvider implements ClientDataProvider {
    private final ClientList clientList;

    public MembraneClientDataProvider(ClientList clientList) {
        this.clientList = clientList;
    }

    @Override
    public boolean clientExists(String clientId) {
        return clientList.getClient(clientId) != null;
    }

    @Override
    public boolean isConfidential(String clientId) {
        if (clientExists(clientId))
            return clientList.getClient(clientId).getClientSecret() != null;
        return false;
    }

    @Override
    public boolean verify(String clientId, String clientSecret) {
        if (clientExists(clientId))
            return clientList.getClient(clientId).verify(clientId, clientSecret);
        return false;
    }

    @Override
    public Set<String> getRedirectUris(String clientId) {
        if (clientExists(clientId))
            return new HashSet<>(Arrays.asList(clientList.getClient(clientId).getCallbackUrl()));
        return new HashSet<>();
    }
}
