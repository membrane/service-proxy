package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.security.oauth2openid.providers.UserDataProvider;
import com.predic8.membrane.core.interceptor.oauth2server.MembraneProvidedServices;

import java.util.*;
import java.util.stream.Collectors;

public class MembraneUserDataProvider implements UserDataProvider {
    private final MembraneProvidedServices membraneProvidedServices;
    private final com.predic8.membrane.core.interceptor.authentication.session.UserDataProvider userDataProvider;
    private final String subClaimName;

    public MembraneUserDataProvider(MembraneProvidedServices membraneProvidedServices, com.predic8.membrane.core.interceptor.authentication.session.UserDataProvider userDataProvider, String subClaimName) {
        this.membraneProvidedServices = membraneProvidedServices;
        this.userDataProvider = userDataProvider;
        this.subClaimName = subClaimName;
    }

    @Override
    public boolean verifyUser(String username, String password) {
        HashMap<String, String> postData = new HashMap<>();
        postData.put("username", username);
        postData.put("password", password);
        try {
            Map<String, String> attr = userDataProvider.verify(postData);
            membraneProvidedServices.verifiedUsers.put(username, attr);
            return true;
        } catch (NoSuchElementException e) {
            return false;
        }
    }

    @Override
    public Map<String, Object> getClaims(String username, Set<String> publicClaimNames) {
        return membraneProvidedServices.verifiedUsers
                .getIfPresent(username)
                .entrySet()
                .stream()
                .filter(e -> publicClaimNames.contains(e.getKey()))
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
    }

    @Override
    public String getSubClaim(String username) {
        return getClaims(username, new HashSet<>(Arrays.asList(subClaimName))).get(subClaimName).toString();
    }
}
