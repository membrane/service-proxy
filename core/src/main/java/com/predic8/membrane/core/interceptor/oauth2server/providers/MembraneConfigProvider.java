package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.security.oauth2openid.permissions.Scope;
import com.bornium.security.oauth2openid.providers.ActiveGrantsConfiguration;
import com.bornium.security.oauth2openid.providers.ConfigProvider;
import com.bornium.security.oauth2openid.providers.NonSpecConfiguration;
import com.bornium.security.oauth2openid.server.TokenContext;
import com.predic8.membrane.core.interceptor.oauth2.ClaimList;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MembraneConfigProvider implements ConfigProvider {

    private final NonSpecConfiguration nonSpecConfiguration;
    private final ClaimList claimList;
    private ActiveGrantsConfiguration activeGrantsConfiguration;

    public MembraneConfigProvider(ClaimList claimList) {
        this.claimList = claimList;
        nonSpecConfiguration = new NonSpecConfiguration();
        activeGrantsConfiguration = new ActiveGrantsConfiguration();
    }

    @Override
    public boolean useReusableRefreshTokens(TokenContext tokenContext) {
        return false;
    }

    @Override
    public ActiveGrantsConfiguration getActiveGrantsConfiguration() {
        return activeGrantsConfiguration;
    }

    @Override
    public boolean disableNonRecommendedGrants() {
        return false;
    }

    @Override
    public List<Scope> getSupportedScopes(List<Scope> defaultProvided) {
        return Stream.concat(defaultProvided.stream(), claimList.getScopes().stream().map(memScope -> new Scope(memScope.getId(), memScope.getClaims().split(Pattern.quote(" "))))).collect(Collectors.toList());
    }

    @Override
    public Set<String> getSupportedClaims(Set<String> defaultProvided) {
        return Stream.concat(defaultProvided.stream(), claimList.getSupportedClaims().stream()).collect(Collectors.toSet());
    }

    @Override
    public NonSpecConfiguration getNonSpecConfiguration() {
        return nonSpecConfiguration;
    }
}
