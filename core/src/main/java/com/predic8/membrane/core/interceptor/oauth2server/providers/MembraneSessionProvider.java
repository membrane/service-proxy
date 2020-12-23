package com.predic8.membrane.core.interceptor.oauth2server.providers;

import com.bornium.http.Exchange;
import com.bornium.security.oauth2openid.providers.Session;
import com.bornium.security.oauth2openid.providers.SessionProvider;
import com.predic8.membrane.core.interceptor.oauth2server.Convert;
import com.predic8.membrane.core.interceptor.session.SessionManager;

public class MembraneSessionProvider implements SessionProvider {
    private final SessionManager sessionManager;

    public MembraneSessionProvider(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @Override
    public Session getSession(Exchange exc) {
        com.predic8.membrane.core.exchange.Exchange memExc = Convert.convertToMembraneExchange(exc);
        com.predic8.membrane.core.interceptor.session.Session memSession = sessionManager.getSession(memExc);
        exc.getProperties().putAll(memExc.getProperties());
        return new Session() {

            @Override
            public String getValue(String key) throws Exception {
                return memSession.get(key);
            }

            @Override
            public void putValue(String key, String value) throws Exception {
                memSession.put(key, value);
            }

            @Override
            public void removeValue(String key) throws Exception {
                memSession.remove(key);
            }

            @Override
            public void clear() throws Exception {
                memSession.clear();
            }
        };
    }
}
