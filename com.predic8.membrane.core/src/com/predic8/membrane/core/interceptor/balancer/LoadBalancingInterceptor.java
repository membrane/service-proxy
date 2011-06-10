/* Copyright 2009 predic8 GmbH, www.predic8.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */
package com.predic8.membrane.core.interceptor.balancer;

import java.net.*;
import java.util.*;

import org.apache.commons.logging.*;

import com.predic8.membrane.core.exchange.Exchange;
import com.predic8.membrane.core.http.Message;
import com.predic8.membrane.core.interceptor.*;
import com.predic8.membrane.core.transport.http.HostColonPort;

public class LoadBalancingInterceptor extends AbstractInterceptor {

	private static Log log = LogFactory.getLog(LoadBalancingInterceptor.class.getName());
	
	private List<Node> endpoints;

	private DispatchingStrategy strategy = new RoundRobinStrategy();

	public Map<String, Node> sessions = new HashMap<String, Node>();
	
	private XMLElementSessionIdExtractor sesssionIdExtractor;
	
	@Override
	public Outcome handleRequest(Exchange exc) throws Exception {

		Node dispatchedNode = getDispatchedNode(exc.getRequest());
		dispatchedNode.incCounter();
		dispatchedNode.addThread();
		
		exc.setProperty("dispatchedNode", dispatchedNode);
		
		exc.setOriginalRequestUri(getDestinationURL(dispatchedNode, exc));
		
		exc.getDestinations().clear();
		exc.getDestinations().add(getDestinationURL(dispatchedNode, exc));

		for (Node ep : getEndpoints()) {
			if (!ep.equals(dispatchedNode))
				exc.getDestinations().add(getDestinationURL(ep, exc));
		}

		return Outcome.CONTINUE;
	}
	
	@Override
	public Outcome handleResponse(Exchange exc) throws Exception {

		if (sesssionIdExtractor != null && exc.getResponse().isXML() ) {
			String sessionId = getSessionId(exc.getResponse());
			
			if ( sessionId != null && !sessions.containsKey(sessionId) ) {
				sessions.put( sessionId, (Node)exc.getProperty("dispatchedNode"));
			}
		}		
		
		updateDispatchedNode(exc);
		
		return Outcome.CONTINUE;
	}

	private void updateDispatchedNode(Exchange exc) {
		Node n = (Node)exc.getProperty("dispatchedNode");
		n.removeThread();
		n.addStatusCode(exc.getResponse().getStatusCode());
	}

	private Node getDispatchedNode(Message msg) throws Exception {
		String sessionId;
		if ( sesssionIdExtractor == null || !msg.isXML() || (sessionId = getSessionId(msg)) == null ) {
			return strategy.dispatch(this);
		}
		
		if ( !sessions.containsKey(sessionId) || !sessions.get(sessionId).isUp()) {
			sessions.put(sessionId, strategy.dispatch(this));
		}			
		return sessions.get(sessionId);
	}

	public String getDestinationURL(Node ep, Exchange exc) throws MalformedURLException{
		return "http://" + ep.getHost() + ":" + ep.getPort() + getRequestURI(exc);
	}

	private String getSessionId(Message msg) throws Exception {
		return sesssionIdExtractor.getSessionId(msg);
	}

	private String getRequestURI(Exchange exc) throws MalformedURLException {
		if(exc.getOriginalRequestUri().toLowerCase().startsWith("http://")) // TODO what about HTTPS?
			return new URL(exc.getOriginalRequestUri()).getFile();
		
		return exc.getOriginalRequestUri();
	}

	public DispatchingStrategy getDispatchingStrategy() {
		return strategy;
	}

	public void setDispatchingStrategy(DispatchingStrategy strategy) {
		this.strategy = strategy;
	}

	public List<Node> getEndpoints() {
		if (router.getClusterManager() != null) {
			log.info("using endpoints from cluster manager");
			return router.getClusterManager().getAvailableNodes("Default");
		}
		return endpoints;
	}

	public void setEndpoints(List<String> endpoints) {
		this.endpoints = new LinkedList<Node>();
		for (String s : endpoints ) {
			this.endpoints.add(new Node( new HostColonPort(s).host,
										     new HostColonPort(s).port ));
		}		
	}

	public XMLElementSessionIdExtractor getSesssionIdExtractor() {
		return sesssionIdExtractor;
	}

	public void setSesssionIdExtractor(
			XMLElementSessionIdExtractor sesssionIdExtractor) {
		this.sesssionIdExtractor = sesssionIdExtractor;
	}
	
	
}
