/**
 * Copyright (c) 2016 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.evolveum.polygon.connector.ldap;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.connector.ldap.ServerDefinition.Origin;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author Radovan Semancik
 *
 */
public class ConnectionManager<C extends AbstractLdapConfiguration> implements Closeable {
	
	private static final Log LOG = Log.getLog(ConnectionManager.class);
	private static final Random rnd = new Random();
	
	private C configuration;
	private String[] serversConfiguration;
	private ServerDefinition defaultServerDefinition = null;
	private List<ServerDefinition> servers;
	private AbstractSchemaTranslator<C> schemaTranslator;
	private ConnectorBinaryAttributeDetector<C> binaryAttributeDetector = new ConnectorBinaryAttributeDetector<C>();

	public ConnectionManager(C configuration) {
		this(configuration, configuration.getServers(), true);
	}
	
	public ConnectionManager(C configuration, String[] serversConfiguration, boolean useDefaultConnection) {
		this.configuration = configuration;
		this.serversConfiguration = serversConfiguration;
		buildServerList(useDefaultConnection);
	}

	private void buildServerList(boolean useDefaultConnection) {
		servers = new ArrayList<>();
		if (useDefaultConnection) {
			defaultServerDefinition = ServerDefinition.createDefaultDefinition(configuration); 
			servers.add(defaultServerDefinition);
		}
		if (serversConfiguration != null) {
			for(int line = 0; line < serversConfiguration.length; line++) {
				servers.add(ServerDefinition.parse(configuration, serversConfiguration[line], line));
			}
		}
	}
	
	public AbstractSchemaTranslator<C> getSchemaTranslator() {
		return schemaTranslator;
	}

	public void setSchemaTranslator(AbstractSchemaTranslator<C> schemaTranslator) {
		this.schemaTranslator = schemaTranslator;
		binaryAttributeDetector.setSchemaTranslator(schemaTranslator);
	}

	private LdapNetworkConnection getConnection(ServerDefinition server) {
		if (!server.isConnected()) {
			connectServer(server);
		}
		return server.getConnection();
	}
	
	public LdapNetworkConnection getDefaultConnection() {
		if (defaultServerDefinition == null) {
			throw new IllegalStateException("No default connection in this connection manager");
		}
		return getConnection(defaultServerDefinition);
	}
		
	public LdapNetworkConnection getConnection(Dn base) {
		LOG.ok("Selecting server for {0} from servers:\n{1}", base, dumpServers());
		ServerDefinition server = selectServer(base);
		return getConnection(server);
	}
		
	public LdapNetworkConnection getConnectionReconnect(Dn base) {
		return getConnectionReconnect(base, null);
	}
	
	public LdapNetworkConnection getConnectionReconnect(Dn base, Referral referral) {
		LdapUrl ldapUrl = getLdapUrl(referral);
		ServerDefinition server = selectServer(base, ldapUrl);
		LOG.ok("Reconnecting server {0}", server);
		if (server.isConnected()) {
			try {
				closeConnection(server);
			} catch (IOException e) {
				LOG.error("Error closing conection {0}: {1}", server, e.getMessage(), e);
				// Otherwise ignore the error and reconnect anyway
			}
		}
		connectServer(server);
		return server.getConnection();
	}
	
	public LdapNetworkConnection getConnection(Dn base, Referral referral) {
		return getConnection(base, getLdapUrl(referral));
	}
	
	private LdapUrl getLdapUrl(Referral referral) {
		if (referral == null) {
			return null;
		}
		Collection<String> ldapUrls = referral.getLdapUrls();
		if (ldapUrls == null || ldapUrls.isEmpty()) {
			return null;
		}
		String urlString = selectRandomItem(ldapUrls);
		LdapUrl ldapUrl;
		try {
			ldapUrl = new LdapUrl(urlString);
		} catch (LdapURLEncodingException e) {
			throw new IllegalArgumentException("Wrong LDAP URL '"+urlString+"': "+e.getMessage());
		}
		return ldapUrl;
	}

	public LdapNetworkConnection getConnection(Dn base, LdapUrl url) {
		ServerDefinition server = selectServer(base, url);
		if (!server.isConnected()) {
			connectServer(server);
		}
		return server.getConnection();		
	}
	
	public LdapNetworkConnection getRandomConnection() {
		ServerDefinition server = selectRandomServer();
		if (!server.isConnected()) {
			connectServer(server);
		}
		return server.getConnection();		
	}
	
	public Iterable<LdapNetworkConnection> getAllConnections() {
		
		final Iterator<ServerDefinition> serversIterator = servers.iterator();
		
		return new Iterable<LdapNetworkConnection>() {
			
			@Override
			public Iterator<LdapNetworkConnection> iterator() {
				return new Iterator<LdapNetworkConnection>() {

					@Override
					public boolean hasNext() {
						return serversIterator.hasNext();
					}

					@Override
					public LdapNetworkConnection next() {
						return getConnection(serversIterator.next());
					}

					@Override
					public void remove() {
							serversIterator.remove();
					}
					
				};
			}
		};
		
	}

	private ServerDefinition selectServer(Dn dn) {
		String stringDn = dn != null ? dn.getName() : null;
		if (StringUtils.isBlank(stringDn) || !Character.isAlphabetic(stringDn.charAt(0))) {
			// Do not even bother to choose. There are the strange
			// things such as empty DN or the <GUID=...> insanity.
			// The selection will not work anyway.
			if (defaultServerDefinition == null) {
				throw new IllegalStateException("No default connection in this connection manager");
			}
			return defaultServerDefinition;
		}
		Dn selectedBaseContext = null;
		for (ServerDefinition server: servers) {
			Dn serverBaseContext = server.getBaseContext();
			LOG.ok("SELECT: considering {0} ({1}) for {2}", server.getHost(), serverBaseContext, dn);
			if (serverBaseContext == null) {
				continue;
			}
			if (serverBaseContext.equals(dn)) {
				// we cannot get tighter match than this
				selectedBaseContext = dn;
				LOG.ok("SELECT: accepting {0} because {1} is an exact match", server.getHost(), serverBaseContext);
				break;
			}
			if (LdapUtil.isAncestorOf(serverBaseContext, dn, schemaTranslator)) {
				if (serverBaseContext == null || serverBaseContext.isDescendantOf(selectedBaseContext)) {
					LOG.ok("SELECT: accepting {0} because {1} is under {2} and it is the best we have", server.getHost(), dn, serverBaseContext);
					selectedBaseContext = serverBaseContext;
				} else {
					LOG.ok("SELECT: accepting {0} because {1} is under {2} but it is NOT the best we have, {3} is better",
							server.getHost(), dn, serverBaseContext, selectedBaseContext);
				}
			} else {
				LOG.ok("SELECT: refusing {0} because {1} ({2}) is not under {3} ({4})", server.getHost(), 
						dn, dn.isSchemaAware(), 
						serverBaseContext, serverBaseContext.isSchemaAware());
			}
		}
		LOG.ok("SELECT: selected base context: {0}", selectedBaseContext);
		List<ServerDefinition> selectedServers = new ArrayList<>();
		for (ServerDefinition server: servers) {
			if (selectedBaseContext == null && server.getBaseContext() == null) {
				if (server.getOrigin() == Origin.REFERRAL) {
					// avoid using dynamically added servers as a fallback
					// for all queries
					continue;
				} else {
					selectedServers.add(server);
				}
			}
			if (selectedBaseContext == null || server.getBaseContext() == null) {
				continue;
			}
			if (selectedBaseContext.equals(server.getBaseContext())) {
				selectedServers.add(server);
			}
		}
		LOG.ok("SELECT: selected server list: {0}", selectedServers);
		ServerDefinition selectedServer = selectRandomItem(selectedServers);
		if (selectedServer == null) {
			LOG.ok("SELECT: selected default for {0}", dn);
			if (defaultServerDefinition == null) {
				throw new IllegalStateException("No default connection in this connection manager");
			}
			return defaultServerDefinition;
		} else {
			LOG.ok("SELECT: selected {0} for {1}", selectedServer.getHost(), dn);
			return selectedServer;
		}
	}

	private ServerDefinition selectServer(Dn dn, LdapUrl url) {
		if (url == null) {
			return selectServer(dn);
		}
		for (ServerDefinition server: servers) {
			if (server.matches(url)) {
				return server;
			}
		}
		ServerDefinition server = ServerDefinition.createDefinition(configuration, url);
		servers.add(server);
		return server;
	}

	private ServerDefinition selectRandomServer() {
		return selectRandomItem(servers);
	}
	
	public ConnectorBinaryAttributeDetector<C> getBinaryAttributeDetector() {
		return binaryAttributeDetector;
	}

	public boolean isConnected() {
		if (defaultServerDefinition == null) {
			throw new IllegalStateException("No default connection in this connection manager");
		}
		return defaultServerDefinition.getConnection() != null && defaultServerDefinition.getConnection().isConnected();
	}
	
	@Override
	public void close() throws IOException {
		// Make sure that we attempt to close all connection even if there are some exceptions during the close.
		IOException exception = null;
		for (ServerDefinition serverDef: servers) {			
			try {
				closeConnection(serverDef);
			} catch (IOException e) {
				LOG.error("Error closing conection {0}: {1}", serverDef, e.getMessage(), e);
				exception = e;
			}
		}
		if (exception != null) {
			throw exception;
		}
	}
	
	private void closeConnection(ServerDefinition serverDef) throws IOException {
		// Checking for isConnected() is not enough here.
		// Even if the connection is NOT connected it still
		// maintains some resources (pipes) and needs to be
		// explicitly closed from the client side.
		if (serverDef.getConnection() != null) {
			LOG.ok("Closing connection {0}", serverDef);
			serverDef.getConnection().close();
			serverDef.setConnection(null);
		} else {
			LOG.ok("Not closing connection {0} because there is no connection", serverDef);
		}
	}
	
	public void connect() {
		if (defaultServerDefinition != null) {
			connectServer(defaultServerDefinition);
		}
    }
	
	private LdapConnectionConfig createLdapConnectionConfig(ServerDefinition serverDefinition) {
		LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
		connectionConfig.setLdapHost(serverDefinition.getHost());
		connectionConfig.setLdapPort(serverDefinition.getPort());
		connectionConfig.setTimeout(serverDefinition.getConnectTimeout());
		
		String connectionSecurity = serverDefinition.getConnectionSecurity();
    	if (connectionSecurity == null || LdapConfiguration.CONNECTION_SECURITY_NONE.equals(connectionSecurity)) {
    		// Nothing to do
    	} else if (LdapConfiguration.CONNECTION_SECURITY_SSL.equals(connectionSecurity)) {
    		connectionConfig.setUseSsl(true);
    	} else if (LdapConfiguration.CONNECTION_SECURITY_STARTTLS.equals(connectionSecurity)) {
    		connectionConfig.setUseTls(true);
    	} else {
    		throw new ConfigurationException("Unknown value for connectionSecurity: "+connectionSecurity);
    	}
    	
    	String[] enabledSecurityProtocols = configuration.getEnabledSecurityProtocols();
		if (enabledSecurityProtocols != null) {
			connectionConfig.setEnabledProtocols(enabledSecurityProtocols);
		}
		
		String[] enabledCipherSuites = configuration.getEnabledCipherSuites();
		if (enabledCipherSuites != null) {
			connectionConfig.setEnabledCipherSuites(enabledCipherSuites);
		}
		
		String sslProtocol = configuration.getSslProtocol();
		if (sslProtocol != null) {
			connectionConfig.setSslProtocol(sslProtocol);
		}
		
    	connectionConfig.setBinaryAttributeDetector(binaryAttributeDetector);

		return connectionConfig;
	}
	
	private void connectServer(ServerDefinition server) {
		if (server.getConnection() != null) {
			try {
				closeConnection(server);
			} catch (IOException e) {
				throw new ConnectorIOException("Error closing connection to "+server+": "+e.getMessage(), e);
			}
		}
		final LdapConnectionConfig connectionConfig = createLdapConnectionConfig(server);
		LdapNetworkConnection connection = connectConnection(connectionConfig);
		try {
			bind(connection, server);
		} catch (RuntimeException e) {
			try {
				connection.close();
			} catch (IOException e1) {
				LOG.error("Error closing conection (error handling of a bind of a new connection): {1}", e.getMessage(), e);
			}
			throw e;
		}
		server.setConnection(connection);
    }
	
	private LdapNetworkConnection connectConnection(LdapConnectionConfig connectionConfig) {
		LOG.ok("Creating connection object");
		LdapNetworkConnection connection = new LdapNetworkConnection(connectionConfig);
		try {
			LOG.info("Connecting to {0}:{1} as {2}", connectionConfig.getLdapHost(), connectionConfig.getLdapPort(), configuration.getBindDn());
			if (LOG.isOk()) {
				String connectionSecurity = "none";
				if (connectionConfig.isUseSsl()) {
					connectionSecurity = "ssl";
				} else if (connectionConfig.isUseTls()) {
					connectionSecurity = "tls";
				}
				LOG.ok("Connection security: {0} (sslProtocol={1}, enabledSecurityProtocols={2}, enabledCipherSuites={3}",
						connectionSecurity, connectionConfig.getSslProtocol(),
						connectionConfig.getEnabledProtocols(), connectionConfig.getEnabledCipherSuites());
			}
			boolean connected = connection.connect();
			LOG.ok("Connected ({0})", connected);
			if (!connected) {
				throw new ConnectionFailedException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
			}
		} catch (LdapException e) {
			try {
				connection.close();
			} catch (IOException e1) {
				LOG.error("Error closing conection (handling error during creation of a new connection): {1}", e.getMessage(), e);
			}
			throw LdapUtil.processLdapException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort(), e);
		}
		
		return connection;
	}
		
	private void bind(LdapNetworkConnection connection, ServerDefinition server) {
		final BindRequest bindRequest = new BindRequestImpl();
		String bindDn = server.getBindDn();
		try {
			bindRequest.setDn(new Dn(createBindSchemaManager(), bindDn));
		} catch (LdapInvalidDnException e) {
			throw new ConfigurationException("bindDn is not in DN format: "+e.getMessage(), e);
		}
		
		GuardedString bindPassword = server.getBindPassword();
    	if (bindPassword != null) {
    		// I hate this GuardedString!
    		bindPassword.access(new GuardedStringAccessor() {
				@Override
				public void access(char[] chars) {
					bindRequest.setCredentials(new String(chars));
				}
			});
    	}
		
    	BindResponse bindResponse;
		try {
			bindResponse = connection.bind(bindRequest);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Unable to bind to LDAP server "
					+ connection.getConfig().getLdapHost() + ":" + connection.getConfig().getLdapPort() 
					+ " as " + bindDn, e);
		}
		LdapResult ldapResult = bindResponse.getLdapResult();
		if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
			String msg = "Unable to bind to LDAP server " + connection.getConfig().getLdapHost() 
					+ ":" + connection.getConfig().getLdapPort() + " as " + bindDn
					+ ": " + LdapUtil.sanitizeString(ldapResult.getResultCode().getMessage()) + ": " 
					+ LdapUtil.sanitizeString(ldapResult.getDiagnosticMessage() )
					+ " (" + ldapResult.getResultCode().getResultCode() + ")";
			throw new ConfigurationException(msg);
		}
		LOG.info("Bound to {0}:{1} as {2}: {3} ({4})", 
				connection.getConfig().getLdapHost(), connection.getConfig().getLdapPort(), 
				bindDn, ldapResult.getDiagnosticMessage(), ldapResult.getResultCode());
	}
    	
	private SchemaManager createBindSchemaManager() {
		if (schemaTranslator != null && schemaTranslator.getSchemaManager() != null) {
			return schemaTranslator.getSchemaManager();
		}
		Collection<Schema> emptySchemaCollection = new ArrayList<>(0);
		DefaultSchemaManager schemaManager = new DefaultSchemaManager(emptySchemaCollection);
		schemaManager.setRelaxed();
		return schemaManager;
	}

	public boolean isAlive() {
		if (defaultServerDefinition == null) {
			throw new IllegalStateException("No default connection in this connection manager");
		}

		if (defaultServerDefinition.getConnection() == null) {
			return false;
		}
		if (!defaultServerDefinition.getConnection().isConnected()) {
			return false;
		}
		// TODO: try some NOOP operation
		return true;
	}

	private <T> T selectRandomItem(Collection<T> collection) {
		if (collection == null || collection.isEmpty()) {
			return null;
		}
		if (collection.size() == 1) {
			return collection.iterator().next();
		}
		int index = rnd.nextInt(collection.size());
		T selected = null;
		Iterator<T> iterator = collection.iterator();
		for (int i=0; i<=index; i++) {
			selected = iterator.next();
		}
		return selected;
	}
	
	public String dumpServers() {
		StringBuilder sb = new StringBuilder();
		Iterator<ServerDefinition> iterator = servers.iterator();
		while (iterator.hasNext()) {
			ServerDefinition server = iterator.next();
			sb.append(server.toString());
			if (server == defaultServerDefinition) {
				sb.append(" DEFAULT");
			}
			if (iterator.hasNext()) {
				sb.append("\n");
			}
		}
		return sb.toString();
	}
}
