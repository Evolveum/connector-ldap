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
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.entry.Entry;
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
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;

import com.evolveum.polygon.common.GuardedStringAccessor;

/**
 * @author Radovan Semancik
 *
 */
public class ConnectionManager<C extends AbstractLdapConfiguration> implements Closeable {
	
	private static final Log LOG = Log.getLog(ConnectionManager.class);
	private static final Random rnd = new Random();
	
	private C configuration;
	private LdapNetworkConnection defaultConnection = null;
	private Map<String, LdapNetworkConnection> connectionMap = new HashMap<>();
	private ConnectorBinaryAttributeDetector<C> binaryAttributeDetector = new ConnectorBinaryAttributeDetector<C>();

	public ConnectionManager(C configuration) {
		this.configuration = configuration;
	}

	public LdapNetworkConnection getDefaultConnection() {
		if (defaultConnection == null) {
			connect();
		}
		return defaultConnection;
	}
	
	public LdapNetworkConnection getConnection(Dn base) {
		// TODO: Choose connection based on configuration
		return defaultConnection;
	}
	
	public LdapNetworkConnection getConnection(Dn base, Referral referral) {
		Collection<String> ldapUrls = referral.getLdapUrls();
		if (ldapUrls == null || ldapUrls.isEmpty()) {
			return null;
		}
		// Choose URL randomly
		int index = rnd.nextInt(ldapUrls.size());
		String urlString = null;
		Iterator<String> iterator = ldapUrls.iterator();
		for (int i=0; i<index; i++) {
			urlString = iterator.next();
		}
		LdapUrl ldapUrl;
		try {
			ldapUrl = new LdapUrl(urlString);
		} catch (LdapURLEncodingException e) {
			throw new IllegalArgumentException("Wrong LDAP URL '"+urlString+"': "+e.getMessage());
		}
		return getConnection(base, ldapUrl);
	}
	
	public LdapNetworkConnection getConnection(Dn base, LdapUrl url) {
		String connectionMapKey = createConnectionMapKey(url);
		LdapNetworkConnection connection = connectionMap.get(connectionMapKey);
		if (connection == null || !connection.isConnected()) {
			LdapConnectionConfig connectionConfig = createLdapConnectionConfig(url);
			connection = connectConnection(connectionConfig);
			connectionMap.put(connectionMapKey, connection);
		}
		return connection;
	}

	
	private String createConnectionMapKey(LdapUrl url) {
		StringBuilder sb = new StringBuilder();
		sb.append(url.getScheme().toLowerCase());
		sb.append(url.getHost().toLowerCase());
		sb.append(":");
		
		int defaultPort = 389;
    	if (LdapUrl.LDAPS_SCHEME.equals(url.getScheme())) {
    		defaultPort = 636;
		}    	
		if (url.getPort() < 0) {
			sb.append(defaultPort);
		} else {
			sb.append(url.getPort());
		}
		
		return sb.toString();
	}

	public ConnectorBinaryAttributeDetector<C> getBinaryAttributeDetector() {
		return binaryAttributeDetector;
	}

	public boolean isConnected() {
		return defaultConnection != null && defaultConnection.isConnected();
	}
	
	@Override
	public void close() throws IOException {
		// Make sure that we attempt to close all connection even if there are some exceptions during the close.
		IOException exception = null;
		for (java.util.Map.Entry<String, LdapNetworkConnection> entry: connectionMap.entrySet()) {
			try {
				closeConnection(entry.getKey(), entry.getValue());
			} catch (IOException e) {
				LOG.error("Error closing conection {0}: {1}", entry.getKey(), e.getMessage(), e);
				exception = e;
			}
		}
		try {
			closeConnection("default", defaultConnection);
		} catch (IOException e) {
			LOG.error("Error closing default conection: {1}", e.getMessage(), e);
			throw e;
		}
		if (exception != null) {
			throw exception;
		}
	}
	
	private void closeConnection(String key, LdapNetworkConnection connection) throws IOException {
		if (connection != null || connection.isConnected()) {
			LOG.ok("Closing connection {0}", key);
			connection.close();
		}else {
			LOG.ok("Not closing connection {0} because it is not connected", key);
		}
	}
	
	public void connect() {
		// Open just default connection. Other connections are opened on demand.
		final LdapConnectionConfig connectionConfig = createDefaultLdapConnectionConfig();
    	defaultConnection = connectConnection(connectionConfig);
    }
	
	private LdapNetworkConnection connectConnection(LdapConnectionConfig connectionConfig) {
		LOG.ok("Creating connection object");
		LdapNetworkConnection connection = new LdapNetworkConnection(connectionConfig);
		try {
			LOG.info("Connecting to {0}:{1} as {2}", configuration.getHost(), configuration.getPort(), configuration.getBindDn());
			if (LOG.isOk()) {
				String connectionSecurity = "none";
				if (connectionConfig.isUseSsl()) {
					connectionSecurity = "ssl";
				} else if (connectionConfig.isUseTls()) {
					connectionSecurity = "tls";
				}
				LOG.ok("Connection security: {0} (sslProtocol={1}, enabledSecurityProtocols={2}, enabledCipherSuites={3}",
						connectionSecurity, connectionConfig.getEnabledProtocols(), connectionConfig.getEnabledCipherSuites());
			}
			boolean connected = connection.connect();
			LOG.ok("Connected ({0})", connected);
			if (!connected) {
				throw new ConnectionFailedException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
			}
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort(), e);
		}

		bind(connection);
		
		return connection;
	}
	
	private LdapConnectionConfig createDefaultLdapConnectionConfig() {
    	final LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
    	connectionConfig.setLdapHost(configuration.getHost());
    	connectionConfig.setLdapPort(configuration.getPort());
    	connectionConfig.setTimeout(configuration.getConnectTimeout());
    	
    	String connectionSecurity = configuration.getConnectionSecurity();
    	if (connectionSecurity == null || LdapConfiguration.CONNECTION_SECURITY_NONE.equals(connectionSecurity)) {
    		// Nothing to do
    	} else if (LdapConfiguration.CONNECTION_SECURITY_SSL.equals(connectionSecurity)) {
    		connectionConfig.setUseSsl(true);
    	} else if (LdapConfiguration.CONNECTION_SECURITY_STARTTLS.equals(connectionSecurity)) {
    		connectionConfig.setUseTls(true);
    	} else {
    		throw new ConfigurationException("Unknown value for connectionSecurity: "+connectionSecurity);
    	}
    	
    	setSsLTlsConfig(connectionConfig);
    	
    	setCommonConfig(connectionConfig);

		return connectionConfig;
	}

	private LdapConnectionConfig createLdapConnectionConfig(LdapUrl url) {
    	final LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
    	
    	int defaultPort = 389;
    	if (LdapUrl.LDAPS_SCHEME.equals(url.getScheme())) {
    		defaultPort = 636;
			connectionConfig.setUseSsl(true);
			setSsLTlsConfig(connectionConfig);
		}
    	
    	if (StringUtils.isBlank(url.getHost())) {
    		connectionConfig.setLdapHost(configuration.getHost());
    		connectionConfig.setLdapPort(configuration.getPort());
    	} else { 
    		connectionConfig.setLdapHost(url.getHost());
    		if (url.getPort() < 0) {
    			connectionConfig.setLdapPort(defaultPort);
    		} else {
    			connectionConfig.setLdapPort(url.getPort());
    		}
    	}
    	
    	setCommonConfig(connectionConfig);
    	
    	return connectionConfig;
	}
	
	private void setSsLTlsConfig(LdapConnectionConfig connectionConfig) {
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
	}
	
	private void setCommonConfig(LdapConnectionConfig connectionConfig) {
		connectionConfig.setBinaryAttributeDetector(binaryAttributeDetector);
	}
	
	
	private void bind(LdapNetworkConnection connection) {
		final BindRequest bindRequest = new BindRequestImpl();
		String bindDn = configuration.getBindDn();
		try {
			bindRequest.setDn(new Dn(bindDn));
		} catch (LdapInvalidDnException e) {
			throw new ConfigurationException("bindDn is not in DN format: "+e.getMessage(), e);
		}
		
		GuardedString bindPassword = configuration.getBindPassword();
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
			throw LdapUtil.processLdapException("Unable to bind to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" as "+bindDn, e);
		}
		LdapResult ldapResult = bindResponse.getLdapResult();
		if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
			String msg = "Unable to bind to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" as "+bindDn
					+": "+ldapResult.getResultCode().getMessage()+": "+ldapResult.getDiagnosticMessage()+" ("
					+ldapResult.getResultCode().getResultCode()+")";
			throw new ConfigurationException(msg);
		}
		LOG.info("Bound to {0}: {1} ({2})", bindDn, ldapResult.getDiagnosticMessage(), ldapResult.getResultCode());
	}
    	
	public boolean isAlive() {
		if (defaultConnection == null) {
			return false;
		}
		if (!defaultConnection.isConnected()) {
			return false;
		}
		// TODO: try some NOOP operation
		return true;
	}

}
