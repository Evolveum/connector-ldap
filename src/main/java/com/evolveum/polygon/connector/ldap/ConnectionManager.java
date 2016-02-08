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

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
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
	
	private C configuration;
	LdapNetworkConnection defaultConnection = null;
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
		// TODO
		return defaultConnection;
	}

	
	public ConnectorBinaryAttributeDetector<C> getBinaryAttributeDetector() {
		return binaryAttributeDetector;
	}

	public boolean isConnected() {
		return defaultConnection != null && defaultConnection.isConnected();
	}
	
	@Override
	public void close() throws IOException {
		if (defaultConnection != null || defaultConnection.isConnected()) {
			LOG.ok("Closing default connection");
			defaultConnection.close();
		}else {
			LOG.ok("Not closing connection ... because it is not connected");
		}
	}
	
	public void connect() {
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
    	
    	LOG.ok("Creating connection object");
    	defaultConnection = new LdapNetworkConnection(connectionConfig);
		try {
			LOG.info("Connecting to {0}:{1} as {2}", configuration.getHost(), configuration.getPort(), configuration.getBindDn());
			if (LOG.isOk()) {
				LOG.ok("Connection security: {0} (sslProtocol={1}, enabledSecurityProtocols={2}, enabledCipherSuites={3}",
						connectionSecurity, connectionConfig.getEnabledProtocols(), connectionConfig.getEnabledCipherSuites());
			}
			boolean connected = defaultConnection.connect();
			LOG.ok("Connected ({0})", connected);
			if (!connected) {
				throw new ConnectionFailedException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
			}
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort(), e);
		}

		bind();
    }
	
	private void bind() {
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
			bindResponse = defaultConnection.bind(bindRequest);
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
