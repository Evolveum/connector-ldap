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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;

/**
 * @author semancik
 *
 */
public class ServerDefinition {
	
	private String host;
	private int port;
	private String connectionSecurity;
	private String sslProtocol = null;
	private String[] enabledSecurityProtocols = null;
	private String[] enabledCipherSuites = null;
	private String authenticationType;
	private String bindDn;
	private GuardedString bindPassword;
	private long connectTimeout;
	private Dn baseContext;
	private Origin origin = Origin.CONFIGURATION;
	
	enum Origin {
		CONFIGURATION, REFERRAL;
	}
	
	private LdapNetworkConnection connection;
	
	public static ServerDefinition createDefaultDefinition(AbstractLdapConfiguration configuration) {
		ServerDefinition def = new ServerDefinition();
		def.host = configuration.getHost();
		def.port = configuration.getPort();
		def.connectionSecurity = configuration.getConnectionSecurity();
		def.sslProtocol = configuration.getSslProtocol();
		def.enabledSecurityProtocols = configuration.getEnabledSecurityProtocols();
		def.enabledCipherSuites = configuration.getEnabledCipherSuites();
		def.authenticationType = configuration.getAuthenticationType();
		def.bindDn = configuration.getBindDn();
		def.bindPassword = configuration.getBindPassword();
		def.connectTimeout = configuration.getConnectTimeout();
		try {
			def.baseContext = new Dn(configuration.getBaseContext());
		} catch (LdapInvalidDnException e) {
			throw new ConfigurationException("Wrong DN format in baseContext: "+e.getMessage(), e);
		}
		def.origin = Origin.CONFIGURATION;
		return def;
	}
	
	public static ServerDefinition parse(AbstractLdapConfiguration configuration, String serverConfigLine, int lineNumber) {
		String[] clauses = serverConfigLine.split(";");
		Map<String,String> props = new HashMap<>();
		for (String clause: clauses) {
			clause = clause.trim();
			int indexEq = clause.indexOf('=');
			if (indexEq < 0) {
				throw new ConfigurationException("Wrong format of server configuration line "+lineNumber+": missing equals sign");
			}
			String propName = clause.substring(0, indexEq);
			String propValue = clause.substring(indexEq+1);
			props.put(propName, propValue);
		}
		ServerDefinition def = new ServerDefinition();
		def.host = getStringProp(props, "host", configuration.getHost());
		Integer port = getIntProp(props, "port", configuration.getPort());
		if (port == null) {
			def.port = 389;
		} else {
			def.port = port;
		}
		def.connectionSecurity = getStringProp(props, "connectionSecurity", configuration.getConnectionSecurity());
		def.sslProtocol = getStringProp(props, "sslProtocol", configuration.getSslProtocol());
		def.enabledSecurityProtocols = getStringArrayProp(props, "enabledSecurityProtocols", configuration.getEnabledSecurityProtocols());
		def.enabledCipherSuites = getStringArrayProp(props, "enabledCipherSuites", configuration.getEnabledCipherSuites());
		def.authenticationType = getStringProp(props, "authenticationType", configuration.getAuthenticationType());
		def.bindDn = getStringProp(props, "bindDn", configuration.getBindDn());
		def.bindPassword = getGuardedStringProp(props, "bindPassword", configuration.getBindPassword());
		def.connectTimeout = getLongProp(props, "connectTimeout", configuration.getConnectTimeout());
		try {
			def.baseContext = new Dn(getStringProp(props, "baseContext", configuration.getBaseContext()));
		} catch (LdapInvalidDnException e) {
			throw new ConfigurationException("Wrong DN format in baseContext in server definition (line "+lineNumber+"): "+e.getMessage(), e);
		}
		def.origin = Origin.CONFIGURATION;
		return def;
	}
	
	public static ServerDefinition createDefinition(AbstractLdapConfiguration configuration, LdapUrl url) {
		ServerDefinition def = new ServerDefinition();
		def.host = url.getHost();
		int defaultPort = 389;
		if (LdapUrl.LDAPS_SCHEME.equals(url.getScheme())) {
			defaultPort = 636;
			def.connectionSecurity = AbstractLdapConfiguration.CONNECTION_SECURITY_SSL;
		} else {
			if (AbstractLdapConfiguration.CONNECTION_SECURITY_STARTTLS.equals(configuration.getConnectionSecurity())) {
				def.connectionSecurity = AbstractLdapConfiguration.CONNECTION_SECURITY_STARTTLS;
			} else {
				def.connectionSecurity = AbstractLdapConfiguration.CONNECTION_SECURITY_NONE;
			}
		}
		if (url.getPort() < 0) {
			def.port = defaultPort;
		} else {
			def.port = url.getPort();
		}
		def.sslProtocol = configuration.getSslProtocol();
		def.enabledSecurityProtocols = configuration.getEnabledSecurityProtocols();
		def.enabledCipherSuites = configuration.getEnabledCipherSuites();
		def.authenticationType = configuration.getAuthenticationType();
		def.bindDn = configuration.getBindDn();
		def.bindPassword = configuration.getBindPassword();
		def.connectTimeout = configuration.getConnectTimeout();
		def.baseContext = null;
		def.origin = Origin.REFERRAL;
		return def;
	}

	private static String getStringProp(Map<String, String> props, String key, String defaultVal) {
		String propVal = props.get(key);
		if (propVal == null) {
			return defaultVal;
		} else {
			if (StringUtil.isBlank(propVal)) {
				return null;
			} else {
				return propVal;
			}
		}
	}
	
	private static GuardedString getGuardedStringProp(Map<String, String> props, String key, GuardedString defaultVal) {
		String propVal = props.get(key);
		if (propVal == null) {
			return defaultVal;
		} else {
			if (StringUtil.isBlank(propVal)) {
				return null;
			} else {
				return new GuardedString(propVal.toCharArray());
			}
		}
	}
	
	private static String[] getStringArrayProp(Map<String, String> props, String key, String[] defaultVal) {
		String propVal = props.get(key);
		if (propVal == null) {
			return defaultVal;
		} else {
			if (StringUtil.isBlank(propVal)) {
				return new String[0];
			} else {
				return propVal.split(",");
			}
		}
	}

	private static Integer getIntProp(Map<String, String> props, String key, int defaultVal) {
		String propVal = props.get(key);
		if (propVal == null) {
			return defaultVal;
		} else {
			if (StringUtil.isBlank(propVal)) {
				return null;
			} else {
				return Integer.parseInt(propVal);
			}
		}
	}

	private static Long getLongProp(Map<String, String> props, String key, long defaultVal) {
		String propVal = props.get(key);
		if (propVal == null) {
			return defaultVal;
		} else {
			if (StringUtil.isBlank(propVal)) {
				return null;
			} else {
				return Long.parseLong(propVal);
			}
		}
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getConnectionSecurity() {
		return connectionSecurity;
	}

	public void setConnectionSecurity(String connectionSecurity) {
		this.connectionSecurity = connectionSecurity;
	}

	public String getSslProtocol() {
		return sslProtocol;
	}

	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}

	public String[] getEnabledSecurityProtocols() {
		return enabledSecurityProtocols;
	}

	public void setEnabledSecurityProtocols(String[] enabledSecurityProtocols) {
		this.enabledSecurityProtocols = enabledSecurityProtocols;
	}

	public String[] getEnabledCipherSuites() {
		return enabledCipherSuites;
	}

	public void setEnabledCipherSuites(String[] enabledCipherSuites) {
		this.enabledCipherSuites = enabledCipherSuites;
	}

	public String getAuthenticationType() {
		return authenticationType;
	}

	public void setAuthenticationType(String authenticationType) {
		this.authenticationType = authenticationType;
	}

	public String getBindDn() {
		return bindDn;
	}

	public void setBindDn(String bindDn) {
		this.bindDn = bindDn;
	}

	public GuardedString getBindPassword() {
		return bindPassword;
	}

	public void setBindPassword(GuardedString bindPassword) {
		this.bindPassword = bindPassword;
	}

	public long getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(long connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public Dn getBaseContext() {
		return baseContext;
	}

	public void setBaseContext(Dn baseContext) {
		this.baseContext = baseContext;
	}

	public Origin getOrigin() {
		return origin;
	}

	public void setOrigin(Origin origin) {
		this.origin = origin;
	}

	public LdapNetworkConnection getConnection() {
		return connection;
	}

	public void setConnection(LdapNetworkConnection connection) {
		this.connection = connection;
	}
	
	public boolean isConnected() {
		return connection != null && connection.isConnected();
	}

	public boolean matches(LdapUrl url) {
		if (!url.getHost().equalsIgnoreCase(host)) {
			return false;
		}
		if (url.getPort() != port) {
			return false;
		}
		if (LdapUrl.LDAPS_SCHEME.equals(url.getScheme()) &&
				!connectionSecurity.equals(AbstractLdapConfiguration.CONNECTION_SECURITY_SSL)) {
			return false;
		}
		return true;
	}
	
	public void apply(SchemaManager schemaManager) {
		if (baseContext != null) {
			try {
				baseContext.apply(schemaManager);
			} catch (LdapInvalidDnException e) {
				throw new InvalidAttributeValueException("Invalid DN '"+baseContext+"': "+e.getMessage(), e);
			}
		}
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authenticationType == null) ? 0 : authenticationType.hashCode());
		result = prime * result + ((baseContext == null) ? 0 : baseContext.hashCode());
		result = prime * result + ((bindDn == null) ? 0 : bindDn.hashCode());
		result = prime * result + ((bindPassword == null) ? 0 : bindPassword.hashCode());
		result = prime * result + (int) (connectTimeout ^ (connectTimeout >>> 32));
		result = prime * result + ((connection == null) ? 0 : connection.hashCode());
		result = prime * result + ((connectionSecurity == null) ? 0 : connectionSecurity.hashCode());
		result = prime * result + Arrays.hashCode(enabledCipherSuites);
		result = prime * result + Arrays.hashCode(enabledSecurityProtocols);
		result = prime * result + ((host == null) ? 0 : host.hashCode());
		result = prime * result + port;
		result = prime * result + ((sslProtocol == null) ? 0 : sslProtocol.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ServerDefinition other = (ServerDefinition) obj;
		if (authenticationType == null) {
			if (other.authenticationType != null) {
				return false;
			}
		} else if (!authenticationType.equals(other.authenticationType)) {
			return false;
		}
		if (baseContext == null) {
			if (other.baseContext != null) {
				return false;
			}
		} else if (!baseContext.equals(other.baseContext)) {
			return false;
		}
		if (bindDn == null) {
			if (other.bindDn != null) {
				return false;
			}
		} else if (!bindDn.equals(other.bindDn)) {
			return false;
		}
		if (bindPassword == null) {
			if (other.bindPassword != null) {
				return false;
			}
		} else if (!bindPassword.equals(other.bindPassword)) {
			return false;
		}
		if (connectTimeout != other.connectTimeout) {
			return false;
		}
		if (connection == null) {
			if (other.connection != null) {
				return false;
			}
		} else if (!connection.equals(other.connection)) {
			return false;
		}
		if (connectionSecurity == null) {
			if (other.connectionSecurity != null) {
				return false;
			}
		} else if (!connectionSecurity.equals(other.connectionSecurity)) {
			return false;
		}
		if (!Arrays.equals(enabledCipherSuites, other.enabledCipherSuites)) {
			return false;
		}
		if (!Arrays.equals(enabledSecurityProtocols, other.enabledSecurityProtocols)) {
			return false;
		}
		if (host == null) {
			if (other.host != null) {
				return false;
			}
		} else if (!host.equals(other.host)) {
			return false;
		}
		if (port != other.port) {
			return false;
		}
		if (sslProtocol == null) {
			if (other.sslProtocol != null) {
				return false;
			}
		} else if (!sslProtocol.equals(other.sslProtocol)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "ServerDefinition(host=" + host + ", port=" + port + ", connectionSecurity="
				+ connectionSecurity + ", bindDn=" + bindDn + ", baseContext=" + baseContext + ", origin=" + origin 
				+ ", connection=" + getConnectionStatusString(connection) + ")";
	}

	private String getConnectionStatusString(LdapNetworkConnection conn) {
		if (conn == null) {
			return null;
		}
		if (conn.isConnected()) {
			return "connected";
		} else {
			return "disconnected";
		}
	}
	
}
