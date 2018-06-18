/*
 * Copyright (c) 2015-2017 Evolveum
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

import static org.identityconnectors.common.StringUtil.isBlank;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public abstract class AbstractLdapConfiguration extends AbstractConfiguration {

    private static final Log LOG = Log.getLog(AbstractLdapConfiguration.class);
    
    public static final int DEFAULT_PORT = 389;

	public static final String SCOPE_SUB = "sub";
	public static final String SCOPE_ONE = "one";
	public static final String SCOPE_BASE = "base";

	public static final String PSEUDO_ATTRIBUTE_DN_NAME = "dn";
	public static final String SEARCH_FILTER_ALL = "(objectClass=*)";
	public static final String BOOLEAN_TRUE = "TRUE";
	public static final String BOOLEAN_FALSE = "FALSE";
	
	public static final String OBJECTCLASS_TOP_NAME = "top";
	
    /**
     * The LDAP server hostname.
     */
    private String host;
    
    /**
     * The LDAP server port.
     */
    private int port = DEFAULT_PORT;
    
    /**
     * What connection security to use.
     * Possible values: null, "ssl", "starttls".
     * Default value: null
     */
    private String connectionSecurity;
    
    public static final String CONNECTION_SECURITY_NONE = "none";
    public static final String CONNECTION_SECURITY_SSL = "ssl";
    public static final String CONNECTION_SECURITY_STARTTLS = "starttls";
    
    /**
     * The standard name of the SSL protocol.
     * This name is used to instantiate javax.net.ssl.SSLContext.
     * See the SSLContext section in the Java Cryptography Architecture Standard Algorithm Name Documentation.
     * E.g. SSL, SSLv2, SSLv3, TLS, TLSv1, TLSv1.1, TLSv1.2
     */
    private String sslProtocol = null;
    
    /**
     * Set of security protocols that are acceptable for protocol negotiation.
     * This name is used to set up SSLEngine.
     * See the SSLContext section in the Java Cryptography Architecture Standard Algorithm Name Documentation.
     * E.g. SSL, SSLv2, SSLv3, TLS, TLSv1, TLSv1.1, TLSv1.2
     */
    private String[] enabledSecurityProtocols = null;
    
    private String[] enabledCipherSuites = null;
    
    /**
     * The authentication mechanism to use.
     * Possible values: "simple", "SASL-GSSAPI"
     * Default value: "simple"
     */
    private String authenticationType = "simple";
    
    /**
     * The DN of the object to bind to.
     */
    private String bindDn;

    /**
     * Bind password.
     */
    private GuardedString bindPassword;
    
    /**
     * Timeout to connect (in milliseconds)
     */
    private long connectTimeout = 10000;
    
    /**
     * Maximum number of attempts to retrieve the entry or to re-try the operation.
     * This number is applicable in replicated topology when handling connection failures
     * and re-trying on another server, when following referrals and in similar situations.
     */
    private int maximumNumberOfAttempts = 10;
    
    /**
     * The base DN that the connector will use if the base DN is not specified explicitly.
     */
    private String baseContext;
    
    /**
     * Structured definition of a server in the directory topology.
     * It contains attribute-value pairs that define each individual server.
     * The names of configuration properties can be used, separated by equal
     * signs and semicolons, such as this:
     * 
     * baseContext=dc=sub,dc=example,dc=com; host=sub.example.com; port=389
     * 
     * The server will be selected for each operation according to the baseContext
     * that is specified in server definition. The most specific DN match will
     * be used. If there are more multiple servers specified for the same
     * baseContext then one of them will be selected randomly. The server
     * which does not specify any baseContext is considered to be the default
     * and that server will be used if the DN cannot be matched. This is equivalent
     * to the server which is specified by ordinary configuration properties.
     * 
     *  The configuration properties that are not explicitly specified in the
     *  server configuration line are taken from the ordinary configuration.
     */
    private String[] servers;
    
    /**
     * The referral handling strategy.
     * Possible values: "follow", "ignore" or "throw".
     * Default value: "follow"
     */
    private String referralStrategy = REFERRAL_STRATEGY_FOLLOW;
    
    public static final String REFERRAL_STRATEGY_FOLLOW = "follow";
    public static final String REFERRAL_STRATEGY_IGNORE = "ignore";
    public static final String REFERRAL_STRATEGY_THROW = "throw";
    
    /**
     * The name of the attribute which contains the password.
     */
    private String passwordAttribute = null;
    
    /**
     * Hash the passwords with a specified algorithm before they are sent to the server.
     */
    private String passwordHashAlgorithm;
    
    public static final String PASSWORD_HASH_ALGORITHM_NONE = "none";
    
    /**
     * Strategy for reading the password. LDAP schema itself cannot reliably indicate whether
     * a password is readable or not. Therefore there this can be configured. Possible values:
     * "unreadable":     Password is not readable, it is never returned by the connector.
     *                   This is the default.
     * "incompleteRead": If password is returned by the LDAP server then connector will
     *                   remove the value. Connector will indicate that the value is
     *                   incomplete. Therefore IDM system can learn that there is
     *                   password without knowing the password value.
     * "readable":       If password is returned by the LDAP server then it is passed
     *                   to the IDM system in the same form as it was returned.
     */
    private String passwordReadStrategy = PASSWORD_READ_STRATEGY_UNREADABLE;
    
    public static final String PASSWORD_READ_STRATEGY_UNREADABLE = "unreadable";
    public static final String PASSWORD_READ_STRATEGY_INCOMPLETE_READ = "incompleteRead";
    public static final String PASSWORD_READ_STRATEGY_READABLE = "readable";
    
    /**
     * Specifies strategy of using paging mechanisms such as VLV or Simple Paged Results.
     * Possible values: "none", "auto", "spr", "vlv"
     * Default value: "auto"
     */
    private String pagingStrategy = null;

    public static final String PAGING_STRATEGY_NONE = "none";
    public static final String PAGING_STRATEGY_AUTO = "auto";
    public static final String PAGING_STRATEGY_SPR = "spr";
    public static final String PAGING_STRATEGY_VLV = "vlv";
    
    /**
     * Number of entries in one "page" when paging is used.
     */
    private int pagingBlockSize = 100;
    
    /**
     * The attribute used for sorting for the VLV searches if no explicit sorting attribute was specified.
     * It may also contain a comma-separated list of attribute names. The first attribute that is found
     * in the applicable object class definition will be used for sorting.
     */
    private String vlvSortAttribute = null;
    
    /**
     * The ordering rule for VLV searches if no other ordering was specified.
     */
    private String vlvSortOrderingRule = null;
    
    /**
     * Name of the attribute which will be used as ICF UID.
     */
    private String uidAttribute;
    
    /**
     * Operational attributes that apply to all object classes.
     */
    private String[] operationalAttributes = { };

    /**
     * If set to false then the schema will not be retrieved from the server.
     */
    private boolean readSchema = true;
    
    /**
     * If set to false then the schema parsers will be very strict.
     * If set to true then various "quirks" in the schema will be accepted, such as
     * non-numeric OIDs.
     */
    private boolean schemaQuirksMode = true;
    
    /**
     * Accept also attributes that are not defined in schema.
     * Single-value string is assumed as the attribute type.
     */
    private boolean allowUnknownAttributes = false;
    
    /**
     * Use permissive modify LDAP control for modify operations.
     * Possible values: "never", "auto", "always"
     * Default value: auto
     */
    private String usePermissiveModify = USE_PERMISSIVE_MODIFY_AUTO;

    public static final String USE_PERMISSIVE_MODIFY_NEVER = "never";
    public static final String USE_PERMISSIVE_MODIFY_AUTO = "auto";
    public static final String USE_PERMISSIVE_MODIFY_ALWAYS = "always";
    		
    /**
     * Synchronization strategy to detect changes in real time.
     * Possible values: "none", "auto", ... TODO
     * Default value: auto
     */
    private String synchronizationStrategy = null;
    
    public static final String SYNCHRONIZATION_STRATEGY_NONE = "none";
    public static final String SYNCHRONIZATION_STRATEGY_AUTO = "auto";
    public static final String SYNCHRONIZATION_STRATEGY_SUN_CHANGE_LOG = "sunChangeLog";
    public static final String SYNCHRONIZATION_STRATEGY_MODIFY_TIMESTAMP = "modifyTimestamp";
    public static final String SYNCHRONIZATION_STRATEGY_AD_DIR_SYNC = "adDirSync";
    
    /**
     * List of base contexts DNs that will be accepted during synchronization.
     * If set to empty then all DNs will be accepted.
     */
    private String[] baseContextsToSynchronize = { };

    /**
     * List of object classes that will be accepted during synchronization.
     * If set to empty then all object classes will be accepted.
     */
    private String[] objectClassesToSynchronize = { };
    
    /**
     * List of attributes that will be passed during synchronization.
     * If set to empty then all non-operational attributes will be passed.
     */
    private String[] attributesToSynchronize = { };

    /**
     * List of modifiers DNs that will NOT be accepted during synchronization.
     */
    private String[] modifiersNamesToFilterOut = { };
    
    /**
     * Number of change log entries to fetch in a single request.
     */
    private int changeLogBlockSize = 100;

    /**
     * "Change number" attribute - unique indentifier of the change in the change log.
     */
    private String changeNumberAttribute = "changeNumber";
    
    /**
     * Entry DN can be provided to the connector as a "name hint". Connector will use the name hint whenever
     * it can use it safely. But there are some cases when the name hint cannot be used safely. There are
     * mostly modify and delete operations when in a rare case a wrong object can be modified or deleted.
     * The connector will not use the name hint in these cases by default. It will make explicit search
     * to make sure that everything is fair and square before attempting the operation. However this comes
     * at the expense of performance. If this switch is set to true then the connector will try to use
     * the name hint even if it is not completely safe. This may mean significant perfomacne boost for
     * modify and delete operations.
     */
    private boolean useUnsafeNameHint = false;

    /**
     * Enable extra tests during the test connection operations.
     * Those tests may take longer and they may make more LDAP requests.
     * These tests try to test some tricky situations and border conditions
     * and they are generally useful only for connector developers or when
     * diagnosing connector bugs. 
     */
    private boolean enableExtraTests = false;
    
    /**
     * Timestamp presentation mode. This controls the way how connector presents the timestamps
     * to the client. It can present them in native framework format (which is the default). 
     * Or it can present them as unix epoch (number of seconds since 1970) or the
     * timestamps can be presented in LDAP-native string form (ISO 8601). Unix epoch and
     * string representation are provided mostly for compatibility reasons.
     * Possible values: "native", "unixEpoch", "string"
     * Default value: native
     */
    private String timestampPresentation = TIMESTAMP_PRESENTATION_NATIVE;

    public static final String TIMESTAMP_PRESENTATION_NATIVE = "native";
    public static final String TIMESTAMP_PRESENTATION_UNIX_EPOCH = "unixEpoch";
    public static final String TIMESTAMP_PRESENTATION_STRING = "string";
    
    /**
     * Enables inclusion of explicit object class filter in all searches. Normally the connector would
     * derive search filter only based on the attributes specified in the query. E.g. (&(uid=foo)(cn=bar)).
     * If includeObjectClassFilter is set to true, then also explicit filter for objectclass will be included.
     * E.g (&(objectClass=inetOrgPerson)(uid=foo)(cn=bar))
     */
    private boolean includeObjectClassFilter = false;
    
    /**
     * Enabled more tolerant algorithm to detect which object class is structural and which is auxiliary.
     */
    private boolean alternativeObjectClassDetection = false;

    // TODO: failover, accountSynchronizationFilter
    // MAYBE TODO: respectResourcePasswordPolicyChangeAfterReset? filterWithOrInsteadOfAnd? 
    //			   removeLogEntryObjectClassFromFilter? synchronizePasswords? passwordAttributeToSynchronize?

	@ConfigurationProperty(required = true, order = 1)
    public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	@ConfigurationProperty(order = 2)
	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	@ConfigurationProperty(order = 3)
	public String getConnectionSecurity() {
		return connectionSecurity;
	}

	public void setConnectionSecurity(String connectionSecurity) {
		this.connectionSecurity = connectionSecurity;
	}

	@ConfigurationProperty(order = 4)
	public String getSslProtocol() {
		return sslProtocol;
	}

	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}

	@ConfigurationProperty(order = 5)
	public String[] getEnabledSecurityProtocols() {
		return enabledSecurityProtocols;
	}

	public void setEnabledSecurityProtocols(String[] enabledSecurityProtocols) {
		this.enabledSecurityProtocols = enabledSecurityProtocols;
	}

	@ConfigurationProperty(order = 6)
	public String[] getEnabledCipherSuites() {
		return enabledCipherSuites;
	}

	public void setEnabledCipherSuites(String[] enabledCipherSuites) {
		this.enabledCipherSuites = enabledCipherSuites;
	}

	@ConfigurationProperty(order = 7)
	public String getAuthenticationType() {
		return authenticationType;
	}

	public void setAuthenticationType(String authenticationType) {
		this.authenticationType = authenticationType;
	}

	@ConfigurationProperty(order = 8)
	public String getBindDn() {
		return bindDn;
	}

	public void setBindDn(String bindDn) {
		this.bindDn = bindDn;
	}

	@ConfigurationProperty(order = 9)
	public GuardedString getBindPassword() {
		return bindPassword;
	}

	public void setBindPassword(GuardedString bindPassword) {
		this.bindPassword = bindPassword;
	}

	@ConfigurationProperty(order = 10)
	public long getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(long connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	@ConfigurationProperty(order = 11)
	public int getMaximumNumberOfAttempts() {
		return maximumNumberOfAttempts;
	}

	public void setMaximumNumberOfAttempts(int maximumNumberOfAttempts) {
		this.maximumNumberOfAttempts = maximumNumberOfAttempts;
	}

	@ConfigurationProperty(order = 12)
	public String getBaseContext() {
		return baseContext;
	}

	public void setBaseContext(String baseContext) {
		this.baseContext = baseContext;
	}

	@ConfigurationProperty(order = 13)
	public String[] getServers() {
		return servers;
	}

	public void setServers(String[] servers) {
		this.servers = servers;
	}

	@ConfigurationProperty(order = 14)
	public String getReferralStrategy() {
		return referralStrategy;
	}

	public void setReferralStrategy(String referralStrategy) {
		this.referralStrategy = referralStrategy;
	}

	@ConfigurationProperty(order = 15)
	public String getPasswordAttribute() {
		return passwordAttribute;
	}

	public void setPasswordAttribute(String passwordAttribute) {
		this.passwordAttribute = passwordAttribute;
	}

	@ConfigurationProperty(order = 16)
	public String getPasswordHashAlgorithm() {
		return passwordHashAlgorithm;
	}

	public void setPasswordHashAlgorithm(String passwordHashAlgorithm) {
		this.passwordHashAlgorithm = passwordHashAlgorithm;
	}

	@ConfigurationProperty(order = 17)
	public String getPasswordReadStrategy() {
		return passwordReadStrategy;
	}

	public void setPasswordReadStrategy(String passwordReadStrategy) {
		this.passwordReadStrategy = passwordReadStrategy;
	}

	@ConfigurationProperty(order = 18)
	public String getPagingStrategy() {
		return pagingStrategy;
	}

	public void setPagingStrategy(String pagingStrategy) {
		this.pagingStrategy = pagingStrategy;
	}

	@ConfigurationProperty(order = 19)
	public int getPagingBlockSize() {
		return pagingBlockSize;
	}

	public void setPagingBlockSize(int pagingBlockSize) {
		this.pagingBlockSize = pagingBlockSize;
	}

	@ConfigurationProperty(order = 20)
	public String getVlvSortAttribute() {
		return vlvSortAttribute;
	}

	public void setVlvSortAttribute(String vlvSortAttribute) {
		this.vlvSortAttribute = vlvSortAttribute;
	}

	@ConfigurationProperty(order = 21)
	public String getVlvSortOrderingRule() {
		return vlvSortOrderingRule;
	}

	public void setVlvSortOrderingRule(String vlvSortOrderingRule) {
		this.vlvSortOrderingRule = vlvSortOrderingRule;
	}

	@ConfigurationProperty(order = 22)
	public String getUidAttribute() {
		return uidAttribute;
	}

	public void setUidAttribute(String uidAttribute) {
		this.uidAttribute = uidAttribute;
	}

	@ConfigurationProperty(order = 23)
	public String[] getOperationalAttributes() {
		return operationalAttributes;
	}

	public void setOperationalAttributes(String[] operationalAttributes) {
		this.operationalAttributes = operationalAttributes;
	}

	@ConfigurationProperty(order = 24)
	public boolean isReadSchema() {
		return readSchema;
	}

	public void setReadSchema(boolean readSchema) {
		this.readSchema = readSchema;
	}

	@ConfigurationProperty(order = 25)
	public boolean isSchemaQuirksMode() {
		return schemaQuirksMode;
	}

	public void setSchemaQuirksMode(boolean schemaQuirksMode) {
		this.schemaQuirksMode = schemaQuirksMode;
	}

	@ConfigurationProperty(order = 26)
	public boolean isAllowUnknownAttributes() {
		return allowUnknownAttributes;
	}

	public void setAllowUnknownAttributes(boolean allowUnknownAttributes) {
		this.allowUnknownAttributes = allowUnknownAttributes;
	}

	@ConfigurationProperty(order = 27)
	public String getUsePermissiveModify() {
		return usePermissiveModify;
	}

	public void setUsePermissiveModify(String usePermissiveModify) {
		this.usePermissiveModify = usePermissiveModify;
	}

	@ConfigurationProperty(order = 28)
	public String getSynchronizationStrategy() {
		return synchronizationStrategy;
	}

	public void setSynchronizationStrategy(String synchronizationStrategy) {
		this.synchronizationStrategy = synchronizationStrategy;
	}

	@ConfigurationProperty(order = 29)
	public String[] getBaseContextsToSynchronize() {
		return baseContextsToSynchronize;
	}

	public void setBaseContextsToSynchronize(String[] baseContextsToSynchronize) {
		this.baseContextsToSynchronize = baseContextsToSynchronize;
	}

	@ConfigurationProperty(order = 30)
	public String[] getObjectClassesToSynchronize() {
		return objectClassesToSynchronize;
	}

	public void setObjectClassesToSynchronize(String[] objectClassesToSynchronize) {
		this.objectClassesToSynchronize = objectClassesToSynchronize;
	}

	@ConfigurationProperty(order = 31)
	public String[] getAttributesToSynchronize() {
		return attributesToSynchronize;
	}

	public void setAttributesToSynchronize(String[] attributesToSynchronize) {
		this.attributesToSynchronize = attributesToSynchronize;
	}

	@ConfigurationProperty(order = 32)
	public String[] getModifiersNamesToFilterOut() {
		return modifiersNamesToFilterOut;
	}

	public void setModifiersNamesToFilterOut(String[] modifiersNamesToFilterOut) {
		this.modifiersNamesToFilterOut = modifiersNamesToFilterOut;
	}

	@ConfigurationProperty(order = 33)
	public int getChangeLogBlockSize() {
		return changeLogBlockSize;
	}

	public void setChangeLogBlockSize(int changeLogBlockSize) {
		this.changeLogBlockSize = changeLogBlockSize;
	}

	@ConfigurationProperty(order = 34)
	public String getChangeNumberAttribute() {
		return changeNumberAttribute;
	}

	public void setChangeNumberAttribute(String changeNumberAttribute) {
		this.changeNumberAttribute = changeNumberAttribute;
	}
	
	@ConfigurationProperty(order = 35)
	public boolean isUseUnsafeNameHint() {
		return useUnsafeNameHint;
	}

	public void setUseUnsafeNameHint(boolean useUnsafeNameHint) {
		this.useUnsafeNameHint = useUnsafeNameHint;
	}
	
	@ConfigurationProperty(order = 36)
	public boolean isEnableExtraTests() {
		return enableExtraTests;
	}

	public void setEnableExtraTests(boolean enableExtraTests) {
		this.enableExtraTests = enableExtraTests;
	}

	@ConfigurationProperty(order = 37)
	public String getTimestampPresentation() {
		return timestampPresentation;
	}

	public void setTimestampPresentation(String timestampPresentation) {
		this.timestampPresentation = timestampPresentation;
	}

	@ConfigurationProperty(order = 38)
	public boolean isIncludeObjectClassFilter() {
		return includeObjectClassFilter;
	}

	public void setIncludeObjectClassFilter(boolean includeObjectClassFilter) {
		this.includeObjectClassFilter = includeObjectClassFilter;
	}

	@ConfigurationProperty(order = 39)
	public boolean isAlternativeObjectClassDetection() {
		return alternativeObjectClassDetection;
	}

	public void setAlternativeObjectClassDetection(boolean alternativeObjectClassDetection) {
		this.alternativeObjectClassDetection = alternativeObjectClassDetection;
	}

	@Override
    public void validate() {
    	validateNotBlank(host, "host.blank");
    	if (port < 0 || port > 65535) {
    		throwConfigurationError("port.illegalValue");
        }
    	validateDn(baseContext, "baseContext.invalidDn");
    	
        // TODO
    }
	
	private void validateNotBlank(String value, String errorKey) {
        if (isBlank(value)) {
        	throwConfigurationError(errorKey);
        }
    }
    
    private void validateDn(String value, String errorKey) {
        if (isBlank(value)) {
        	throwConfigurationError(errorKey);
        }
        // TODO
    }
    
    private void throwConfigurationError(String errorKey) {
    	throw new ConfigurationException(getConnectorMessages().format(errorKey, null));
    }
    
    public void recompute() {
    	if (passwordAttribute == null) {
    		passwordAttribute = SchemaConstants.USER_PASSWORD_AT;
    	}
    	if (synchronizationStrategy == null) {
    		synchronizationStrategy = SYNCHRONIZATION_STRATEGY_AUTO;
    	}
    	if (vlvSortAttribute == null) {
    		vlvSortAttribute = SchemaConstants.UID_AT;
    	}
    }
    
    public boolean isReferralStrategyFollow() {
    	return referralStrategy == null || REFERRAL_STRATEGY_FOLLOW.equals(referralStrategy);
    }
    
    public boolean isReferralStrategyIgnore() {
    	return REFERRAL_STRATEGY_IGNORE.equals(referralStrategy);
    }

    public boolean isReferralStrategyThrow() {
    	return REFERRAL_STRATEGY_THROW.equals(referralStrategy);
    }
    
    // TODO: equals, hashCode
}