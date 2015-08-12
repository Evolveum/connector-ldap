/*
 * Copyright (c) 2015 Evolveum
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
	public static final String ATTRIBUTE_OBJECTCLASS_NAME = "objectClass";
	public static final String ATTRIBUTE_ENTRYUUID_NAME = "entryUUID";
	public static final String ATTRIBUTE_NSUNIQUEID_NAME = "nsUniqueId";
	
	public static final String SEARCH_FILTER_ALL = "(objectClass=*)";
	public static final String BOOLEAN_TRUE = "TRUE";
	public static final String BOOLEAN_FALSE = "FALSE";
	
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
    
    public static final String CONNECTION_SECURITY_SSL = "ssl";
    public static final String CONNECTION_SECURITY_STARTTLS = "starttls";
    
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
     * The base DN that the connector will use if the base DN is not specified explicitly.
     */
    private String baseContext;
    
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
    private String passwordAttribute = "userPassword";
    
    /**
     * Hash the passwords with a specified algorithm before they are sent to the server.
     */
    private String passwordHashAlgorithm;
    
    public static final String PASSWORD_HASH_ALGORITHM_NONE = "none";
    
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
     */
    private String vlvSortAttribute = "uid";
    
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
     * Synchronization strategy to detect changes in real time.
     * Possible values: "none", "auto", ... TODO
     * Default value: auto
     */
    private String synchronizationStrategy = SYNCHRONIZATION_STRATEGY_AUTO;
    
    public static final String SYNCHRONIZATION_STRATEGY_NONE = "none";
    public static final String SYNCHRONIZATION_STRATEGY_AUTO = "auto";
    public static final String SYNCHRONIZATION_STRATEGY_SUN_CHANGE_LOG = "sunChangeLog";
    public static final String SYNCHRONIZATION_STRATEGY_MODIFY_TIMESTAMP = "modifyTimestamp";
    
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
    
    // TODO: failover, accountSynchronizationFilter
    // MAYBE TODO: respectResourcePasswordPolicyChangeAfterReset? filterWithOrInsteadOfAnd? 
    //			   removeLogEntryObjectClassFromFilter? synchronizePasswords? passwordAttributeToSynchronize?

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

	public String getBaseContext() {
		return baseContext;
	}

	public void setBaseContext(String baseContext) {
		this.baseContext = baseContext;
	}

	public String getReferralStrategy() {
		return referralStrategy;
	}

	public void setReferralStrategy(String referralStrategy) {
		this.referralStrategy = referralStrategy;
	}

	public String getPasswordAttribute() {
		return passwordAttribute;
	}

	public void setPasswordAttribute(String passwordAttribute) {
		this.passwordAttribute = passwordAttribute;
	}

	public String getPasswordHashAlgorithm() {
		return passwordHashAlgorithm;
	}

	public void setPasswordHashAlgorithm(String passwordHashAlgorithm) {
		this.passwordHashAlgorithm = passwordHashAlgorithm;
	}

	public String getPagingStrategy() {
		return pagingStrategy;
	}

	public void setPagingStrategy(String pagingStrategy) {
		this.pagingStrategy = pagingStrategy;
	}

	public int getPagingBlockSize() {
		return pagingBlockSize;
	}

	public void setPagingBlockSize(int pagingBlockSize) {
		this.pagingBlockSize = pagingBlockSize;
	}

	public String getVlvSortAttribute() {
		return vlvSortAttribute;
	}

	public void setVlvSortAttribute(String vlvSortAttribute) {
		this.vlvSortAttribute = vlvSortAttribute;
	}

	public String getVlvSortOrderingRule() {
		return vlvSortOrderingRule;
	}

	public void setVlvSortOrderingRule(String vlvSortOrderingRule) {
		this.vlvSortOrderingRule = vlvSortOrderingRule;
	}

	public String getUidAttribute() {
		return uidAttribute;
	}

	public void setUidAttribute(String uidAttribute) {
		this.uidAttribute = uidAttribute;
	}

	public String[] getOperationalAttributes() {
		return operationalAttributes;
	}

	public void setOperationalAttributes(String[] operationalAttributes) {
		this.operationalAttributes = operationalAttributes;
	}

	public boolean isReadSchema() {
		return readSchema;
	}

	public void setReadSchema(boolean readSchema) {
		this.readSchema = readSchema;
	}

	public boolean isSchemaQuirksMode() {
		return schemaQuirksMode;
	}

	public void setSchemaQuirksMode(boolean schemaQuirksMode) {
		this.schemaQuirksMode = schemaQuirksMode;
	}

	public String getSynchronizationStrategy() {
		return synchronizationStrategy;
	}

	public void setSynchronizationStrategy(String synchronizationStrategy) {
		this.synchronizationStrategy = synchronizationStrategy;
	}

	public String[] getBaseContextsToSynchronize() {
		return baseContextsToSynchronize;
	}

	public void setBaseContextsToSynchronize(String[] baseContextsToSynchronize) {
		this.baseContextsToSynchronize = baseContextsToSynchronize;
	}

	public String[] getObjectClassesToSynchronize() {
		return objectClassesToSynchronize;
	}

	public void setObjectClassesToSynchronize(String[] objectClassesToSynchronize) {
		this.objectClassesToSynchronize = objectClassesToSynchronize;
	}

	public String[] getAttributesToSynchronize() {
		return attributesToSynchronize;
	}

	public void setAttributesToSynchronize(String[] attributesToSynchronize) {
		this.attributesToSynchronize = attributesToSynchronize;
	}

	public String[] getModifiersNamesToFilterOut() {
		return modifiersNamesToFilterOut;
	}

	public void setModifiersNamesToFilterOut(String[] modifiersNamesToFilterOut) {
		this.modifiersNamesToFilterOut = modifiersNamesToFilterOut;
	}

	public int getChangeLogBlockSize() {
		return changeLogBlockSize;
	}

	public void setChangeLogBlockSize(int changeLogBlockSize) {
		this.changeLogBlockSize = changeLogBlockSize;
	}

	public String getChangeNumberAttribute() {
		return changeNumberAttribute;
	}

	public void setChangeNumberAttribute(String changeNumberAttribute) {
		this.changeNumberAttribute = changeNumberAttribute;
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
    
    public abstract void recompute();
    
    // TODO: equals, hashCode
}