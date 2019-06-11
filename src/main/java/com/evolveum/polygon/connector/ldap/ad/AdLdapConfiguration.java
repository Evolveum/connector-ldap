/*
 * Copyright (c) 2015-2019 Evolveum
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

package com.evolveum.polygon.connector.ldap.ad;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.ConfigurationProperty;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;

/**
 * Active Directory LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class AdLdapConfiguration extends AbstractLdapConfiguration {
	
	private static final Log LOG = Log.getLog(AdLdapConfiguration.class);

	
	
	/**
	 * Execution of PowerShell using a single WinRM (WS-MAN) command.
	 */
	public static final String SCRIPT_LANGUAGE_POWERSHELL = "powershell";
	
	/**
	 * Execution of single WinRM (WS-MAN) command (using default shell: cmd.exe).
	 */
	public static final String SCRIPT_LANGUAGE_CMD = "cmd";
	
	/**
	 * Long-running PowerShell using the PowerHell loop (no special initialization).
	 */
	public static final String SCRIPT_LANGUAGE_POWERHELL = "powerhell";

	/**
	 * Long-running PowerShell initialized with Exchange snap-ins using the PowerHell loop.
	 */
	public static final String SCRIPT_LANGUAGE_EXCHANGE = "exchange";
    
	/**
	 * Object class to use for user accounts. Default: user
	 */
    private String userObjectClass = "user";
    
    /**
     * Object class to use for user accounts. Default: group
     */
    private String groupObjectClass = "group";
    
    /**
     * Group member attribute name. Default: member
     */
    private String groupObjectMemberAttribute = "member";
    
    /**
     * Specification of global catalog servers. If left empty then the
     * connector will try to determine the host and port automatically.
     * The definition has the same format as "servers" definition.
     */
    private String[] globalCatalogServers;
    
    /**
     * Strategy of global catalog usage.
     */
    private String globalCatalogStrategy = GLOBAL_CATALOG_STRATEGY_NONE;
    
    /**
     * Do not use global catalog explicitly. The global catalog will only
     * be used when following the referrals.
     */
    public static final String GLOBAL_CATALOG_STRATEGY_NONE = "none";
    
    /**
     * The global catalog will be used to resolve DNs. Other entry data from
     * global catalog will be ignored. Explicit read to an authoritative server
     * will be used to retrieve the data.
     */
    public static final String GLOBAL_CATALOG_STRATEGY_RESOLVE = "resolve";
    
    /**
     * The global catalog will be used to resolve DNs. Only the attributes
     * that are stored in global catalog will be returned when object is
     * retrieved. This provides incomplete data, but it avoids additional
     * round-trip to an authoritative server.
     */
    public static final String GLOBAL_CATALOG_STRATEGY_READ = "read";
    
    /**
     * If set to true then the connector will try to search all defined
     * servers for an entry if all other attempts fail.
     */
    private boolean allowBruteForceSearch = false;
    
    /**
     * If set to false then the connector will interpret the content of
     * userAccountControl attribute and will decompose it to pseudo-attributes
     * for enabled state, lockout, etc.
     * If set to true then the connector will NOT do any interpretation and
     * the userAccountControl will be exposed as a simple attribute.
     */
    private boolean rawUserAccountControlAttribute = false;
    
    /**
     * If set to true, then the connector will use native AD schema definition.
     * If set to false, connector will use LDAP-like schema definition exposed by the AD server.
     * Default value: false
     * EXPERIMENTAL. There may be subtle differences between LDAP schema and AD schema. Not completely tested yet.
     */
    private boolean nativeAdSchema = false;
    
    /**
     * Extend the declared AD schema with tweaks that allow practical usage of the schema.
     * AD will generally allow any attribute to be set to any object regardless for the schema.
     * This is often used is practice. E.g. declared AD schema for users and groups does not
     * include samAccountName attribute. But that attribute is needed for users and groups to
     * work correctly. If this configuration property is set to true (which is the default) then
     * the connector will artificially add these attributes to the schema.
     */
    private boolean tweakSchema = true;
    
    /**
     * Enables inclusion of explicit object category filter in all searches. Normally the connector would
     * derive search filter only based on the attributes specified in the query. E.g. (&(uid=foo)(cn=bar)).
     * If includeObjectClassFilter is set to true, then also explicit filter for objectClass and objectCategory
     * will be included.
     * E.g (&(objectClass=inetOrgPerson)(objectCategory=CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com)(uid=foo)(cn=bar))
     * Only works if includeObjectClassFilter is enabled and native AD schema is used.
     * Default value: false.
     * EXPERIMENTAL. Not completely tested yet.
     */
    private boolean includeObjectCategoryFilter = false;
    
    /**
     * If set to true then the connector will automatically add default object category to all created objects.
     * Object category is automatically determined from schema. Only works if native AD schema is enabled.
     * Default value: false.
     * EXPERIMENTAL. Not completely tested yet.
     */
    private boolean addDefaultObjectCategory = false;
    
    /**
     * If set to true then the connector will force password change at next log-on
     * every time when the password is changed. If set to false (default) the password
     * change at next log-on will not be forced. 
     */
    private boolean forcePasswordChangeAtNextLogon = false;
    
    /**
     * The mechanism that will be used to execute scripts on resource.
     * The default WinRM mechanism will execute the script by using
     * WinRM client built into the connector. Local strategy means execution
     * on the local machine where the connector is deployed.
     * Possible values: "winrm", "local".
     * Default value: "winrm"
     */
    private String scriptExecutionMechanism = null;
    
    public static final String SCRIPT_EXECUTION_MECHANISM_WINRM = "winrm";
    public static final String SCRIPT_EXECUTION_MECHANISM_LOCAL = "local";
    // The "winrs" and "invoke-command" mechanisms may come later.
    
    /**
     * Hostname of the WinRM server. If not set the ordinary host will be used.
     */
    private String winRmHost = null;
    
    /**
     * Username used for WinRM authentication. If not set the bind DN will be used.
     */
    private String winRmUsername = null;
    
    /**
     * Domain name used for WinRM authentication.
     */
    private String winRmDomain = null;
    
    /**
     * Password used for WinRM authentication. If not set the bind password will be used.
     */
    private GuardedString winRmPassword = null;
    
    /**
     * WinRM authentication scheme.
     * Possible values: "basic", "ntlm", "credssp".
     * Default value: "ntlm"
     */
    private String winRmAuthenticationScheme = null;
    
    public static final String WINDOWS_AUTHENTICATION_SCHEME_BASIC = "basic";
    public static final String WINDOWS_AUTHENTICATION_SCHEME_NTLM = "ntlm";
    public static final String WINDOWS_AUTHENTICATION_SCHEME_CREDSSP = "credssp";
    
    /**
     * Port number of the WinRM service.
     */
    private int winRmPort = 5985;
    
    /**
     * If set to true then the WinRM client will use HTTPS. Otherwise HTTP will be used.
     */
    private boolean winRmUseHttps = false;
    
    /**
     * Style of argument processing when invoking powesrhell scripts. If set to 'dashed' (default), then
     * the arguments will be appended to the command in the -arg1 val1 -arg2 val2 form. If set to 'variables'
     * then the arguments will be placed in powershell variables before the command is executed.
     */
    private String powershellArgumentStyle = ARGUMENT_STYLE_DASHED;
    
    public static final String ARGUMENT_STYLE_DASHED = "dashed";
    public static final String ARGUMENT_STYLE_SLASHED = "slashed";
    public static final String ARGUMENT_STYLE_VARIABLES = "variables";
    
    @ConfigurationProperty(order = 100)
	public String getUserObjectClass() {
		return userObjectClass;
	}

	public void setUserObjectClass(String userObjectClass) {
		this.userObjectClass = userObjectClass;
	}

	@ConfigurationProperty(order = 101)
	public String getGroupObjectClass() {
		return groupObjectClass;
	}

	public void setGroupObjectClass(String groupObjectClass) {
		this.groupObjectClass = groupObjectClass;
	}

	@ConfigurationProperty(order = 102)
	public String getGroupObjectMemberAttribute() {
		return groupObjectMemberAttribute;
	}

	public void setGroupObjectMemberAttribute(String groupObjectMemberAttribute) {
		this.groupObjectMemberAttribute = groupObjectMemberAttribute;
	}

	@ConfigurationProperty(order = 103)
	public String[] getGlobalCatalogServers() {
		return globalCatalogServers;
	}

	public void setGlobalCatalogServers(String[] globalCatalogServers) {
		this.globalCatalogServers = globalCatalogServers;
	}

	@ConfigurationProperty(order = 104)
	public String getGlobalCatalogStrategy() {
		return globalCatalogStrategy;
	}

	public void setGlobalCatalogStrategy(String globalCatalogStrategy) {
		this.globalCatalogStrategy = globalCatalogStrategy;
	}

	@ConfigurationProperty(order = 105)
	public boolean isAllowBruteForceSearch() {
		return allowBruteForceSearch;
	}

	public void setAllowBruteForceSearch(boolean allowBruteForceSearch) {
		this.allowBruteForceSearch = allowBruteForceSearch;
	}

	@ConfigurationProperty(order = 106)
	public boolean isRawUserAccountControlAttribute() {
		return rawUserAccountControlAttribute;
	}

	public void setRawUserAccountControlAttribute(boolean rawUserAccountControlAttribute) {
		this.rawUserAccountControlAttribute = rawUserAccountControlAttribute;
	}
	
	@ConfigurationProperty(order = 107)
	public boolean isNativeAdSchema() {
		return nativeAdSchema;
	}

	public void setNativeAdSchema(boolean nativeAdSchema) {
		this.nativeAdSchema = nativeAdSchema;
	}

	@ConfigurationProperty(order = 108)
	public boolean isTweakSchema() {
		return tweakSchema;
	}

	public void setTweakSchema(boolean tweakSchema) {
		this.tweakSchema = tweakSchema;
	}
	
	@ConfigurationProperty(order = 109)
	public boolean isIncludeObjectCategoryFilter() {
		return includeObjectCategoryFilter;
	}

	public void setIncludeObjectCategoryFilter(boolean includeObjectCategoryFilter) {
		this.includeObjectCategoryFilter = includeObjectCategoryFilter;
	}
	
	@ConfigurationProperty(order = 110)
	public boolean isAddDefaultObjectCategory() {
		return addDefaultObjectCategory;
	}

	public void setAddDefaultObjectCategory(boolean addDefaultObjectCategory) {
		this.addDefaultObjectCategory = addDefaultObjectCategory;
	}

	@ConfigurationProperty(order = 111)
	public boolean isForcePasswordChangeAtNextLogon() {
		return forcePasswordChangeAtNextLogon;
	}

	public void setForcePasswordChangeAtNextLogon(boolean forcePasswordChangeAtNextLogon) {
		this.forcePasswordChangeAtNextLogon = forcePasswordChangeAtNextLogon;
	}

	@ConfigurationProperty(order = 112)
	public String getScriptExecutionMechanism() {
		return scriptExecutionMechanism;
	}

	public void setScriptExecutionMechanism(String scriptExecitionMechanism) {
		this.scriptExecutionMechanism = scriptExecitionMechanism;
	}

	@ConfigurationProperty(order = 113)
	public String getWinRmHost() {
		return winRmHost;
	}

	public void setWinRmHost(String winRmHost) {
		this.winRmHost = winRmHost;
	}

	@ConfigurationProperty(order = 114)
	public String getWinRmUsername() {
		return winRmUsername;
	}

	public void setWinRmUsername(String winRmUsername) {
		this.winRmUsername = winRmUsername;
	}
	
	@ConfigurationProperty(order = 115)
	public String getWinRmDomain() {
		return winRmDomain;
	}

	public void setWinRmDomain(String winRmDomain) {
		this.winRmDomain = winRmDomain;
	}

	@ConfigurationProperty(order = 116)
	public GuardedString getWinRmPassword() {
		return winRmPassword;
	}

	public void setWinRmPassword(GuardedString winRmPassword) {
		this.winRmPassword = winRmPassword;
	}
	
	@ConfigurationProperty(order = 117)
	public String getWinRmAuthenticationScheme() {
		return winRmAuthenticationScheme;
	}

	public void setWinRmAuthenticationScheme(String winRmAuthenticationScheme) {
		this.winRmAuthenticationScheme = winRmAuthenticationScheme;
	}

	@ConfigurationProperty(order = 118)
	public int getWinRmPort() {
		return winRmPort;
	}

	public void setWinRmPort(int winRmPort) {
		this.winRmPort = winRmPort;
	}

	@ConfigurationProperty(order = 119)
	public boolean isWinRmUseHttps() {
		return winRmUseHttps;
	}

	public void setWinRmUseHttps(boolean winRmUseHttps) {
		this.winRmUseHttps = winRmUseHttps;
	}

	@ConfigurationProperty(order = 120)
	public String getPowershellArgumentStyle() {
		return powershellArgumentStyle;
	}

	public void setPowershellArgumentStyle(String powershellArgumentStyle) {
		this.powershellArgumentStyle = powershellArgumentStyle;
	}

	@Override
	public void recompute() {
		if (getPasswordAttribute() == null) {
			setPasswordAttribute(AdConstants.ATTRIBUTE_UNICODE_PWD_NAME);
		}
		if (getUidAttribute() == null) {
			setUidAttribute(AdConstants.ATTRIBUTE_OBJECT_GUID_NAME);
		}
		if (getSynchronizationStrategy() == null) {
    		setSynchronizationStrategy(SYNCHRONIZATION_STRATEGY_AD_DIR_SYNC);
    	}
		if (getVlvSortAttribute() == null) {
			setVlvSortAttribute("cn,ou,dc");
		}
		if (globalCatalogServers == null) {
			String gcHost;
			String host = getHost();
			int dotIndex = host.indexOf('.');
			if (dotIndex > 0) {
				String domain = host.substring(dotIndex + 1);
				gcHost = "gc._msdcs."+domain;
			} else {
				gcHost = "gc._msdcs";
			}
			int gcPort = 3268;
			if (CONNECTION_SECURITY_SSL.equals(getConnectionSecurity())) {
				gcPort = 3269;
			}
			String configLine = "host=" + gcHost +"; port=" + gcPort;
			LOG.ok("Automatically determined global catalog configuration: {0}", configLine);
			globalCatalogServers = new String[] { configLine };
		}
		if (WINDOWS_AUTHENTICATION_SCHEME_CREDSSP.equals(winRmAuthenticationScheme) &&
				winRmDomain == null) {
			throw new ConfigurationException("Domain name is required if CredSSP is used");
		}
		super.recompute();
	}
    

}