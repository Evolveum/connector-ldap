/*
 * Copyright (c) 2015-2016 Evolveum
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

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;

/**
 * Active Directory LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class AdLdapConfiguration extends AbstractLdapConfiguration {
	
	private static final Log LOG = Log.getLog(AdLdapConfiguration.class);

	public static final String ATTRIBUTE_OBJECT_GUID_NAME = "objectGUID";
	public static final String ATTRIBUTE_UNICODE_PWD_NAME = "unicodePwd";
    
    private String userObjectClass = "user";
    
    private String groupObjectClass = "group";
    
    private String groupObjectMemberAttribute = "member";
    
    private String userContainerDn;
    
    private String groupContainerDn;
        
    /**
     * Specification of global catalog servers. If left empty then the
     * connector will try to determine the host and port automatically.
     * The definition has the same format as "servers" definition.
     */
    private String[] globalCatalogServers;
    
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
     * If set to false then the connector will interpret the content of
     * userAccountControl attribute and will decompose it to pseudo-attributes
     * for enabled state, lockout, etc.
     * If set to true then the connector will NOT do any interpretation and
     * the userAccountControl will be exposed as a simple attribute.
     */
    private boolean rawUserAccountControlAttribute = false;
        
	public String getUserObjectClass() {
		return userObjectClass;
	}

	public void setUserObjectClass(String userObjectClass) {
		this.userObjectClass = userObjectClass;
	}

	public String getGroupObjectClass() {
		return groupObjectClass;
	}

	public void setGroupObjectClass(String groupObjectClass) {
		this.groupObjectClass = groupObjectClass;
	}

	public String getGroupObjectMemberAttribute() {
		return groupObjectMemberAttribute;
	}

	public void setGroupObjectMemberAttribute(String groupObjectMemberAttribute) {
		this.groupObjectMemberAttribute = groupObjectMemberAttribute;
	}

	public String getUserContainerDn() {
		return userContainerDn;
	}

	public void setUserContainerDn(String userContainerDn) {
		this.userContainerDn = userContainerDn;
	}

	public String getGroupContainerDn() {
		return groupContainerDn;
	}

	public void setGroupContainerDn(String groupContainerDn) {
		this.groupContainerDn = groupContainerDn;
	}

	public String[] getGlobalCatalogServers() {
		return globalCatalogServers;
	}

	public void setGlobalCatalogServers(String[] globalCatalogServers) {
		this.globalCatalogServers = globalCatalogServers;
	}

	public String getGlobalCatalogStrategy() {
		return globalCatalogStrategy;
	}

	public void setGlobalCatalogStrategy(String globalCatalogStrategy) {
		this.globalCatalogStrategy = globalCatalogStrategy;
	}

	public boolean isRawUserAccountControlAttribute() {
		return rawUserAccountControlAttribute;
	}

	public void setRawUserAccountControlAttribute(boolean rawUserAccountControlAttribute) {
		this.rawUserAccountControlAttribute = rawUserAccountControlAttribute;
	}

	@Override
	public void recompute() {
		if (getPasswordAttribute() == null) {
			setPasswordAttribute(ATTRIBUTE_UNICODE_PWD_NAME);
		}
		if (userContainerDn == null) {
			userContainerDn = "CN=Users,"+getBaseContext();
		}
		if (groupContainerDn == null) {
			groupContainerDn = "CN=Users,"+getBaseContext();
		}
		if (getUidAttribute() == null) {
			setUidAttribute(ATTRIBUTE_OBJECT_GUID_NAME);
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
			int dotIndex = host.indexOf(".");
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
		super.recompute();
	}
    

}