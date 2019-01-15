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

package com.evolveum.polygon.connector.ldap;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class LdapConfiguration extends AbstractLdapConfiguration {

	private static final Log LOG = Log.getLog(LdapConfiguration.class);
	
	/**
     * Specifies strategy of handling account lockouts.
     * Please note that the "openldap" lockout strategy is EXPERIMENTAL.
     * Possible values: "none", "openldap"
     * Default value: "none"
     */
    private String lockoutStrategy = LOCKOUT_STRATEGY_NONE;
    
    public static final String LOCKOUT_STRATEGY_NONE = "none";
    public static final String LOCKOUT_STRATEGY_OPENLDAP = "openldap";
	
    /**
	 * DN of the OpenLDAP access log 
	 */
	private String openLdapAccessLogDn;

	/**
	 * optional additional search filter in the OpenLDAP access log
	 */
	private String openLdapAccessLogAdditionalFilter;
    
    @ConfigurationProperty(order = 100)
	public String getLockoutStrategy() {
		return lockoutStrategy;
	}

	public void setLockoutStrategy(String lockoutStrategy) {
		this.lockoutStrategy = lockoutStrategy;
	}

	@Override
	public void recompute() {
		if (getUidAttribute() == null) {
			setUidAttribute(SchemaConstants.ENTRY_UUID_AT);
		}
		super.recompute();
	}
	
	@ConfigurationProperty(order = 42)
	public String getOpenLdapAccessLogDn() {
		return this.openLdapAccessLogDn;
	}

	public void setOpenLdapAccessLogDn(String accessLogDn) {
		this.openLdapAccessLogDn = accessLogDn;
	}

	@ConfigurationProperty(order = 43)
	public String getOpenLdapAccessLogAdditionalFilter() {
		return this.openLdapAccessLogAdditionalFilter;
	}

	public void setOpenLdapAccessLogAdditionalFilter(String accessLogAditionalFilter) {
		this.openLdapAccessLogAdditionalFilter = accessLogAditionalFilter;
	}

}