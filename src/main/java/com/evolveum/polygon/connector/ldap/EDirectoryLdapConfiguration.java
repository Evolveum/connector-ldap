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
 * eDirectory LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class EDirectoryLdapConfiguration extends AbstractLdapConfiguration {

    private static final Log LOG = Log.getLog(EDirectoryLdapConfiguration.class);

	private static final String ATTRIBUTE_GUID_NAME = "GUID";
    
    private String userObjectClass = "inetOrgPerson";
    
    private String groupObjectClass = "groupOfNames";
    
    private String userContainerDn;
    
    private String groupContainerDn;
    
    private boolean completeSchema = false;
    
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

	public boolean isCompleteSchema() {
		return completeSchema;
	}

	public void setCompleteSchema(boolean completeSchema) {
		this.completeSchema = completeSchema;
	}

	@Override
	public void recompute() {
		if (userContainerDn == null) {
			userContainerDn = "ou=People,"+getBaseContext();
		}
		if (groupContainerDn == null) {
			groupContainerDn = "ou=Groups,"+getBaseContext();
		}
		if (getUidAttribute() == null) {
			setUidAttribute(ATTRIBUTE_GUID_NAME);
		}
	}
    

}