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

package com.evolveum.polygon.connector.ldap.edirectory;

import org.identityconnectors.framework.spi.ConfigurationProperty;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;

/**
 * eDirectory LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class EDirectoryLdapConfiguration extends AbstractLdapConfiguration {

	private static final String ATTRIBUTE_GUID_NAME = "GUID";
    
    private String userObjectClass = "inetOrgPerson";
    
    private String groupObjectClass = "groupOfNames";
    
    private String groupObjectMemberAttribute = "member";
    
    private boolean manageReciprocalGroupAttributes = true;
    
    private boolean manageEquivalenceAttributes = true;
    
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
	public boolean isManageReciprocalGroupAttributes() {
		return manageReciprocalGroupAttributes;
	}

	public void setManageReciprocalGroupAttributes(boolean manageReciprocalGroupAttributes) {
		this.manageReciprocalGroupAttributes = manageReciprocalGroupAttributes;
	}

	@ConfigurationProperty(order = 104)
	public boolean isManageEquivalenceAttributes() {
		return manageEquivalenceAttributes;
	}

	public void setManageEquivalenceAttributes(boolean manageEquivalenceAttributes) {
		this.manageEquivalenceAttributes = manageEquivalenceAttributes;
	}

	@Override
	public void recompute() {
		if (getUidAttribute() == null) {
			setUidAttribute(ATTRIBUTE_GUID_NAME);
		}
		super.recompute();
	}

}