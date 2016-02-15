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

package com.evolveum.polygon.connector.ldap.ad;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;

/**
 * Active Directory LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class AdLdapConfiguration extends AbstractLdapConfiguration {

	public static final String ATTRIBUTE_OBJECT_GUID_NAME = "objectGUID";
	public static final String ATTRIBUTE_UNICODE_PWD_NAME = "unicodePwd";
    
    private String userObjectClass = "user";
    
    private String groupObjectClass = "group";
    
    private String groupObjectMemberAttribute = "member";
    
    private String userContainerDn;
    
    private String groupContainerDn;
        
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
		super.recompute();
	}
    

}