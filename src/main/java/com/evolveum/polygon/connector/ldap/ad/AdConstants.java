/**
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

/**
 * @author semancik
 *
 */
public class AdConstants {
	
	/**
	 * Name used for native AD schema in Apache Directory API.
	 */
	public static final String AD_SCHEMA_NAME = "AD";
	
	public static final String ATTRIBUTE_OBJECT_GUID_NAME = "objectGUID";
	public static final String ATTRIBUTE_OBJECT_SID_NAME = "objectSid";
	public static final String ATTRIBUTE_OBJECT_CATEGORY_NAME = "objectCategory";
	public static final String ATTRIBUTE_SAM_ACCOUNT_NAME_NAME = "sAMAccountName";
	public static final String ATTRIBUTE_UNICODE_PWD_NAME = "unicodePwd";
	public static final String ATTRIBUTE_UNICODE_PWD_OID = "1.2.840.113556.1.4.90";
	public static final String ATTRIBUTE_CN_NAME = "cn";
	public static final String ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME = "userAccountControl";
	public static final String ATTRIBUTE_NT_SECURITY_DESCRIPTOR = "nTSecurityDescriptor";
	public static final String ATTRIBUTE_IS_DELETED = "isDeleted";
	public static final String ATTRIBUTE_DISTINGUISHED_NAME_NAME = "distinguishedName";
	public static final String ATTRIBUTE_PWD_LAST_SET_NAME = "pwdLastSet";
	public static final String ATTRIBUTE_SCHEMA_NAMING_CONTEXT_NAME = "schemaNamingContext";
	public static final String ATTRIBUTE_GOVERNS_ID_NAME = "governsID";
	public static final String ATTRIBUTE_ATTRIBUTE_ID_NAME = "attributeID";
	public static final String ATTRIBUTE_LDAP_DISPLAY_NAME_NAME = "lDAPDisplayName";
	public static final String ATTRIBUTE_IS_SINGLE_VALUED_NAME = "isSingleValued";
	public static final String ATTRIBUTE_ATTRIBUTE_SYNTAX_NAME = "attributeSyntax";
	public static final String ATTRIBUTE_MUST_CONTAIN_NAME = "mustContain";
	public static final String ATTRIBUTE_SYSTEM_MUST_CONTAIN_NAME = "systemMustContain";
	public static final String ATTRIBUTE_MAY_CONTAIN_NAME = "mayContain";
	public static final String ATTRIBUTE_SYSTEM_MAY_CONTAIN_NAME = "systemMayContain";
	
	public static final String ATTRIBUTE_SYSTEM_POSS_SUPERIORS_NAME = "systemPossSuperiors";
	public static final String ATTRIBUTE_SYSTEM_ONLY_NAME = "systemOnly";
	public static final String ATTRIBUTE_SUB_CLASS_OF_NAME = "subClassOf";
	public static final String ATTRIBUTE_AUXILIARY_CLASS_NAME = "auxiliaryClass";
	public static final String ATTRIBUTE_DEFAULT_OBJECT_CATEGORY_NAME = "defaultObjectCategory";
	
	public static final int USER_ACCOUNT_CONTROL_NORMAL = 0x0200;
	public static final int USER_ACCOUNT_CONTROL_DISABLED = 0x0002;
	
	
	public static final String OBJECT_CLASS_CLASS_SCHEMA = "classSchema";
	public static final String OBJECT_CLASS_ATTRIBUTE_SCHEMA = "attributeSchema";
	public static final String OBJECT_CLASS_DMD = "dMD";
	public static final String OBJECT_CLASS_SUB_SCHEMA = "subSchema";
	

}
