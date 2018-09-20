/**
 * Copyright (c) 2015-2018 Evolveum
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
	
	public static final String ATTRIBUTE_OBJECT_GUID_NAME = "objectGUID";
	public static final String ATTRIBUTE_OBJECT_SID_NAME = "objectSid";
	public static final String ATTRIBUTE_SAM_ACCOUNT_NAME_NAME = "sAMAccountName";
	public static final String ATTRIBUTE_UNICODE_PWD_NAME = "unicodePwd";
	public static final String ATTRIBUTE_CN_NAME = "cn";
	public static final String ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME = "userAccountControl";
	public static final String ATTRIBUTE_NT_SECURITY_DESCRIPTOR = "nTSecurityDescriptor";
	public static final String ATTRIBUTE_IS_DELETED = "isDeleted";
	public static final String ATTRIBUTE_DISTINGUISHED_NAME_NAME = "distinguishedName";
	public static final String ATTRIBUTE_PWD_LAST_SET_NAME = "pwdLastSet";
	
	public static final int USER_ACCOUNT_CONTROL_NORMAL = 0x0200;
	public static final int USER_ACCOUNT_CONTROL_DISABLED = 0x0002;

}
