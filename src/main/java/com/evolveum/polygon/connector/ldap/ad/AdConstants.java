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
	public static final String ATTRIBUTE_UNICODE_PWD_OID = "1.2.840.113556.1.4.90";
	public static final String ATTRIBUTE_CN_NAME = "cn";
	public static final String ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME = "userAccountControl";
	public static final String ATTRIBUTE_NT_SECURITY_DESCRIPTOR = "nTSecurityDescriptor";
	public static final String ATTRIBUTE_IS_DELETED = "isDeleted";
	public static final String ATTRIBUTE_DISTINGUISHED_NAME_NAME = "distinguishedName";
	public static final String ATTRIBUTE_PWD_LAST_SET_NAME = "pwdLastSet";
	
	public static final int USER_ACCOUNT_CONTROL_NORMAL = 0x0200;
	public static final int USER_ACCOUNT_CONTROL_DISABLED = 0x0002;
	
	protected static enum UAC {
		UAC_SCRIPT(0x0001), //1
		UAC_ACCOUNTDISABLE(0x0002, true), //2
		UAC_HOMEDIR_REQUIRED(0x0008, true), //8
		//UAC_LOCKOUT(0x0010, true), //16
		UAC_PASSWD_NOTREQD(0x0020), //32
		UAC_PASSWD_CANT_CHANGE(0x0040, true), //64
		UAC_ENCRYPTED_TEXT_PWD_ALLOWED(0x0080, true), //128
		UAC_TEMP_DUPLICATE_ACCOUNT(0x0100, true), //256
		UAC_NORMAL_ACCOUNT(0x0200, true), //512
		UAC_INTERDOMAIN_TRUST_ACCOUNT(0x0800, true), //2048
		UAC_WORKSTATION_TRUST_ACCOUNT(0x1000, true), //4096
		UAC_SERVER_TRUST_ACCOUNT(0x2000, true), //8192
		UAC_DONT_EXPIRE_PASSWORD(0x10000), //65536
		UAC_MNS_LOGON_ACCOUNT(0x20000, true), //131072
		UAC_SMARTCARD_REQUIRED(0x40000), //262144
		UAC_TRUSTED_FOR_DELEGATION(0x80000, true), //524288
		UAC_PARTIAL_SECRETS_ACCOUNT(0x04000000, true), //67108864
		UAC_NOT_DELEGATED(0x100000, true), //1048576
		UAC_USE_DES_KEY_ONLY(0x200000, true), //2097152
		UAC_DONT_REQ_PREAUTH(0x400000, true), //4194304
		//UAC_PASSWORD_EXPIRED(0x800000, true), //8388608
		UAC_TRUSTED_TO_AUTH_FOR_DELEGATION(0x1000000, true) //16777216
        ;

		private final int bit;
		private final boolean readOnly;
		
        UAC(final int bit)
        {
            this.bit = bit;
            this.readOnly = false;
        }
        
        UAC(final int bit, final boolean readOnly)
        {
            this.bit = bit;
            this.readOnly = readOnly;
        }
        
        public int getBit()
        {
            return bit;
        }
        public boolean isReadOnly()
        {
            return readOnly;
        }
    }

}
