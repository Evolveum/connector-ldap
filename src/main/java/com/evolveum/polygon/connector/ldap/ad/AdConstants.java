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
	
	/*
	 * https://docs.microsoft.com/en-us/windows/desktop/adschema/a-useraccountcontrol
	 * 
	 * 
	 */
	protected static enum UAC {
		//TODO: which attributes should be readOnly
		//account types, only typical user for now
		//Typical user : 0x200 (512)
		//Domain controller : 0x82000 (532480)
		//Workstation/server: 0x1000 (4096)
		
		ADS_UF_SCRIPT (0x00000001), //The logon script is executed.
		//readonly because OperationalAttributes.ENABLE_NAME is master
		ADS_UF_ACCOUNTDISABLE (0x00000002, true), //The user account is disabled.
		ADS_UF_HOMEDIR_REQUIRED (0x00000008), //The home directory is required.
		ADS_UF_LOCKOUT (0x00000010, true), //The account is currently locked out.
		ADS_UF_PASSWD_NOTREQD (0x00000020), //No password is required.
		ADS_UF_PASSWD_CANT_CHANGE (0x00000040), //The user cannot change the password. [!Note]You cannot assign the permission settings of PASSWD_CANT_CHANGE by directly modifying the UserAccountControl attribute. For more information and a code example that shows how to prevent a user from changing the password, see User Cannot Change Password.
		ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x00000080), //The user can send an encrypted password.
		ADS_UF_TEMP_DUPLICATE_ACCOUNT (0x00000100, true), //This is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. Also known as a local user account.
		ADS_UF_NORMAL_ACCOUNT (0x00000200, true), //This is a default account type that represents a typical user.
		ADS_UF_INTERDOMAIN_TRUST_ACCOUNT (0x00000800, true), //This is a permit to trust account for a system domain that trusts other domains.
		ADS_UF_WORKSTATION_TRUST_ACCOUNT (0x00001000, true), //This is a computer account for a computer that is a member of this domain.
		ADS_UF_SERVER_TRUST_ACCOUNT (0x00002000, true), //This is a computer account for a system backup domain controller that is a member of this domain.
		//N/A (0x00004000), //Not used.
		//N/A (0x00008000), //Not used.
		ADS_UF_DONT_EXPIRE_PASSWD (0x00010000), //The password for this account will never expire.
		ADS_UF_MNS_LOGON_ACCOUNT (0x00020000), //This is an MNS logon account.
		ADS_UF_SMARTCARD_REQUIRED (0x00040000), //The user must log on using a smart card.
		ADS_UF_TRUSTED_FOR_DELEGATION (0x00080000), //The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
		ADS_UF_NOT_DELEGATED (0x00100000), //The security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation.
		ADS_UF_USE_DES_KEY_ONLY (0x00200000), //Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
		ADS_UF_DONT_REQUIRE_PREAUTH (0x00400000), //This account does not require Kerberos pre-authentication for logon.
		ADS_UF_PASSWORD_EXPIRED (0x00800000, true), //The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the domain policy.
		ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (0x01000000), //The account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled should be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
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
        
        private static final UAC[] copyOfValues = values();

        public static UAC forName(String name) {
            for (UAC value : copyOfValues) {
                if (value.name().equals(name)) {
                    return value;
                }
            }
            return null;
        }
    }

}
