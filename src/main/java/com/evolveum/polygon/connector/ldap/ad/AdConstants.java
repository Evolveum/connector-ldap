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

import java.util.Map;

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

    public static final String OBJECT_CLASS_CLASS_SCHEMA = "classSchema";
    public static final String OBJECT_CLASS_ATTRIBUTE_SCHEMA = "attributeSchema";
    public static final String OBJECT_CLASS_DMD = "dMD";
    public static final String OBJECT_CLASS_SUB_SCHEMA = "subSchema";

    public static final String OBJECT_CLASS_NAME_USER = "user";
    public static final String OBJECT_CLASS_NAME_GROUP = "group";

    public static final Map<String, String> AD_MEMBERSHIP_ATTRIBUTES = Map.of(OBJECT_CLASS_NAME_GROUP,"member");

    /*
     * https://docs.microsoft.com/en-us/windows/desktop/adschema/a-useraccountcontrol
     *
     *
     */
    protected static enum UAC {
//account types
        //Typical user : 0x200 (512)
        //Domain controller : 0x82000 (532480) this is: ADS_UF_SERVER_TRUST_ACCOUNT + ADS_UF_TRUSTED_FOR_DELEGATION
        //Workstation/server: 0x1000 (4096)

        ADS_UF_SCRIPT (0x00000001, true), //int: 1 //The logon script is executed.
        //ADS_UF_ACCOUNTDISABLE is readonly because OperationalAttributes.ENABLE_NAME is master
        ADS_UF_ACCOUNTDISABLE (0x00000002, true), //int: 2 //The user account is disabled.
        ADS_UF_HOMEDIR_REQUIRED (0x00000008), //int: 8 //The home directory is required.
        ADS_UF_LOCKOUT (0x00000010, true), //int: 16 //The account is currently locked out.
        ADS_UF_PASSWD_NOTREQD (0x00000020), //int: 32 //No password is required.
        ADS_UF_PASSWD_CANT_CHANGE (0x00000040, true), //int: 64 //The user cannot change the password. [!Note]You cannot assign the permission settings of PASSWD_CANT_CHANGE by directly modifying the UserAccountControl attribute. For more information and a code example that shows how to prevent a user from changing the password, see User Cannot Change Password.
        ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x00000080), //int: 128 //The user can send an encrypted password.
        ADS_UF_TEMP_DUPLICATE_ACCOUNT (0x00000100, true), //int: 256 //This is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. Also known as a local user account.
        ADS_UF_NORMAL_ACCOUNT (0x00000200, true), //int: 512 //This is a default account type that represents a typical user.
        ADS_UF_INTERDOMAIN_TRUST_ACCOUNT (0x00000800, true), //int: 2048  //This is a permit to trust account for a system domain that trusts other domains.
        ADS_UF_WORKSTATION_TRUST_ACCOUNT (0x00001000, true), //int: 4096 //This is a computer account for a computer that is a member of this domain.
        ADS_UF_SERVER_TRUST_ACCOUNT (0x00002000, true), //int: 8192 //This is a computer account for a system backup domain controller that is a member of this domain.
        //N/A (0x00004000), //int: 548864 //Not used.
        //N/A (0x00008000), //int: 565248//Not used.
        ADS_UF_DONT_EXPIRE_PASSWD (0x00010000), //int: 65536 //The password for this account will never expire.
        ADS_UF_MNS_LOGON_ACCOUNT (0x00020000), //int: 131072 //This is an MNS logon account.
        ADS_UF_SMARTCARD_REQUIRED (0x00040000), //int: 262144 //The user must log on using a smart card.
        ADS_UF_TRUSTED_FOR_DELEGATION (0x00080000), //int: 524288 //The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
        ADS_UF_NOT_DELEGATED (0x00100000), //int: 1048576 //The security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation.
        ADS_UF_USE_DES_KEY_ONLY (0x00200000), //int: 2097152 //Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
        ADS_UF_DONT_REQUIRE_PREAUTH (0x00400000), //int: 4194304 //This account does not require Kerberos pre-authentication for logon.
        ADS_UF_PASSWORD_EXPIRED (0x00800000, true), //int: 8388608 //The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the domain policy.
        ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (0x01000000), //int: 16777216 //The account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled should be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
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
