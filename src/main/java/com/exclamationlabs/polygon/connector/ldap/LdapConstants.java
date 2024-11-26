/**
 * Copyright (c) 2016 Evolveum
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
package com.exclamationlabs.polygon.connector.ldap;

/**
 * @author semancik
 *
 */
public class LdapConstants {

    public static final String ATTRIBUTE_OBJECTCLASS_NAME = "objectClass";
    public static final String ATTRIBUTE_ENTRYUUID_NAME = "entryUUID";
    public static final String ATTRIBUTE_NSUNIQUEID_NAME = "nsUniqueId";
    public static final String ATTRIBUTE_MODIFYTIMESTAMP_NAME = "modifyTimestamp";
    public static final String ATTRIBUTE_MODIFIERSNAME_NAME = "modifiersName";
    public static final String ATTRIBUTE_CREATETIMESTAMP_NAME = "createTimestamp";
    public static final String ATTRIBUTE_CREATORSNAME_NAME = "creatorsName";

    public static final String ATTRIBUTE_CN_NAME = "cn";
    public static final String ATTRIBUTE_CN_OID = "2.5.4.3";

    public static final String ATTRIBUTE_DC_NAME = "dc";
    public static final String ATTRIBUTE_DC_OID = "0.9.2342.19200300.100.1.25";

    public static final String ATTRIBUTE_OU_NAME = "ou";
    public static final String ATTRIBUTE_OU_OID = "2.5.4.11";

    public static final String ATTRIBUTE_389DS_FIRSTCHANGENUMBER = "firstchangenumber";
    public static final String ATTRIBUTE_389DS_LASTCHANGENUMBER = "lastchangenumber";

    // Account disable attribute for OpenDS/OpenDJ servers. Used in tests.
    public static final String ATTRIBUTE_OPENDJ_DS_PWP_ACCOUNT_DISABLED_NAME = "ds-pwp-account-disabled";

    // Group memebership virtual attribure used by some servers (e.g. OpenDJ).
    public static final String ATTRIBUTE_IS_MEMBER_OF_NAME = "isMemberOf";

    // Group memebership virtual attribure used by other servers (e.g. OpenLDAP).
    public static final String ATTRIBUTE_MEMBER_OF_NAME = "memberOf";

    // TODO isn't this the same as SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT?
    public static final String ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_NAME = "pwdAccountLockedTime";

    public static final String ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_VALUE = "000001010000Z";

    public static final String MATCHING_RULE_CASE_IGNORE_MATCH_NAME = "caseIgnoreMatch";
    public static final String MATCHING_RULE_CASE_IGNORE_MATCH_OID = "2.5.13.2";

    public static final String MATCHING_RULE_CASE_IGNORE_IA5_MATCH_NAME = "caseIgnoreIA5Match";
    public static final String MATCHING_RULE_CASE_IGNORE_IA5_MATCH_OID = "1.3.6.1.4.1.1466.109.114.2";

    public static final String SYNTAX_AUTH_PASSWORD = "1.3.6.1.4.1.4203.1.1.2";
    public static final String SYNTAX_SUN_DEFINED_ACCESS_CONTROL_INFORMATION = "1.3.6.1.4.1.26027.1.3.4";
    public static final String SYNTAX_COLLECTIVE_CONFLICT_BEHAVIOR = "1.3.6.1.4.1.26027.1.3.6";
    public static final String SYNTAX_NIS_NETGROUP_TRIPLE_SYNTAX = "1.3.6.1.1.1.0.0";
    public static final String SYNTAX_NIS_BOOT_PARAMETER_SYNTAX = "1.3.6.1.1.1.0.1";
    public static final String SYNTAX_AD_DN_WITH_BINARY_SYNTAX = "1.2.840.113556.1.4.903";
    public static final String SYNTAX_AD_DN_WITH_STRING_SYNTAX = "1.2.840.113556.1.4.904";
    public static final String SYNTAX_AD_CASE_IGNORE_STRING_TELETEX_SYNTAX = "1.2.840.113556.1.4.905";
    public static final String SYNTAX_AD_CASE_IGNORE_STRING_SYNTAX = "1.2.840.113556.1.4.1221";
    public static final String SYNTAX_AD_INTEGER8_SYNTAX = "1.2.840.113556.1.4.906";
    public static final String SYNTAX_AD_OBJECT_DS_DN = "2.5.5.1";
    public static final String SYNTAX_AD_STRING_OBJECT_IDENTIFIER = "2.5.5.2";
    public static final String SYNTAX_AD_STRING_CASE = "2.5.5.3";
    public static final String SYNTAX_AD_STRING_TELETEX = "2.5.5.4";
    public static final String SYNTAX_AD_STRING_IA5 = "2.5.5.5";
    public static final String SYNTAX_AD_STRING_NUMERIC = "2.5.5.6";
    public static final String SYNTAX_AD_OBJECT_DN_BINARY = "2.5.5.7";
    public static final String SYNTAX_AD_ADSTYPE_BOOLEAN = "2.5.5.8";
    public static final String SYNTAX_AD_ADSTYPE_INTEGER = "2.5.5.9";
    public static final String SYNTAX_AD_ADSTYPE_OCTET_STRING = "2.5.5.10";
    public static final String SYNTAX_AD_UTC_TIME = "2.5.5.11";
    public static final String SYNTAX_AD_STRING_UNICODE = "2.5.5.12";
    public static final String SYNTAX_AD_SECURITY_DESCRIPTOR_SYNTAX = "1.2.840.113556.1.4.907";
    public static final String SYNTAX_AD_OBJECT_PRESENTATION_ADDRESS = "2.5.5.13";
    public static final String SYNTAX_AD_OBJECT_ACCESS_POINT = "2.5.5.14";
    public static final String SYNTAX_AD_ADSTYPE_NT_SECURITY_DESCRIPTOR = "2.5.5.15";

    public static final String SYNTAX_AD_LARGE_INTEGER = "2.5.5.16";
    public static final String SYNTAX_AD_STRING_SID = "2.5.5.17";

    public static final String CONTROL_TREE_DELETE_OID = "1.2.840.113556.1.4.805";
}
