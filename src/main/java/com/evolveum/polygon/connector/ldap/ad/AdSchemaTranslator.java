/**
 * Copyright (c) 2015-2024 Evolveum
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

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import com.evolveum.polygon.connector.ldap.LdapConstants;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.ad.AdConstants.UAC;
import com.evolveum.polygon.connector.ldap.ad.AdUserParametersHandler.CtxCfgFlagsBitValues;
import com.evolveum.polygon.connector.ldap.ad.AdUserParametersHandler.UserParametersAttributes;
import com.evolveum.polygon.connector.ldap.ad.AdUserParametersHandler.UserParametersValueTypes;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

import static com.evolveum.polygon.connector.ldap.LdapConstants.*;
import static com.evolveum.polygon.connector.ldap.ad.AdConstants.AD_MEMBERSHIP_ATTRIBUTES;


/**
 * @author semancik
 *
 */
public class AdSchemaTranslator extends AbstractSchemaTranslator<AdLdapConfiguration> {

    private static final Log LOG = Log.getLog(AdSchemaTranslator.class);

    // Note: List the attributes here as all lowercase.
    // AD varies the letter case in attribute names quite a lot, therefore the connector looks for
    // attribute names using their lower-case versions.
    private static final String[] OPERATIONAL_ATTRIBUTE_NAMES = {
        "distinguishedname", "dscorepropagationdata",
        "allowedattributes", "allowedattributeseffective",
        "allowedchildclasses", "allowedchildclasseseffective",
        "replpropertymetadata",
        "usnchanged", "usncreated",
        "whenchanged", "whencreated",

    };

    /**
     * List of attributes in the top object class that are specified as
     * mandatory but they are in fact optional.
     */
    private static final String[] OPTIONAL_TOP_ATTRIBUTES = {
            "ntsecuritydescriptor", "instancetype", "objectcategory"
    };

    private static final ObjectClass FSP_OBJECT_CLASS = new ObjectClass("foreignSecurityPrincipal");
    private static final Pattern FSP_DN_PATTERN = Pattern.compile("^CN=(.*),CN=ForeignSecurityPrincipals,DC=.*", Pattern.CASE_INSENSITIVE);

    private AttributeType guidAttributeType = null;

    public AdSchemaTranslator(SchemaManager schemaManager, AdLdapConfiguration configuration) {
        super(schemaManager, configuration);
    }

    @Override
    protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        super.extendObjectClassDefinition(ocib, ldapObjectClass);
        if (getConfiguration().isTweakSchema()) {
            // Account and groups need samAccountName attribute. But it is not in the declared schema.
            if (isUserObjectClass(ldapObjectClass.getName()) || isGroupObjectClass(ldapObjectClass.getName())) {

                AttributeInfoBuilder samAccountNameAttr = new AttributeInfoBuilder(AdConstants.ATTRIBUTE_SAM_ACCOUNT_NAME_NAME);
                samAccountNameAttr.setType(String.class);
                ocib.addAttributeInfo(samAccountNameAttr.build());

                AttributeInfoBuilder objectSidAttr = new AttributeInfoBuilder(AdConstants.ATTRIBUTE_OBJECT_SID_NAME);
                objectSidAttr.setType(String.class);
                objectSidAttr.setCreateable(false);
                objectSidAttr.setUpdateable(false);
                ocib.addAttributeInfo(objectSidAttr.build());
            }
        }

        //create uac attributes
        if (!getConfiguration().isRawUserAccountControlAttribute()) {
            //enable is ICF
            AttributeInfoBuilder enableAb = new AttributeInfoBuilder(OperationalAttributes.ENABLE_NAME);
            enableAb.setType(boolean.class);
            ocib.addAttributeInfo(enableAb.build());

            //all uac attributes defined in AdConstants
            for (UAC uac : AdConstants.UAC.values()) {
                AttributeInfoBuilder uacAb = new AttributeInfoBuilder(uac.name());
                uacAb.setType(boolean.class);
                uacAb.setUpdateable(!uac.isReadOnly());

                ocib.addAttributeInfo(uacAb.build());
            }
        }
        
        //create userParameters attribtues
        if (!getConfiguration().isRawUserParametersAttribute() && isUserObjectClass(ldapObjectClass.getName())) {
            for (UserParametersAttributes up : UserParametersAttributes.values()) {
                AttributeInfoBuilder upAb = new AttributeInfoBuilder(up.getName());
                upAb.setType(String.class);
                ocib.addAttributeInfo(upAb.build());
                // strings have an additional widestring representation
                if (up.getType().equals(UserParametersValueTypes.STRING_VALUE)) {
                    AttributeInfoBuilder upAbWideString = new AttributeInfoBuilder(up.getName()+"W");
                    upAbWideString.setType(String.class);
                    ocib.addAttributeInfo(upAbWideString.build());
                }
            }
            for(CtxCfgFlagsBitValues flag : CtxCfgFlagsBitValues.values()) {
                AttributeInfoBuilder upFlagAb = new AttributeInfoBuilder(flag.name());
                upFlagAb.setType(Boolean.class);
                ocib.addAttributeInfo(upFlagAb.build());
            }
            
        }
    }

    @Override
    protected void setAttributeMultiplicityAndPermissions(AttributeType ldapAttributeType, String connidAttributeName,
            AttributeInfoBuilder aib) {
        super.setAttributeMultiplicityAndPermissions(ldapAttributeType, connidAttributeName, aib);
        if (ArrayUtils.contains(OPTIONAL_TOP_ATTRIBUTES, ldapAttributeType.getName().toLowerCase())) {
            aib.setRequired(false);
        }
        if (getConfiguration().isAddDefaultObjectCategory() && AdConstants.ATTRIBUTE_OBJECT_CATEGORY_NAME.equals(ldapAttributeType.getName())) {
            // Connector is going to manage objectCategory. Therefore from the point of view of IDM the objectCategory is optional.
            aib.setRequired(false);
        }
    }

    @Override
    public AttributeType toLdapAttribute(
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, String icfAttributeName) {
        if (!getConfiguration().isRawUserAccountControlAttribute() && icfAttributeName.equals(OperationalAttributes.ENABLE_NAME)) {
            return super.toLdapAttribute(ldapObjectClass, AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME);
        } else {
            return super.toLdapAttribute(ldapObjectClass, icfAttributeName);
        }
    }

    /**
     * @param ldapValue containing AD interval value (100-nanosecond intervals since 1601-01-01)
     * @return long UTC millis
     */
    @Override
    protected Long getLastLoginDateValue(
            String connIdAttributeName, Value ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
        String value = ldapValue.getString();

        if (value == null) {
            return null;
        }
        return LdapUtil.windowsTimeToZonedDateTime(value).toInstant().toEpochMilli();
    }

    @Override
    protected Object toConnIdValue(String connIdAttributeName, Value ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
        if (AdConstants.ATTRIBUTE_OBJECT_SID_NAME.equals(ldapAttributeName)) {
            return sidToString(ldapValue.getBytes());
        } else {
            return super.toConnIdValue(connIdAttributeName, ldapValue, ldapAttributeName, ldapAttributeType);
        }
    }

    private String sidToString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        if (bytes.length < 8) {
            throw new InvalidAttributeValueException("Wrong SID syntax, expected at least 8 bytes, but got "+bytes.length+" bytes");
        }

        StringBuilder sb = new StringBuilder("S-1");

        // Byte 0: revision
        int revision = bytes[0];
        if (revision != 1) {
            throw new InvalidAttributeValueException("Unexpected SID revision: "+revision);
        }

        // Byte 1: subAuthorityCount
        int subAuthorityCount = bytes[1];

        // Byte 2-7: IdentifierAuthority (SID_IDENTIFIER_AUTHORITY)
        decodeSidAuthority(sb, bytes, 2);

        // Bytes 8-...: SubAuthority
        for (int i = 0; i < subAuthorityCount; i ++) {
            decodeSidSubauthority(sb, bytes, 8 + 4*i);
        }

        return sb.toString();
    }

    private void decodeSidAuthority(StringBuilder sb, byte[] bytes, int startByte) {
        long value = 0;
        for (int i = startByte; i < startByte + 6; i++) {
            value <<= 8;
            value |= bytes[i] & 0xFF;
        }
        sb.append("-").append(value);
    }

    private void decodeSidSubauthority(StringBuilder sb, byte[] bytes, int startByte) {
        long value = 0;
        for (int i = startByte + 3; i >= startByte; i--) {
            value <<= 8;
            value |= bytes[i] & 0xFF;
        }
        sb.append("-").append(value);
    }

    public boolean isFSPObjectClass(ObjectClass objectClass) {
        return FSP_OBJECT_CLASS.equals(objectClass);
    }

    public boolean isFSPDn(String dnString) {
        return FSP_DN_PATTERN.matcher(dnString).matches();
    }

    public String resolveMemberDn(String dnString) {
        Matcher matcher = FSP_DN_PATTERN.matcher(dnString);
        if (matcher.matches()) {
            return getSidDn(matcher.group(1));
        }
        return dnString;
    }

    public String getSidDn(String sid) {
        return "<SID=" + sid + ">";
    }

    @Override
    public Value toLdapIdentifierValue(AttributeType ldapAttributeType, String connIdAttributeValue) {
        if (isGuid(ldapAttributeType)) {
            connIdAttributeValue = parseGuidFromDashedNotation(connIdAttributeValue);
        }
        return super.toLdapIdentifierValue(ldapAttributeType, connIdAttributeValue);
    }

    @Override
    public String toConnIdIdentifierValue(Value ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
        String icfIdentifierValue = super.toConnIdIdentifierValue(ldapValue, ldapAttributeName, ldapAttributeType);
        if (isGuid(ldapAttributeType)) {
            icfIdentifierValue = formatGuidToDashedNotation(icfIdentifierValue);
        }
        return icfIdentifierValue;
    }

    private boolean isGuid(AttributeType ldapAttributeType) {
        return ldapAttributeType.getName().equalsIgnoreCase(AdConstants.ATTRIBUTE_OBJECT_GUID_NAME);
    }

    @Override
    protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
        super.extendConnectorObject(cob, entry, objectClassName);
        if (!getConfiguration().isRawUserAccountControlAttribute()) {
            Integer userAccountControl = LdapUtil.getIntegerAttribute(entry, AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, null);
            if (userAccountControl == null) {
                if (isUserObjectClass(objectClassName)) {
                    cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.FALSE);
                }
            } else {
                if ((userAccountControl & AdConstants.UAC.ADS_UF_ACCOUNTDISABLE.getBit()) == 0) {
                    cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.TRUE);
                } else {
                    cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.FALSE);
                }
                for (UAC uac : UAC.values()) {
                    if ((userAccountControl & uac.getBit()) == 0) {
                        cob.addAttribute(uac.name(), Boolean.FALSE);
                    } else {
                        cob.addAttribute(uac.name(), Boolean.TRUE);
                    }
                }
            }
        }
        if (!getConfiguration().isRawUserParametersAttribute() && isUserObjectClass(objectClassName)) {
            Attribute userParametersAttr = entry.get(AdUserParametersHandler.USER_PARAMETERS_LDAP_ATTR_NAME);
            if (userParametersAttr != null) {
                AdUserParametersHandler handler = new AdUserParametersHandler();
                try {
                    handler.setUserParameters(userParametersAttr.getString());
                    try {
                        cob.addAttributes(handler.toIcf());
                    } catch (AdUserParametersHandlerException e) {
                        if (getConfiguration().isUserParametersThrowException()) {
                            LOG.error(e, "Could not parse userParameters to icf Attributes of entry with DN "
                                    + entry.getDn());
                            throw new InvalidAttributeValueException(
                                    "Could not parse userParameters to icf Attributes for entry with dn "
                                            + entry.getDn(),
                                    e);
                        } else {
                            LOG.warn("Could not parse userParameters to icf Attributes of entry with DN '"
                                    + entry.getDn() + "'. Will not throw an Exception due to configuration.");
                            LOG.ok(e, "The following Exception was thrown while parsing Userparameters:");
                        }

                    }
                } catch (LdapInvalidAttributeValueException e) {
                    throw new InvalidAttributeValueException(e);
                }
                // reset userParameters to avoid excess data at the end of the byte array and
                // eventually fix it with next write operation
                cob.addAttribute(AdUserParametersHandler.USER_PARAMETERS_LDAP_ATTR_NAME, handler.getUserParameters());
            }
        }
    }

    public boolean isUserObjectClass(String ldapObjectClass) {
        return getConfiguration().getUserObjectClass().equals(ldapObjectClass);
    }

    public boolean isGroupObjectClass(String ldapObjectClass) {
        return getConfiguration().getGroupObjectClass().equals(ldapObjectClass);
    }

    @Override
    protected Value toLdapPasswordValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
        String password;
        if (icfAttributeValue instanceof String) {
                password = (String)icfAttributeValue;
        } else if (icfAttributeValue instanceof GuardedString) {
            final String[] out = new String[1];
            ((GuardedString)icfAttributeValue).access(new GuardedString.Accessor() {
                @Override
                public void access(char[] clearChars) {
                    out[0] = new String(clearChars);
                }
            });
            password = out[0];
        } else {
            throw new IllegalArgumentException("Password must be string or GuardedString, but it was "+icfAttributeValue.getClass());
        }

        String quotedPassword = "\"" + password + "\"";
        byte[] utf16PasswordBytes;
        try {
            utf16PasswordBytes = quotedPassword.getBytes("UTF-16LE");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Error converting password to UTF-16: "+e.getMessage(), e);
        }

        try {
            return new Value(ldapAttributeType, utf16PasswordBytes);
        } catch (LdapInvalidAttributeValueException e) {
            throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                    +"; attributeType="+ldapAttributeType, e);
        }
    }

    @Override
    protected boolean isBinarySyntax(String syntaxOid) {
        if (syntaxOid == null) {
            return false;
        }
        switch (syntaxOid) {
            case LdapConstants.SYNTAX_AD_ADSTYPE_OCTET_STRING:
            case LdapConstants.SYNTAX_AD_ADSTYPE_NT_SECURITY_DESCRIPTOR:
                // Even though this is "String(Sid)", it is not really string. It is binary.
            case LdapConstants.SYNTAX_AD_STRING_SID:
                return true;
            default :
                return super.isBinarySyntax(syntaxOid);
        }
    }

    @Override
    public boolean isBinaryAttribute(String attributeId) {
        if (AdConstants.ATTRIBUTE_NT_SECURITY_DESCRIPTOR.equalsIgnoreCase(attributeId)) {
            return true;
        }
        if (AdConstants.ATTRIBUTE_UNICODE_PWD_NAME.equalsIgnoreCase(attributeId)) {
            return true;
        }
        return super.isBinaryAttribute(attributeId);
    }

    public Dn getGuidDn(String uidValue) {
        // Yes, this is really how Active Directory DNs looks like. Yes, they are really DNs.
        // Insane, isn't it? Well, yes, it is AD after all.
        // We need to create this as schema-aware even though it has nothing to do with the
        // schema. But if the Dn parsing does not know about schemaManager it does not know
        // that we are in relaxed mode and it will fail with these crazy DNs.
        return toSchemaAwareDn("<GUID="+uidValue+">");
    }


    public String getGuidAsDashedString(Entry entry) {
        Attribute guidAttribute = entry.get(AdConstants.ATTRIBUTE_OBJECT_GUID_NAME);
        String hexNotation = super.toConnIdIdentifierValue(guidAttribute.get(), AdConstants.ATTRIBUTE_OBJECT_GUID_NAME,
                getGuidAttributeType());
        return formatGuidToDashedNotation(hexNotation);
    }

    private AttributeType getGuidAttributeType() {
        if (guidAttributeType == null) {
            guidAttributeType = getSchemaManager().getAttributeType(AdConstants.ATTRIBUTE_OBJECT_GUID_NAME);
        }
        return guidAttributeType;
    }

    /**
     * Returns dashed GUID notation formatted from simple hex-encoded binary.
     *
     * E.g. "2f01c06bb1d0414e9a69dd3841a13506" -> "6bc0012f-d0b1-4e41-9a69-dd3841a13506"
     */
    public String formatGuidToDashedNotation(String hexValue) {
        if (hexValue == null) {
            return null;
        }
        if (hexValue.length() != 32) {
            throw new InvalidAttributeValueException("Unexpected GUID format: "+hexValue);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(hexValue.substring(6, 8));
        sb.append(hexValue.substring(4, 6));
        sb.append(hexValue.substring(2, 4));
        sb.append(hexValue.substring(0, 2));
        sb.append('-');
        sb.append(hexValue.substring(10, 12));
        sb.append(hexValue.substring(8, 10));
        sb.append('-');
        sb.append(hexValue.substring(14, 16));
        sb.append(hexValue.substring(12, 14));
        sb.append('-');
        sb.append(hexValue.substring(16, 20));
        sb.append('-');
        sb.append(hexValue.substring(20, 32));
        return sb.toString();
    }

    /**
     * Returns simple hex-encoded string parsed from dashed GUID notation.
     *
     * E.g. "6bc0012f-d0b1-4e41-9a69-dd3841a13506" -> "2f01c06bb1d0414e9a69dd3841a13506"
     */
    public String parseGuidFromDashedNotation(String guidDashedNotation) {
        if (guidDashedNotation == null) {
            return null;
        }
        if (guidDashedNotation.length() != 36) {
            throw new InvalidAttributeValueException("Unexpected GUID format: "+guidDashedNotation);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(guidDashedNotation.substring(6, 8));
        sb.append(guidDashedNotation.substring(4, 6));
        sb.append(guidDashedNotation.substring(2, 4));
        sb.append(guidDashedNotation.substring(0, 2));
        sb.append(guidDashedNotation.substring(11, 13));
        sb.append(guidDashedNotation.substring(9, 11));
        sb.append(guidDashedNotation.substring(16, 18));
        sb.append(guidDashedNotation.substring(14, 16));
        sb.append(guidDashedNotation.substring(19, 23));
        sb.append(guidDashedNotation.substring(24, 36));
        return sb.toString();
    }

    @Override
    public String getDn(Entry entry) {
        // distinguishedName attribute provides better DN format (some kind of Microsoft-cannonical form).
        // The usual entry DN will be formatted in the same way as it was in the request. Therefore if
        // name hint is used with midPoint, the normal DN will be all lowercase. This may break some things,
        // e.g. it may interfere with names in older shadows.
        // So use distinguishedName attribute if available.
        Attribute distinguishedNameAttr = entry.get(AdConstants.ATTRIBUTE_DISTINGUISHED_NAME_NAME);
        if (distinguishedNameAttr != null) {
            try {
                return distinguishedNameAttr.getString();
            } catch (LdapInvalidAttributeValueException e) {
                LOG.warn("Error getting sting value from {0}, falling back to entry DN: {1}",
                        distinguishedNameAttr, e.getMessage(), e);
                return super.getDn(entry);
            }
        }
        return super.getDn(entry);
    }

    @Override
    protected boolean isConfiguredAsOperational(String ldapAttributeName) {
        // AD is using attribute letter case quite wildly, therefore use case-ignore search
        if (ldapAttributeName.toLowerCase().startsWith("msds-")) {
            return true;
        }
        for (String confOpAttr : OPERATIONAL_ATTRIBUTE_NAMES) {
            if (confOpAttr.equalsIgnoreCase(ldapAttributeName)) {
                return true;
            }
        }
        for (String confOpAttr : getConfiguration().getOperationalAttributes()) {
            if (confOpAttr.equalsIgnoreCase(ldapAttributeName)) {
                return true;
            }
        }
        return false;
    }

    protected boolean isVirtualAttribute(String connIdAttributeName) {
        if (AdConstants.UAC.forName(connIdAttributeName) != null) {
            return true;
        }

        if(!ArrayUtils.isEmpty(getConfiguration().getManagedAssociationPairs())){

            if(ATTR_SCHEMA_OBJECT.equalsIgnoreCase(connIdAttributeName)){

                if(AD_MEMBERSHIP_ATTRIBUTES.containsValue(connIdAttributeName)){

                    return false;
                }

                return true;
            }

            if(ATTR_SCHEMA_SUBJECT.equalsIgnoreCase(connIdAttributeName)){

                return true;
            }
        }

        return false;
    }

    @Override
    protected boolean isValidAttributeToGet(String connidAttr, AttributeType ldapAttributeType) {
        if (isVirtualAttribute(connidAttr)) {
            return false;
        }
        if (ldapAttributeType == null) {
            // Strange, but not too strange for AD. Let's allow it.
            return true;
        }
        List<String> searchFlags = ldapAttributeType.getExtension("X-SEARCH-FLAGS");
        if (searchFlags != null) {
            LOG.info("X-SEARCH-FLAGS on {0}: {1}", connidAttr, searchFlags);
        }
        return true;
    }
}
