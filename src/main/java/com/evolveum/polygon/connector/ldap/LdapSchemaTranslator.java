/**
 * Copyright (c) 2016-2019 Evolveum
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.evolveum.polygon.connector.ldap;

import java.util.Arrays;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.evolveum.polygon.connector.ldap.connection.ConnectionManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributeValueCompleteness;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;

import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.AttributeHandler;

import static com.evolveum.polygon.connector.ldap.ad.AdConstants.ATTRIBUTE_OBJECT_SID_NAME;
import static com.evolveum.polygon.connector.ldap.ad.AdConstants.ATTRIBUTE_SAM_ACCOUNT_NAME_NAME;

/**
 * @author semancik
 */
public class LdapSchemaTranslator extends AbstractSchemaTranslator<LdapConfiguration> {

    // TODO: move to polygon
    public static final String POLYSTRING_SUBTYPE = "http://midpoint.evolveum.com/xml/ns/public/connector/icf-1/subtypes#PolyString";
    public static final String POLYSTRING_ORIG_KEY = "";

    private static final Log LOG = Log.getLog(LdapSchemaTranslator.class);

    private String[] computedOperationalAttributes = null;

    public LdapSchemaTranslator(SchemaManager schemaManager, LdapConfiguration configuration) {
        super(schemaManager, configuration);
    }

    @Override
    protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
                                               org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        super.extendObjectClassDefinition(ocib, ldapObjectClass);

        if (!LdapConfiguration.LOCKOUT_STRATEGY_NONE.equals(getConfiguration().getLockoutStrategy())) {
            AttributeInfoBuilder lockoutAb = new AttributeInfoBuilder(OperationalAttributes.LOCK_OUT_NAME);
            lockoutAb.setType(boolean.class);
//            lockoutAb.setReturnedByDefault(false);
            ocib.addAttributeInfo(lockoutAb.build());
            AttributeInfoBuilder statusAb = new AttributeInfoBuilder(OperationalAttributes.ENABLE_NAME);
            statusAb.setType(boolean.class);
//            lockoutAb.setReturnedByDefault(false);
            ocib.addAttributeInfo(statusAb.build());
        }
    }

    @Override
    public String[] getOperationalAttributes() {
        if (computedOperationalAttributes == null) {
            if (getConfiguration().isOpenLdapLockoutStrategy()) {
                String[] schemaOperationalAttributes = super.getOperationalAttributes();
                computedOperationalAttributes = Arrays.copyOf(schemaOperationalAttributes, schemaOperationalAttributes.length + 1);
                computedOperationalAttributes[schemaOperationalAttributes.length] = SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT;
            } else {
                computedOperationalAttributes = super.getOperationalAttributes();
            }
        }
        return computedOperationalAttributes;
    }

    @Override
    public Class<?> toConnIdType(LdapSyntax syntax, String connIdAttributeName) {
        if (supportsLanguageTag(connIdAttributeName)) {
            return Map.class;
        } else {
            return super.toConnIdType(syntax, connIdAttributeName);
        }
    }

    @Override
    public String toConnIdSubtype(Class<?> connIdType, AttributeType ldapAttribute, String connIdAttributeName) {
        if (supportsLanguageTag(connIdAttributeName)) {
            return POLYSTRING_SUBTYPE;
        } else {
            return super.toConnIdSubtype(connIdType, ldapAttribute, connIdAttributeName);
        }
    }

    private boolean supportsLanguageTag(String connIdAttributeName) {
        if (getConfiguration().getLanguageTagAttributes() == null) {
            return false;
        }
        for (String languageTagAttribute : getConfiguration().getLanguageTagAttributes()) {
            if (connIdAttributeName.equals(languageTagAttribute)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isPolyAttribute(AttributeType ldapAttributeType, String connIdAttributeName, List<Object> values) {
        if (values == null) {
            return false;
        } else if (values.isEmpty()) {
            // We have nothing else to base our decision on.
            return supportsLanguageTag(connIdAttributeName);
        } else if (values.size() > 1) {
            return false;
        } else {
            Object value = values.get(0);
            return value instanceof Map;
        }
    }

    @Override
    public boolean isPolyAttribute(AttributeInfo connIdAttributeInfo) {
        return Map.class.isAssignableFrom(connIdAttributeInfo.getType());
    }

    @Override
    public Map<String, List<Value>> toLdapPolyValues(AttributeType ldapAttributeType, List<Object> connIdValues) {
        Map<String, List<Value>> ldapValueMap = new HashMap<>();
        if (connIdValues.size() > 1) {
            throw new InvalidAttributeValueException("Only single-valued poly attributes are supported (attribute '" + ldapAttributeType.getName() + "')");
        } else if (connIdValues.isEmpty()) {
            return ldapValueMap;
        } else {
            Object connId = connIdValues.get(0);
            if (!(connId instanceof Map)) {
                throw new InvalidAttributeValueException(
                        "Only map-valued poly attributes are supported (attribute '" + ldapAttributeType.getName() + "'), got "
                                + connId.getClass() + " instead");
            }
            //noinspection unchecked
            Map<String, String> connIdValueMap = (Map<String, String>) connId;
            // TODO: check if this is really polystring
            for (Map.Entry<String, String> connIdValueMapEntry : connIdValueMap.entrySet()) {
                String attrName;
                if (connIdValueMapEntry.getKey().equals(POLYSTRING_ORIG_KEY)) {
                    attrName = ldapAttributeType.getName();
                } else {
                    attrName = ldapAttributeType.getName() + ";lang-" + connIdValueMapEntry.getKey();
                }
                List<Value> ldapValues = toLdapValues(ldapAttributeType,
                        Collections.singletonList(connIdValueMapEntry.getValue()));
                ldapValueMap.put(attrName, ldapValues);
            }
            return ldapValueMap;
        }
    }

    @Override
    public AttributeType toLdapAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
                                         String icfAttributeName) {

        if (OperationalAttributes.LOCK_OUT_NAME.equals(icfAttributeName)
                || OperationalAttributes.ENABLE_NAME.equals(icfAttributeName)) {
            if (getConfiguration().isOpenLdapLockoutStrategy()) {
                return super.toLdapAttribute(ldapObjectClass, SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT);
            } else {
                return null;
            }
        }

        return super.toLdapAttribute(ldapObjectClass, icfAttributeName);
    }

    @Override
    protected Attribute toConnIdAttributePoly(String connIdAttributeName, String ldapAttributeNameFromSchema, AttributeType ldapAttributeType,
                                              List<org.apache.directory.api.ldap.model.entry.Attribute> ldapAttributes,
                                              LdapNetworkConnection connection, Entry entry, AttributeHandler attributeHandler) {

        AttributeBuilder ab = new AttributeBuilder();
        ab.setName(connIdAttributeName);

        Map<String, Object> connIdValueMap = new HashMap<>();
        for (org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute : ldapAttributes) {

            String connIdMapKey = determinePolyKey(ldapAttribute);
            if (connIdMapKey == null) {
                continue;
            }

            if (attributeHandler != null) {
                attributeHandler.handle(connection, entry, ldapAttribute, ab);
            }

            if (ldapAttribute.size() == 0) {
                LOG.ok("Empty attribute {0} on {1}", ldapAttribute.getUpId(), entry.getDn());
                continue;
            }

            if (ldapAttribute.size() > 1) {
                if (!getConfiguration().isTolerateMultivalueReduction()) {
                    throw new InvalidAttributeValueException("Multi-valued multi-attributes are not supported, attribute " + ldapAttribute.getUpId() + " on " + entry.getDn());
                } else {
                    LOG.warn("Reducing multiple values of attribute {0} on {1} to a single value", ldapAttribute.getUpId(), entry.getDn());
                    ab.setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
                }
            }

            Value ldapValue = ldapAttribute.get();

            Object connIdValue = toConnIdValue(connIdAttributeName, ldapValue, ldapAttributeNameFromSchema, ldapAttributeType);
            if (connIdValue != null) {
                connIdValueMap.put(connIdMapKey, connIdValue);
            }
        }

        ab.addValue(connIdValueMap);

        try {
            return ab.build();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage() + ", attribute " + connIdAttributeName + " (ldap: " + ldapAttributeNameFromSchema + ")", e);
        }
    }

    @Override
    public String determinePolyKey(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
        String option = getLdapAttributeOption(ldapAttribute);
        if (option != null && !option.startsWith("lang-")) {
            LOG.ok("Unknown option {0} on attribute {1}", option, ldapAttribute.getUpId());
            return null;
        }

        if (option == null) {
            return POLYSTRING_ORIG_KEY;
        } else {
            return option.substring("lang-".length());
        }
    }

    @Override
    protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
        super.extendConnectorObject(cob, entry, objectClassName);

        if (getConfiguration().isOpenLdapLockoutStrategy()) {
            String pwdAccountLockedTime = LdapUtil.getStringAttribute(entry, SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT);
            LOG.ok("Atribute pwdAccountLockedTime = {0}", pwdAccountLockedTime);
            GregorianCalendar cal = new GregorianCalendar();
            if (pwdAccountLockedTime != null && !StringUtils.isEmpty(pwdAccountLockedTime) && (pwdAccountLockedTime.contains(LdapConstants.ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_VALUE) || LdapUtil.getTimestampAttribute(entry, SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT) > cal.getTimeInMillis())) {
                if (pwdAccountLockedTime.contains(LdapConstants.ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_VALUE)) cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.FALSE);
                else cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.TRUE);
                cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.TRUE);
            } else {
                cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.FALSE);
                cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.TRUE);
            }
        }
    }
}
