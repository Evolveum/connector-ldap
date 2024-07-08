/*
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

package com.evolveum.polygon.connector.ldap;

import java.util.*;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.SuggestedValues;
import org.identityconnectors.framework.common.objects.SuggestedValuesBuilder;
import org.identityconnectors.framework.common.objects.ValueListOpenness;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

import static com.evolveum.polygon.connector.ldap.LdapConstants.OBJECT_CLASS_GROUP_OF_NAMES;

@ConnectorClass(displayNameKey = "connector.ldap.display", configurationClass = LdapConfiguration.class)
public class LdapConnector extends AbstractLdapConnector<LdapConfiguration> {

    private static final Log LOG = Log.getLog(LdapConnector.class);

    @Override
    protected AbstractSchemaTranslator<LdapConfiguration> createSchemaTranslator() {
        return new LdapSchemaTranslator(getSchemaManager(), getConfiguration());
    }

    @Override
    protected ErrorHandler createErrorHandler() {
        return new ErrorHandler();
    }

    @Override
    protected void addServerSpecificConfigurationSuggestions(Map<String, SuggestedValues> suggestions) {
        if (isServerOpenLdap()) {
            addOpenLdapConfigurationSuggestions(suggestions);
        }
        if (isServerOpenDj()) {
            addOpenDjConfigurationSuggestions(suggestions);
        }
    }

    private boolean isServerOpenLdap() {
        Attribute rootDseObjectClass = getConnectionManager().getRootDseAttribute(SchemaConstants.OBJECT_CLASS_AT);
        return LdapUtil.anyValueContainsSubstring(rootDseObjectClass,"OpenLDAP");
    }

    private void addOpenLdapConfigurationSuggestions(Map<String, SuggestedValues> suggestions) {
        suggestions.put(AbstractLdapConfiguration.CONF_PROP_NAME_USE_PERMISSIVE_MODIFY,
                SuggestedValuesBuilder.build(AbstractLdapConfiguration.USE_PERMISSIVE_MODIFY_ALWAYS));

        suggestions.put(AbstractLdapConfiguration.PASSWORD_HASH_ALGORITHM_SSHA,
                SuggestedValuesBuilder.buildOpen(AbstractLdapConfiguration.PASSWORD_HASH_ALGORITHM_SSHA));

        suggestions.put(AbstractLdapConfiguration.CONF_PROP_NAME_VLV_SORT_ATTRIBUTE,
                SuggestedValuesBuilder.buildOpen(SchemaConstants.UID_AT));
        suggestions.put(AbstractLdapConfiguration.CONF_PROP_NAME_VLV_SORT_ORDERING_RULE,
                SuggestedValuesBuilder.buildOpen(SchemaConstants.CASE_IGNORE_ORDERING_MATCH_MR_OID));

        suggestions.put(AbstractLdapConfiguration.CONF_PROP_NAME_OPERATIONAL_ATTRIBUTES,
                SuggestedValuesBuilder.buildOpen(LdapConstants.ATTRIBUTE_MEMBER_OF_NAME,
                        SchemaConstants.CREATE_TIMESTAMP_AT, SchemaConstants.MODIFY_TIMESTAMP_AT));

        suggestions.put(LdapConfiguration.CONF_PROP_NAME_LOCKOUT_STRATEGY,
                SuggestedValuesBuilder.build(LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP));

        analyzeReferenceSuggestions(getSchemaManager(), getConfiguration(), suggestions);
    }

    private void analyzeReferenceSuggestions(SchemaManager schemaManager, LdapConfiguration configuration,
                                             Map<String, SuggestedValues> suggestions) {
        // TODO port to Server Specific

        String[] groupObjectClasses = configuration.getGroupObjectClasses();

        List<String> referenceSuggestions = new ArrayList<String>();

        for (String groupObjectClassName : groupObjectClasses) {

            if (schemaManager.getObjectClassRegistry().contains(groupObjectClassName)) {
                for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass : schemaManager.getObjectClassRegistry()) {
                    String oClassName = ldapObjectClass.getName();

                    referenceSuggestions.add(oClassName + " -> " + groupObjectClassName);
                    //TODO expand based on supported group objects
                    //TODO remove log

                    LOG.ok("Reference Suggestion constructed: {0}", oClassName + " -> " + groupObjectClassName);
                }
            }

        }
        referenceSuggestions.size();
        suggestions.put(AbstractLdapConfiguration.CONF_PROP_MNGD_ASSOC_PAIRS,
                SuggestedValuesBuilder.buildOpen(referenceSuggestions.toArray(new String[referenceSuggestions.size()])));
    }

    private boolean isServerOpenDj() {
        Attribute rootDseVendor = getConnectionManager().getRootDseAttribute(SchemaConstants.VENDOR_VERSION_AT);
        return LdapUtil.anyValueContainsSubstring(rootDseVendor,"OpenDJ");
    }

    private void addOpenDjConfigurationSuggestions(Map<String, SuggestedValues> suggestions) {
        suggestions.put(AbstractLdapConfiguration.CONF_PROP_NAME_VLV_SORT_ATTRIBUTE,
                SuggestedValuesBuilder.buildOpen(SchemaConstants.UID_AT));

        suggestions.put(AbstractLdapConfiguration.CONF_PROP_NAME_OPERATIONAL_ATTRIBUTES,
                SuggestedValuesBuilder.buildOpen(LdapConstants.ATTRIBUTE_IS_MEMBER_OF_NAME,
                        LdapConstants.ATTRIBUTE_OPENDJ_DS_PWP_ACCOUNT_DISABLED_NAME,
                        SchemaConstants.CREATE_TIMESTAMP_AT, SchemaConstants.MODIFY_TIMESTAMP_AT));
    }

    @Override
    protected void addAttributeModification(Dn dn, List<Modification> modifications,
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
            ObjectClass icfObjectClass, AttributeDelta delta) {

        if (delta.is(OperationalAttributes.LOCK_OUT_NAME)
                && LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP.equals(getConfiguration().getLockoutStrategy())) {
            Boolean value = SchemaUtil.getSingleReplaceValue(delta, Boolean.class);
            // null value is OK, no valued means default which is "unlocked"
            if (value != null && value) {
                throw new UnsupportedOperationException("Locking object is not supported (only unlocking is)");
            }
            modifications.add(
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT)); // no value
        } else if (delta.is(OperationalAttributes.ENABLE_NAME)
                && LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP.equals(getConfiguration().getLockoutStrategy())) {
            Boolean value = SchemaUtil.getSingleReplaceValue(delta, Boolean.class);
            if (value != null && !value) {
                modifications.add(
                        new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT, LdapConstants.ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_VALUE)); // 000001010000Z
            } else {
                modifications.add(
                        new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, SchemaConstants.PWD_ACCOUNT_LOCKED_TIME_AT)); // no value
            }

        } else {
            super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, icfObjectClass, delta);
        }
    }



}
