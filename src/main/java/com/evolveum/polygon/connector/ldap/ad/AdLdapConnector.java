/*
 * Copyright (c) 2015-2020 Evolveum
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

import java.util.*;
import java.util.stream.Collectors;

import com.evolveum.polygon.connector.ldap.*;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaErrorHandler;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.comparators.NormalizingComparator;
import org.apache.directory.api.ldap.model.schema.comparators.StringComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.registries.AttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.MatchingRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ObjectClassRegistry;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.model.schema.registries.SchemaObjectRegistry;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DirectoryStringSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OctetStringSyntaxChecker;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.polygon.connector.ldap.sync.ModifyTimestampSyncStrategy;

import static com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration.CONF_ASSOC_DELIMITER;
import static com.evolveum.polygon.connector.ldap.LdapConstants.*;
import static com.evolveum.polygon.connector.ldap.ad.AdConstants.AD_MEMBERSHIP_ATTRIBUTES;

@ConnectorClass(displayNameKey = "connector.ldap.ad.display", configurationClass = AdLdapConfiguration.class)
public class AdLdapConnector extends AbstractLdapConnector<AdLdapConfiguration> {

    private static final Log LOG = Log.getLog(AdLdapConnector.class);

    private GlobalCatalogConnectionManager globalCatalogConnectionManager;

    @Override
    public void init(Configuration configuration) {
        super.init(configuration);
        globalCatalogConnectionManager = new GlobalCatalogConnectionManager(getConfiguration(), getErrorHandler(), getConnectionLog());
    }

    @Override
    public void dispose() {
        super.dispose();
    }


    @Override
    protected void extraTests() {
        super.extraTests();
    }

    @Override
    protected AbstractSchemaTranslator<AdLdapConfiguration> createSchemaTranslator() {
        return new AdSchemaTranslator(getSchemaManager(), getConfiguration());
    }

    @Override
    protected LdapFilterTranslator<AdLdapConfiguration> createLdapFilterTranslator(ObjectClass ldapObjectClass) {
        return new AdLdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
    }

    @Override
    protected DefaultSchemaManager createBlankSchemaManager(LdapNetworkConnection connection, boolean schemaQuirksMode) throws LdapException {
        if (getConfiguration().isNativeAdSchema()) {
            // Construction of SchemaLoader actually loads all the schemas from server.
            AdSchemaLoader schemaLoader = new AdSchemaLoader(connection);

            if (LOG.isOk()) {
                LOG.ok("AD Schema loader: {0} schemas ({1} enabled)", schemaLoader.getAllSchemas().size(), schemaLoader.getAllEnabled().size());
                for (Schema schema : schemaLoader.getAllSchemas()) {
                    LOG.ok("AD Schema loader: schema {0}: enabled={1}, {2} objects", schema.getSchemaName(), schema.isEnabled(), schema.getContent().size());
                }
            }

            return new AdSchemaManager(schemaLoader);
        } else {
            return super.createBlankSchemaManager(connection, schemaQuirksMode);
        }
    }

    @Override
    protected AdSchemaTranslator getSchemaTranslator() {
        return (AdSchemaTranslator)super.getSchemaTranslator();
    }

    protected SchemaErrorHandler createSchemaErrorHandler() {
        // null by default. This means that a default logging error handler from directory API
        // will be used. May be overridden by subsclasses.
        return new MutedLoggingSchemaErrorHandler();
    }

    @Override
    protected ErrorHandler createErrorHandler() {
        return new AdErrorHandler();
    }

    @Override
    protected boolean isLogSchemaErrors() {
        // There are too many built-in schema errors in AD that this only pollutes the logs
        return false;
    }

    @Override
    public Uid create(org.identityconnectors.framework.common.objects.ObjectClass connIdObjectClass, Set<Attribute> createAttributes, OperationOptions options) {

        if (getConfiguration().isAllowFSPProcessing()) {
            createAttributes = prepareFSPAttributes(createAttributes);

            if (getSchemaTranslator().isFSPObjectClass(connIdObjectClass)) {
                // Return DN as UID instead of GUID here because AD doesn't allow creating FSP directly
                return new Uid(AttributeUtil.getNameFromAttributes(createAttributes).getNameValue());
            }
        }

        return super.create(connIdObjectClass, createAttributes, options);
    }

    private Set<Attribute> prepareFSPAttributes(Set<Attribute> createAttributes) {
        Set<Attribute> newCreateAttributes = new HashSet<>();
        for (Attribute icfAttr: createAttributes) {
            if (icfAttr.is(getConfiguration().getGroupObjectMemberAttribute())) {
                // Convert to <SID=...> format if it contains DN for FSP object
                List<Object> values = icfAttr.getValue().stream()
                        .map(v -> getSchemaTranslator().resolveMemberDn(v.toString()))
                        .collect(Collectors.toList());
                Attribute attr = new AttributeBuilder()
                        .setName(getConfiguration().getGroupObjectMemberAttribute())
                        .addValue(values)
                        .build();
                newCreateAttributes.add(attr);
            } else {
                // all others remain unchanged
                newCreateAttributes.add(icfAttr);
            }
        }
        return newCreateAttributes;
    }

    @Override
    protected Set<Attribute> prepareCreateConnIdAttributes(org.identityconnectors.framework.common.objects.ObjectClass connIdObjectClass,
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
            Set<Attribute> createAttributes) {
        if ((getConfiguration().isRawUserParametersAttribute() && getConfiguration().isRawUserAccountControlAttribute())
                || !getSchemaTranslator().isUserObjectClass(ldapStructuralObjectClass.getName())) {
            return super.prepareCreateConnIdAttributes(connIdObjectClass, ldapStructuralObjectClass, createAttributes);
        }

        Set<Attribute> newCreateAttributes = new HashSet<Attribute>(createAttributes);

        if (!getConfiguration().isRawUserAccountControlAttribute()) {
            newCreateAttributes = prepareCreateUserAccountControllAttributes(newCreateAttributes);
        }
        if (!getConfiguration().isRawUserParametersAttribute()) {
            newCreateAttributes = prepareCreateUserParametersAttributes(newCreateAttributes);
        }

        LOG.ok("New Create attributes after preparing ConnIdAttributes: {0}" , newCreateAttributes);
        return newCreateAttributes;
    }

    private Set<Attribute> prepareCreateUserParametersAttributes(Set<Attribute> createAttributes) {
        AdUserParametersHandler handler = new AdUserParametersHandler();
        boolean foundUpAttr = false;
        Set<Attribute> newCreateAttributes = new HashSet<Attribute>(createAttributes);
        // collect deltas affecting userParameters
        for (Attribute createAttr : createAttributes) {
            String attrName = createAttr.getName();
            if (AdUserParametersHandler.isUserParametersAttribute(attrName) && !createAttr.getValue().isEmpty()) {
                foundUpAttr = true;
                // its possible that another prepare function already added the attribute
                newCreateAttributes.remove(createAttr);
                try {
                    handler.toLdap(attrName, createAttr.getValue().get(0));
                } catch (AdUserParametersHandlerException e) {
                    if (getConfiguration().isUserParametersThrowException()) {
                        throw new InvalidAttributeValueException(
                                "There was an error while preparing Userparameters create attribute " + attrName, e);
                    } else {
                        LOG.warn(
                                "There was an error while parsing Userparameters create attribute. Will not throw an Exception due to configuration.");
                        LOG.ok(e, "The following Exception was thrown while parsing Userparameters:");
                    }
                }
            } else {
                // its possible that another prepare function already ran before so attributes
                // could already be added
                if (!newCreateAttributes.contains(createAttr)) {
                    newCreateAttributes.add(createAttr);
                }
            }
        }
        // finally add userParameters raw attribute
        if (foundUpAttr) {
            Attribute userParameters = AttributeBuilder.build(AdUserParametersHandler.USER_PARAMETERS_LDAP_ATTR_NAME,
                    handler.getUserParameters());
            newCreateAttributes.add(userParameters);
        }
        return newCreateAttributes;
    }

    private Set<Attribute> prepareCreateUserAccountControllAttributes(Set<Attribute> createAttributes) {
        Set<AdConstants.UAC> uacAddSet = new HashSet<>();
        Set<AdConstants.UAC> uacDelSet = new HashSet<>();

        Set<Attribute> newCreateAttributes = new HashSet<Attribute>(createAttributes);

        for (Attribute createAttr : createAttributes) {
            // collect deltas affecting uac. Will be processed below
            String createAttrName = createAttr.getName();
            if (createAttrName.equals(OperationalAttributes.ENABLE_NAME)
                    || AdConstants.UAC.forName(createAttrName) != null) {
                // it's possible that another prepare function already added the attribute
                newCreateAttributes.remove(createAttr);

                // OperationalAttributes.ENABLE_NAME is replaced by
                // dConstants.UAC.ADS_UF_ACCOUNTDISABLE.name()
                AdConstants.UAC uacVal = Enum.valueOf(AdConstants.UAC.class,
                        createAttrName.equals(OperationalAttributes.ENABLE_NAME)
                                ? AdConstants.UAC.ADS_UF_ACCOUNTDISABLE.name()
                                : createAttrName);
                List<Object> values = createAttr.getValue();
                if (values != null && values.size() > 0) {
                    Object val = values.get(0);

                    if (val instanceof Boolean) {
                        // OperationalAttributes.ENABLE_NAME = true means
                        // AdConstants.UAC.ADS_UF_ACCOUNTDISABLE = false
                        if (createAttrName.equals(OperationalAttributes.ENABLE_NAME)) {
                            val = !((Boolean) val);
                        }

                        // value was changed to true
                        if ((Boolean) val) {
                            uacAddSet.add(uacVal);
                        }
                        // value was changed to false
                        else
                            uacDelSet.add(uacVal);
                    }
                }
            }
            // all others remain unchanged
            else {
                // avoid double create entries added by another prepare function before
                if (!newCreateAttributes.contains(createAttr)) {
                    newCreateAttributes.add(createAttr);
                }
            }
        }
        // no uac attributes affected? we cannot return, we have to set at least
        // AdConstants.UAC.ADS_UF_NORMAL_ACCOUNT

        Integer userAccountControl = AdConstants.UAC.ADS_UF_NORMAL_ACCOUNT.getBit();

        // if bit is not set: add it
        for (AdConstants.UAC uac : uacAddSet) {
            if ((userAccountControl & uac.getBit()) == 0) {
                userAccountControl = userAccountControl + uac.getBit();
            }
        }
        // if bit is set: remove it
        for (AdConstants.UAC uac : uacDelSet) {
            if ((userAccountControl & uac.getBit()) != 0) {
                userAccountControl = userAccountControl - uac.getBit();
            }
        }

        // create new attribute for useraccountcontrol, having new value
        Attribute uacAttr = AttributeBuilder.build(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, userAccountControl);
        newCreateAttributes.add(uacAttr);

        return newCreateAttributes;
    }

    @Override
    protected void prepareCreateLdapAttributes(org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass, Entry entry) {
        super.prepareCreateLdapAttributes(ldapStructuralObjectClass, entry);

        // objectCategory
        if (getConfiguration().isAddDefaultObjectCategory()) {
            if (ldapStructuralObjectClass instanceof AdObjectClass) {
                String existingObjectCategory = LdapUtil.getStringAttribute(entry, AdConstants.ATTRIBUTE_OBJECT_CATEGORY_NAME);
                if (existingObjectCategory == null) {
                    String defaultObjectCategory = ((AdObjectClass)ldapStructuralObjectClass).getDefaultObjectCategory();
                    if (defaultObjectCategory == null) {
                        LOG.warn("Requested to add default object class, but there is no default object category definition in object class {0}", ldapStructuralObjectClass.getName());
                    } else {
                        try {
                            entry.add(AdConstants.ATTRIBUTE_OBJECT_CATEGORY_NAME, defaultObjectCategory);
                        } catch (LdapException e) {
                            throw new IllegalStateException("Error adding attribute "+AdConstants.ATTRIBUTE_OBJECT_CATEGORY_NAME+" to entry: "+e.getMessage(), e);
                        }
                    }
                }
            } else {
                LOG.warn("Requested to add default object class, but native AD schema is not available for object class {0}", ldapStructuralObjectClass.getName());
            }
        }
    }

    @Override
    public Set<AttributeDelta> updateDelta(org.identityconnectors.framework.common.objects.ObjectClass connIdObjectClass, Uid uid, Set<AttributeDelta> deltas,
            OperationOptions options) {
        org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = getSchemaTranslator().toLdapObjectClass(connIdObjectClass);
        boolean isUserObjectClass = getSchemaTranslator().isUserObjectClass(ldapObjectClass.getName());

        boolean hasUacPatch = !getConfiguration().isRawUserAccountControlAttribute() && isUserObjectClass && hasUacDelta(deltas);
        boolean hasUpPatch = !getConfiguration().isRawUserParametersAttribute() && isUserObjectClass && hasUpDelta(deltas);

        if (hasUacPatch || hasUpPatch) {
            // we need existing entry since we need to update binary attribute if present
            List<String> attributesToGet = new ArrayList(2);
            if (hasUacPatch) {
                attributesToGet.add(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME);
            }
            if (hasUpPatch) {
                attributesToGet.add(AdUserParametersHandler.USER_PARAMETERS_LDAP_ATTR_NAME);
            }

            Entry existingEntry = getExistingEntry(uid, attributesToGet.toArray(new String[0]));

            if (hasUacPatch) {
                deltas = prepareUacDeltas(uid, deltas, existingEntry);
            }
            if (hasUpPatch) {
                deltas = prepareUpDeltas(uid, deltas, existingEntry);
            }
        }

        if (getConfiguration().isAllowFSPProcessing()) {
            deltas = prepareFSPDeltas(deltas);
        }

        return super.updateDelta(connIdObjectClass, uid, deltas, options);
    }

    private boolean hasUacDelta(Set<AttributeDelta> deltas) {
        return deltas.stream().anyMatch(delta -> {
            String deltaName = delta.getName();
            return delta.is(OperationalAttributes.ENABLE_NAME) || AdConstants.UAC.forName(deltaName) != null;
        });
    }

    private boolean hasUpDelta(Set<AttributeDelta> deltas) {
        return deltas.stream().anyMatch(delta -> {
            String deltaName = delta.getName();
            return AdUserParametersHandler.isUserParametersAttribute(deltaName);
        });
    }

    private Set<AttributeDelta> prepareUpDeltas(Uid uid, Set<AttributeDelta> deltas, Entry existingEntry) {
        AdUserParametersHandler handler = new AdUserParametersHandler();
        boolean foundUpAttr = false;
        Set<AttributeDelta> newDeltas = new HashSet<AttributeDelta>();

        org.apache.directory.api.ldap.model.entry.Attribute upAttribute = existingEntry.get(AdUserParametersHandler.USER_PARAMETERS_LDAP_ATTR_NAME);
        if (upAttribute != null) {
            try {
                handler.setUserParameters(upAttribute.getString());
            } catch (LdapInvalidAttributeValueException e) {
                throw new ConnectorException("The existing userparameters attribute in LDAP is not a string value, it is "
                        + upAttribute.getAttributeType().getName(), e);
            }
        }
        for (AttributeDelta delta : deltas) {
            String deltaName = delta.getName();
            if (AdUserParametersHandler.isUserParametersAttribute(deltaName)) {
                foundUpAttr = true;
                LOG.ok("Applying deltas for userParameters attribute {0}", delta);
                try {
                    if (delta.getValuesToAdd() != null && !delta.getValuesToAdd().isEmpty()) {
                        handler.toLdap(deltaName, delta.getValuesToAdd().get(0));
                    }
                    if (delta.getValuesToReplace() != null) {
                        if (delta.getValuesToReplace().size() > 0) {
                            handler.toLdap(deltaName, delta.getValuesToReplace().get(0));
                        }
                        else {
                            // empty replace here... we interpret it as remove
                            handler.toLdap(deltaName, null);
                        }
                    }
                    if (delta.getValuesToRemove() != null) {
                        handler.toLdap(deltaName, null);
                    }
                } catch (AdUserParametersHandlerException e) {
                    if (getConfiguration().isUserParametersThrowException()) {
                        throw new InvalidAttributeValueException("There was an error while preparing Userparameters delta " + deltaName
                                + " of user with UID " + uid, e);
                    }
                    else {
                        LOG.warn(
                                "There was an error while preparing Userparameters delta. Will not throw an Exception due to configuration.");
                        LOG.ok(e, "The following Exception was thrown while preparing Userparameters delta:");
                    }
                }
            }
            //all others remain unchanged
            else {
                newDeltas.add(delta);
            }
        }

        //create new delta for userParameters, having new value
        String userParametersUpdated = handler.getUserParameters();
        if (userParametersUpdated != null && foundUpAttr) {
            AttributeDelta uacAttrDelta = AttributeDeltaBuilder.build(AdUserParametersHandler.USER_PARAMETERS_LDAP_ATTR_NAME, userParametersUpdated);
            newDeltas.add(uacAttrDelta);
        }

        return newDeltas;

    }

    private Entry getExistingEntry(Uid uid, String[] attributesToGet) {
        final String uidValue = SchemaUtil.getSingleStringNonBlankValue(uid);
        Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
        Dn hintDn = guidDn;

        if (getConfiguration().useMultiDomain()) {
            if (uid.getNameHintValue() == null) {
                throw new ConnectorException(
                        "Can not search for existing entry with null name-hint-value, because you use multi-domain");
            }
            try {
                hintDn = new Dn(uid.getNameHintValue());
            } catch (LdapInvalidDnException e) {
                throw new InvalidAttributeValueException(
                        "Cannot create DN from nameHint: " + uid.getNameHintValue() + ", of uid: " + uid);
            }
        }


        Entry existingEntry = searchSingleEntry(
                getConnectionManager(),
                null,
                guidDn,
                null,
                SearchScope.OBJECT,
                attributesToGet,
                "pre-read of entry values for binary attributes",
                hintDn,
                null);
        LOG.ok("Pre-read entry for binary attributes:\n{0}", existingEntry);

        if (existingEntry == null) {
            throw new UnknownUidException("Cannot pre-read of entry for attribute binary attributes: " + uid);
        }
        return existingEntry;
    }

    private Set<AttributeDelta> prepareUacDeltas(Uid uid, Set<AttributeDelta> deltas, Entry existingEntry)  {

        Set<AdConstants.UAC> uacAddSet = new HashSet<AdConstants.UAC>();
        Set<AdConstants.UAC> uacDelSet = new HashSet<AdConstants.UAC>();

        Set<AttributeDelta> newDeltas = new HashSet<AttributeDelta>();

        for (AttributeDelta delta : deltas) {
            //collect deltas affecting uac. Will be processed below
            String deltaName = delta.getName();
            //if (deltaName.equals(OperationalAttributes.ENABLE_NAME) || Enum.valueOf(AdConstants.UAC.class, deltaName) != null) {
            if (deltaName.equals(OperationalAttributes.ENABLE_NAME) || AdConstants.UAC.forName(deltaName) != null) {
                //OperationalAttributes.ENABLE_NAME is replaced by dConstants.UAC.ADS_UF_ACCOUNTDISABLE.name()
                AdConstants.UAC uacVal = Enum.valueOf(AdConstants.UAC.class, deltaName.equals(OperationalAttributes.ENABLE_NAME)? AdConstants.UAC.ADS_UF_ACCOUNTDISABLE.name() : deltaName);
                List<Object> valuesToReplace = delta.getValuesToReplace();
                if (valuesToReplace != null && valuesToReplace.size() >0) {
                    Object val = valuesToReplace.get(0);

                    if (val instanceof Boolean) {
                        //OperationalAttributes.ENABLE_NAME = true means AdConstants.UAC.ADS_UF_ACCOUNTDISABLE = false
                        if (deltaName.equals(OperationalAttributes.ENABLE_NAME)) {
                            if ((Boolean)val) {
                                val = Boolean.valueOf(false);
                            }
                            else {
                                val = Boolean.valueOf(true);
                            }
                        }

                        //value was changed to true
                        if ((Boolean)val) {
                            uacAddSet.add(uacVal);
                        }
                        //value was changed to false
                        else {
                            uacDelSet.add(uacVal);
                        }
                    }
                }
            }
            //all others remain unchanged
            else {
                newDeltas.add(delta);
            }
        }
        //no uac attributes affected: return original deltas
        if (uacDelSet.isEmpty() && uacAddSet.isEmpty()) {
            return deltas;
        }
        // We need original value
        Integer userAccountControl = LdapUtil.getIntegerAttribute(existingEntry, AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, null);

        //if bit is not set: add it
        for (AdConstants.UAC uac : uacAddSet) {
            if ((userAccountControl & uac.getBit()) == 0) {
                userAccountControl = userAccountControl + uac.getBit();
            }
        }
        //if bit is set: remove it
        for (AdConstants.UAC uac : uacDelSet) {
            if ((userAccountControl & uac.getBit()) != 0) {
                userAccountControl = userAccountControl - uac.getBit();
            }
        }

        //create new delta for useraccountcontrol, having new value
        AttributeDelta uacAttrDelta = AttributeDeltaBuilder.build(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, userAccountControl);
        newDeltas.add(uacAttrDelta);

        return newDeltas;
    }

    private Set<AttributeDelta> prepareFSPDeltas(Set<AttributeDelta> deltas) {
        Set<AttributeDelta> newDeltas = new HashSet<>();
        for (AttributeDelta delta : deltas) {
            if (delta.is(getConfiguration().getGroupObjectMemberAttribute()) && delta.getValuesToAdd() != null) {
                // Convert to <SID=...> format if it contains DN for FSP object
                List<Object> values = delta.getValuesToAdd().stream()
                        .map(v -> getSchemaTranslator().resolveMemberDn(v.toString()))
                        .collect(Collectors.toList());
                AttributeDelta newDelta = new AttributeDeltaBuilder()
                        .setName(getConfiguration().getGroupObjectMemberAttribute())
                        .addValueToAdd(values)
                        .build();
                newDeltas.add(newDelta);
            } else {
                // all others remain unchanged
                newDeltas.add(delta);
            }
        }
        return newDeltas;
    }

    @Override
    protected void addAttributeModification(Dn dn, List<Modification> modifications, ObjectClass ldapStructuralObjectClass,
            org.identityconnectors.framework.common.objects.ObjectClass icfObjectClass, AttributeDelta delta) {
        Rdn firstRdn = dn.getRdns().get(0);
        String firstRdnAttrName = firstRdn.getAva().getType();
        AttributeType modAttributeType = getSchemaTranslator().toLdapAttribute(ldapStructuralObjectClass, delta.getName());
        if (firstRdnAttrName.equalsIgnoreCase(modAttributeType.getName())) {
            // Ignore this modification. It is already done by the rename operation.
            // Attempting to do it will result in an error.
            return;
        } else {
            super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, icfObjectClass, delta);
        }
    }
// TODO # A port similar to LDAP connector ?
    @Override
    protected SearchStrategy<AdLdapConfiguration> chooseSearchStrategy(org.identityconnectors.framework.common.objects.ObjectClass objectClass,
            ObjectClass ldapObjectClass, ResultsHandler handler, OperationOptions options) {
        SearchStrategy<AdLdapConfiguration> searchStrategy = super.chooseSearchStrategy(objectClass, ldapObjectClass, handler, options);
        searchStrategy.setAttributeHandler(new AdAttributeHandler(searchStrategy, getSchemaTranslator(), objectClass, options));
        // TODO # A
        //searchStrategy.setAttributeHandler(new AdAttributeHandler(searchStrategy));
        return searchStrategy;
    }

    @Override
    protected SearchStrategy<AdLdapConfiguration> getDefaultSearchStrategy(org.identityconnectors.framework.common.objects.ObjectClass objectClass,
            ObjectClass ldapObjectClass, ResultsHandler handler, OperationOptions options) {
        SearchStrategy<AdLdapConfiguration> searchStrategy =  super.getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
        return searchStrategy;

    }

    @Override
    protected SearchStrategy<AdLdapConfiguration> searchByUid(Uid uid, org.identityconnectors.framework.common.objects.ObjectClass objectClass,
            ObjectClass ldapObjectClass, final ResultsHandler handler, OperationOptions options) {
        final String uidValue = SchemaUtil.getSingleStringNonBlankValue(uid);


        // Trivial (but not really realistic) case: UID is DN
        // Also, when the FSP object is first created, the UID is a DN, so it needs to be handled specially
        if (LdapUtil.isDnAttribute(getConfiguration().getUidAttribute()) || getSchemaTranslator().isFSPDn(uid.getUidValue())) {

            return searchByDn(getSchemaTranslator().toDn(uidValue), objectClass, ldapObjectClass, handler, options);

        }

        if (uid.getNameHint() != null) {

            // First attempt: name hint, GUID search (last seen DN)

            // Name hint is the last DN that we have seen for this object. However, the object may have
            // been renamed or may have moved. Therefore use the name hint just to select the connection.
            // Once we have the connection then forget name hint and use GUID DN to get the entry.
            // This is the most efficient and still very reliable way to get the entry.

            Dn nameHintDn = getSchemaTranslator().toDn(uid.getNameHint());
            SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
            LdapNetworkConnection connection = getConnectionManager().getConnection(nameHintDn, options);
            searchStrategy.setExplicitConnection(connection);

            Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
            String[] attributesToGet = determineAttributesToGet(ldapObjectClass, options);
            try {
                searchStrategy.search(guidDn, applyAdditionalSearchFilterNode(null), SearchScope.OBJECT, attributesToGet);
            } catch (LdapException e) {
                throw processLdapException("Error searching for DN '"+guidDn+"'", e);
            }

            if (searchStrategy.getNumberOfEntriesFound() > 0) {
                return searchStrategy;
            }
        }

        // Second attempt: global catalog

        if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_NONE.equals(getConfiguration().getGlobalCatalogStrategy())) {
            // Make search with <GUID=....> baseDn on default connection. Rely on referrals to point our head to
            // the correct domain controller in multi-domain environment.
            // We know that this can return at most one object. Therefore always use simple search.
            SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
            String[] attributesToGet = determineAttributesToGet(ldapObjectClass, options);
            Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
            try {
                searchStrategy.search(guidDn, applyAdditionalSearchFilterNode(LdapUtil.createAllSearchFilter()), SearchScope.OBJECT, attributesToGet);
            } catch (LdapException e) {
                throw processLdapException("Error searching for GUID '"+uidValue+"'", e);
            }

            if (searchStrategy.getNumberOfEntriesFound() > 0) {
                return searchStrategy;
            }

        } else if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_READ.equals(getConfiguration().getGlobalCatalogStrategy())) {
            // Make a search directly to the global catalog server. Present that as final result.
            // We know that this can return at most one object. Therefore always use simple search.
            SearchStrategy<AdLdapConfiguration> searchStrategy = new DefaultSearchStrategy<>(globalCatalogConnectionManager,
                    getConfiguration(), getSchemaTranslator(), objectClass, ldapObjectClass, handler, getErrorHandler(), getConnectionLog(), options);
            String[] attributesToGet = determineAttributesToGet(ldapObjectClass, options);
            Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
            try {
                searchStrategy.search(guidDn, applyAdditionalSearchFilterNode(LdapUtil.createAllSearchFilter()), SearchScope.OBJECT, attributesToGet);
            } catch (LdapException e) {
                throw processLdapException("Error searching for GUID '"+uidValue+"'", e);
            }

            if (searchStrategy.getNumberOfEntriesFound() > 0) {
                return searchStrategy;
            }

        } else if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_RESOLVE.equals(getConfiguration().getGlobalCatalogStrategy())) {
            Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
            Entry entry = searchSingleEntry(globalCatalogConnectionManager, guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT,
                    new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "global catalog entry for GUID "+uidValue, options);
            if (entry == null) {
                throw new UnknownUidException("Entry for GUID "+uidValue+" was not found in global catalog");
            }
            LOG.ok("Resolved GUID {0} in glogbal catalog to DN {1}", uidValue, entry.getDn());
            Dn dn = entry.getDn();

            SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
            // We need to force the use of explicit connection here. The search is still using the <GUID=..> dn
            // The search strategy cannot use that to select a connection. So we need to select a connection
            // based on the DN returned from global catalog explicitly.
            // We also cannot use the DN from the global catalog as the base DN for the search.
            // The global catalog may not be replicated yet and it may not have the correct DN
            // (e.g. the case of quick read after rename)
            LdapNetworkConnection connection = getConnectionManager().getConnection(dn, options);
            searchStrategy.setExplicitConnection(connection);

            String[] attributesToGet = determineAttributesToGet(ldapObjectClass, options);
            try {
                searchStrategy.search(guidDn, applyAdditionalSearchFilterNode(null), SearchScope.OBJECT, attributesToGet);
            } catch (LdapException e) {
                throw processLdapException("Error searching for DN '"+guidDn+"'", e);
            }

            if (searchStrategy.getNumberOfEntriesFound() > 0) {
                return searchStrategy;
            }

        } else {
            throw new IllegalStateException("Unknown global catalog strategy '"+getConfiguration().getGlobalCatalogStrategy()+"'");
        }

        // Third attempt: brutal search over all the servers

        if (getConfiguration().isAllowBruteForceSearch()) {
            LOG.ok("Cannot find object with GUID {0} by using name hint or global catalog. Resorting to brute-force search",
                    uidValue);
            Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
            String[] attributesToGet = determineAttributesToGet(ldapObjectClass, options);
            return getConnectionManager().brutalSearch(connection -> {
                SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
                searchStrategy.setExplicitConnection(connection);

                try {
                    searchStrategy.search(guidDn, applyAdditionalSearchFilterNode(null), SearchScope.OBJECT, attributesToGet);
                } catch (LdapException e) {
                    throw processLdapException("Error searching for DN '"+guidDn+"'", e);
                }

                if (searchStrategy.getNumberOfEntriesFound() > 0) {
                    return searchStrategy;
                } else {
                    return null;
                }
            });


        } else {
            LOG.ok("Cannot find object with GUID {0} by using name hint or global catalog. Brute-force search is disabled. Found nothing.",
                    uidValue);
        }

        // Found nothing
        return null;

    }

    @Override
    protected Dn resolveDn(org.identityconnectors.framework.common.objects.ObjectClass objectClass, Uid uid, OperationOptions options) {

        String guid = uid.getUidValue();

        if (uid.getNameHint() != null) {
            // Try to use name hint to select the correct server, but still search by GUID. The entry might
            // have been renamed since we looked last time and the name hint may be out of date. But it is
            // likely that it is still OK for selecting correct server.
            // Global catalog updates are quite lazy. Looking at global catalog can get even worse results
            // than name hint.

            String dnHintString = uid.getNameHintValue();
            Dn dnHint = getSchemaTranslator().toDn(dnHintString);
            LOG.ok("Resolvig DN by using name hint {0} and guid", dnHint, guid);

            Dn guidDn = getSchemaTranslator().getGuidDn(guid);

            LOG.ok("Resolvig DN by search for {0} (no global catalog)", guidDn);
            Entry entry = searchSingleEntry(getConnectionManager(), null, guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT,
                    new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+guid, dnHint, options);

            if (entry != null) {
                    return entry.getDn();
            } else {
                LOG.ok("Resolvig DN for name hint {0} returned no object", dnHintString);
            }
        }

        Dn guidDn = getSchemaTranslator().getGuidDn(guid);

        if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_NONE.equals(getConfiguration().getGlobalCatalogStrategy())) {
            LOG.ok("Resolvig DN by search for {0} (no global catalog)", guidDn);
            Entry entry = searchSingleEntry(getConnectionManager(), guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT,
                    new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+guid, options);
            if (entry == null) {
                throw new UnknownUidException("Entry for GUID "+guid+" was not found");
            }
            return entry.getDn();

        } else {
            LOG.ok("Resolvig DN by search for {0} (global catalog)", guidDn);
            Entry entry = searchSingleEntry(globalCatalogConnectionManager, guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT,
                    new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+guid, options);
            if (entry == null) {
                throw new UnknownUidException("Entry for GUID "+guid+" was not found in global catalog");
            }
            LOG.ok("Resolved GUID {0} in glogbal catalog to DN {1}", guid, entry.getDn());
            return entry.getDn();
        }
    }

    @Override
    protected void postUpdate(org.identityconnectors.framework.common.objects.ObjectClass connIdObjectClass,
            Uid uid, Set<AttributeDelta> deltas, OperationOptions options,
            Dn dn, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
            List<Modification> ldapModifications) {
        super.postUpdate(connIdObjectClass, uid, deltas, options, dn, ldapStructuralObjectClass, ldapModifications);

        AttributeDelta forcePasswordChangeDelta = SchemaUtil.findDelta(deltas, OperationalAttributes.FORCE_PASSWORD_CHANGE_NAME);
        if (forcePasswordChangeDelta != null) {
            Boolean forcePasswordChangeValue = SchemaUtil.getSingleReplaceValue(forcePasswordChangeDelta, Boolean.class);
            // This may not be entirely correct: TODO review & test later
            if (forcePasswordChangeValue != null && forcePasswordChangeValue) {
                List<Modification> modificationsPwdLastSet = new ArrayList<Modification>();
                AttributeDelta attrPwdLastSetDelta = AttributeDeltaBuilder.build(AdConstants.ATTRIBUTE_PWD_LAST_SET_NAME, "0");
                addAttributeModification(dn, modificationsPwdLastSet, ldapStructuralObjectClass, connIdObjectClass, attrPwdLastSetDelta);
                modify(dn, modificationsPwdLastSet, options);
            }
        } else if (getConfiguration().isForcePasswordChangeAtNextLogon() && isUserPasswordChanged(deltas, ldapStructuralObjectClass)) {
            List<Modification> modificationsPwdLastSet = new ArrayList<Modification>();
            AttributeDelta attrPwdLastSetDelta = AttributeDeltaBuilder.build(AdConstants.ATTRIBUTE_PWD_LAST_SET_NAME, "0");
            addAttributeModification(dn, modificationsPwdLastSet, ldapStructuralObjectClass, connIdObjectClass, attrPwdLastSetDelta);
            modify(dn, modificationsPwdLastSet, options);
        }
    }

    private boolean isUserPasswordChanged(Set<AttributeDelta> deltas, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass) {
        //if password is in modifications set pwdLastSet=0 ("must change password at next logon")
        if (getSchemaTranslator().isUserObjectClass(ldapStructuralObjectClass.getName())) {
            for (AttributeDelta delta: deltas) {
                // coming from midpoint password is __PASSWORD__
                // TODO: should we additionally ask for  icfAttr.getName().equals(getConfiguration().getPasswordAttribute()?
                if (OperationalAttributeInfos.PASSWORD.is(delta.getName())) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    protected RuntimeException processModifyResult(Dn dn, List<Modification> modifications, ModifyResponse modifyResponse) {
        ResultCodeEnum resultCode = modifyResponse.getLdapResult().getResultCode();
        if (ResultCodeEnum.CONSTRAINT_VIOLATION.equals(resultCode)) {
            if (modifyResponse.getLdapResult().getDiagnosticMessage().contains(getConfiguration().getPasswordAttribute())) {
                // This is in fact password policy error, e.g. attempt to set the same password as current password
                InvalidAttributeValueException e = new InvalidAttributeValueException("Error modifying LDAP entry "+dn+": "+LdapUtil.formatLdapMessage(modifyResponse.getLdapResult()));
                e.setAffectedAttributeNames(Collections.singleton(OperationalAttributes.PASSWORD_NAME));
                throw e;
            }
        }
        return super.processModifyResult(dn, modifications, modifyResponse);
    }

    @Override
    protected void patchSchemaManager(SchemaManager schemaManager) {
        super.patchSchemaManager(schemaManager);
        if (!getConfiguration().isTweakSchema()) {
            return;
        }

        Registries registries = schemaManager.getRegistries();
        MatchingRuleRegistry matchingRuleRegistry = registries.getMatchingRuleRegistry();


        MatchingRule mrCaseIgnoreMatch = matchingRuleRegistry.get(SchemaConstants.CASE_IGNORE_MATCH_MR_OID);
        // Microsoft ignores matching rules. Completely. There is not even a single definition.
        if (mrCaseIgnoreMatch == null) {
            MatchingRule correctMrCaseIgnoreMatch = new MatchingRule(SchemaConstants.CASE_IGNORE_MATCH_MR_OID);
            correctMrCaseIgnoreMatch.setSyntaxOid(SchemaConstants.DIRECTORY_STRING_SYNTAX);
            Normalizer normalizer = new DeepTrimToLowerNormalizer(SchemaConstants.CASE_IGNORE_MATCH_MR_OID);
            correctMrCaseIgnoreMatch.setNormalizer(normalizer);
            LdapComparator<?> comparator = new NormalizingComparator(correctMrCaseIgnoreMatch.getOid(), normalizer,
                new StringComparator(correctMrCaseIgnoreMatch.getOid()));
            correctMrCaseIgnoreMatch.setLdapComparator(comparator);
            mrCaseIgnoreMatch = correctMrCaseIgnoreMatch;
            register(matchingRuleRegistry, correctMrCaseIgnoreMatch);
        }

        // Microsoft violates RFC4519
        fixAttribute(schemaManager, SchemaConstants.CN_AT_OID, SchemaConstants.CN_AT,
                createStringSyntax(SchemaConstants.DIRECTORY_STRING_SYNTAX), mrCaseIgnoreMatch, false);
        fixAttribute(schemaManager, SchemaConstants.DOMAIN_COMPONENT_AT_OID, SchemaConstants.DC_AT,
                createStringSyntax(SchemaConstants.DIRECTORY_STRING_SYNTAX), mrCaseIgnoreMatch, false);
        fixAttribute(schemaManager, SchemaConstants.OU_AT_OID, SchemaConstants.OU_AT,
                createStringSyntax(SchemaConstants.DIRECTORY_STRING_SYNTAX), mrCaseIgnoreMatch, false);

        // unicodePwd is not detected as binary, but it should be
        fixAttribute(schemaManager, AdConstants.ATTRIBUTE_UNICODE_PWD_OID, AdConstants.ATTRIBUTE_UNICODE_PWD_NAME,
                createBinarySyntax(SchemaConstants.OCTET_STRING_SYNTAX), null, true);
    }

    private LdapSyntax createStringSyntax(String syntaxOid) {
        LdapSyntax syntax = new LdapSyntax(syntaxOid);
        syntax.setHumanReadable(true);
        syntax.setSyntaxChecker(DirectoryStringSyntaxChecker.INSTANCE);
        return syntax;
    }

    private LdapSyntax createBinarySyntax(String syntaxOid) {
        LdapSyntax syntax = new LdapSyntax(syntaxOid);
        syntax.setHumanReadable(false);
        syntax.setSyntaxChecker(OctetStringSyntaxChecker.INSTANCE);
        return syntax;
    }

    private void fixAttribute(SchemaManager schemaManager, String attrOid, String attrName,
            LdapSyntax syntax, MatchingRule equalityMr, boolean force) {
        Registries registries = schemaManager.getRegistries();
        AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();
        ObjectClassRegistry objectClassRegistry = registries.getObjectClassRegistry();

        AttributeType existingAttrType = attributeTypeRegistry.get(attrOid);
        if (force || existingAttrType == null || existingAttrType.getEquality() == null) {
            AttributeType correctAttrType;
            if (existingAttrType != null) {
                try {
                    attributeTypeRegistry.unregister(existingAttrType);
                } catch (LdapException e) {
                    throw new IllegalStateException("Error unregistering "+existingAttrType+": "+e.getMessage(), e);
                }
                correctAttrType = new AttributeType(existingAttrType.getOid());
                correctAttrType.setNames(existingAttrType.getNames());
            } else {
                correctAttrType = new AttributeType(attrOid);
                correctAttrType.setNames(attrName);
            }

            correctAttrType.setSyntax(syntax);
            if (equalityMr != null) {
                correctAttrType.setEquality(equalityMr);
            }
            correctAttrType.setSingleValued(true);
            LOG.ok("Registering replacement attributeType: {0}", correctAttrType);
            register(attributeTypeRegistry, correctAttrType);
            fixObjectClasses(objectClassRegistry, existingAttrType, correctAttrType);
        }

    }

    private void fixObjectClasses(ObjectClassRegistry objectClassRegistry, AttributeType oldAttributeType, AttributeType newAttributeType) {
        for (ObjectClass objectClass: objectClassRegistry) {
            fixOblectClassAttributes(objectClass.getMayAttributeTypes(), oldAttributeType, newAttributeType);
            fixOblectClassAttributes(objectClass.getMustAttributeTypes(), oldAttributeType, newAttributeType);
        }

    }

    private void fixOblectClassAttributes(List<AttributeType> attributeTypes, AttributeType oldAttributeType, AttributeType newAttributeType) {
        for (int i = 0; i < attributeTypes.size(); i++) {
            AttributeType current = attributeTypes.get(i);
            if (current.equals(oldAttributeType)) {
                attributeTypes.set(i, newAttributeType);
                break;
            }
        }
    }

    private <T extends SchemaObject> void register(SchemaObjectRegistry<T> registry, T object) {
        try {
            registry.register(object);
        } catch (LdapException e) {
            throw new IllegalStateException("Error registering "+object+": "+e.getMessage(), e);
        }
    }


    @Override
    protected ModifyTimestampSyncStrategy<AdLdapConfiguration> createModifyTimestampSyncStrategy() {
        return new ModifyTimestampSyncStrategy<>(getConfiguration(), getConnectionManager(), getSchemaManager(), getSchemaTranslator(), getErrorHandler(), true);
    }

    @Override
    protected void addServerSpecificConfigurationSuggestions(Map<String, SuggestedValues> suggestions) {

        // TODO # A remove log
        LOG.ok("Fetching ser spec suggestions");
        analyzeReferenceSuggestions(suggestions, getConfiguration());
    }

    private void analyzeReferenceSuggestions(Map<String, SuggestedValues> suggestions,
                                             AdLdapConfiguration configuration) {

        List<String> referenceSuggestions = new ArrayList();
        String groupObjectClassName = configuration.getGroupObjectClass();
        String userObjectClassName = configuration.getUserObjectClass();

        if ((groupObjectClassName != null && !groupObjectClassName.isEmpty()) &&
                (userObjectClassName != null && !userObjectClassName.isEmpty())) {

            //TODO # A remove
//            referenceSuggestions.add("\"" + ATTRIBUTE_MEMBER_OF_NAME + "\"+" + groupObjectClassName +
//                    " -> " + "\"" + AD_MEMBERSHIP_ATTRIBUTES.get(groupObjectClassName) + "\"+"
//                    + groupObjectClassName);
//
//            referenceSuggestions.add("\"" + ATTRIBUTE_MEMBER_OF_NAME + "\"+" + userObjectClassName +
//                    " -> " + "\"" + AD_MEMBERSHIP_ATTRIBUTES.get(groupObjectClassName) + "\"+"
//                    + groupObjectClassName);

            referenceSuggestions.add("\"" + groupObjectClassName + "\"+" + ATTRIBUTE_MEMBER_OF_NAME +
                    " "+CONF_ASSOC_DELIMITER+" " + "\"" + groupObjectClassName + "\"+"
                    + AD_MEMBERSHIP_ATTRIBUTES.get(groupObjectClassName));

            referenceSuggestions.add("\"" + userObjectClassName + "\"+" + ATTRIBUTE_MEMBER_OF_NAME +
                    " "+CONF_ASSOC_DELIMITER+" " + "\"" + groupObjectClassName + "\"+"
                    + AD_MEMBERSHIP_ATTRIBUTES.get(groupObjectClassName));

            suggestions.put(AbstractLdapConfiguration.CONF_PROP_MNGD_ASSOC_PAIRS,
                    SuggestedValuesBuilder.buildOpen(referenceSuggestions.toArray(new String[referenceSuggestions.size()])));
        }
    }
}
