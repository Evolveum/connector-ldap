/**
 * Copyright (c) 2014-2019 Evolveum
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
package com.evolveum.polygon.connector.ldap.schema;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.function.Predicate;

import com.evolveum.polygon.connector.ldap.*;
import com.evolveum.polygon.connector.ldap.connection.ConnectionManager;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;

import com.evolveum.polygon.common.SchemaUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration.CONF_ASSOC_ATTR_DELIMITER;
import static com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration.CONF_ASSOC_DELIMITER;
import static com.evolveum.polygon.connector.ldap.LdapConstants.*;

/**
 * @author semancik
 *
 */
public abstract class AbstractSchemaTranslator<C extends AbstractLdapConfiguration> {

    private static final Log LOG = Log.getLog(AbstractSchemaTranslator.class);
    private static final Collection<String> STRING_ATTRIBUTE_NAMES = new ArrayList<>();
    private static final Map<String, TypeSubType> SYNTAX_MAP = new HashMap<>();
    private static final Logger log = LoggerFactory.getLogger(AbstractSchemaTranslator.class);
    private static final String SCHEMA_PLACEHOLVER_REMOVE = "#remove#";

    private SchemaManager schemaManager;
    private C configuration;
    private Schema connIdSchema = null;
    private Map<String, Set<AssociationHolder>> objectAssociationSets = null;
    private Map<String, Set<AssociationHolder>> subjectAssociationSets = null;

    public AbstractSchemaTranslator(SchemaManager schemaManager, C configuration) {
        super();
        this.schemaManager = schemaManager;
        this.configuration = configuration;
    }

    public Schema getConnIdSchema() {
        return connIdSchema;
    }

    public SchemaManager getSchemaManager() {
        return schemaManager;
    }

    public C getConfiguration() {
        return configuration;
    }

    @SuppressWarnings("unchecked")
    public Schema translateSchema(ConnectionManager<C> connectionManager, ErrorHandler errorHandler) {
        SchemaBuilder schemaBuilder = new SchemaBuilder(LdapConnector.class);
        LOG.ok("Translating LDAP schema from {0}", schemaManager);

        for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass: schemaManager.getObjectClassRegistry()) {
            if (shouldTranslateObjectClass(ldapObjectClass.getName())) {
                LOG.ok("Found LDAP schema object class {0}, translating", ldapObjectClass.getName());
                ObjectClassInfoBuilder ocib = new ObjectClassInfoBuilder();
                ocib.setType(toIcfObjectClassType(ldapObjectClass));
                Map<String, AttributeInfo> attrInfoList = new HashMap<>();
                addAttributeTypes(attrInfoList, ldapObjectClass);
                ocib.addAllAttributeInfo(attrInfoList.values());

                if (ldapObjectClass.isAuxiliary()) {
                    ocib.setAuxiliary(true);
                }

                extendObjectClassDefinition(ocib, ldapObjectClass);
                schemaBuilder.defineObjectClass(ocib.build());
            } else {
                LOG.ok("Found LDAP schema object class {0}, skipping", ldapObjectClass.getName());
            }
        }

        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class, SyncOp.class);
        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class, SyncOp.class);
        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAllowPartialResults(), SearchOp.class);
        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildContainer(), SearchOp.class);
        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildScope(), SearchOp.class);

        if (!AbstractLdapConfiguration.RUN_AS_STRATEGY_NONE.equals(configuration.getRunAsStrategy())) {
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildRunWithUser());
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildRunWithPassword());
        }

        List<String> supportedControls;
        try {
            supportedControls = connectionManager.getSupportedControls();
        } catch (ConnectionFailedException e) {
            // This should not really happen.
            // We should have root DSE fetched already, therefore this operation
            // should only read the information from memory.
            throw e;
        }
        if (supportedControls.contains(PagedResults.OID) || supportedControls.contains(VirtualListViewRequest.OID)) {
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildPageSize(), SearchOp.class);
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildPagedResultsCookie(), SearchOp.class);
        }
        if (supportedControls.contains(VirtualListViewRequest.OID)) {
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildPagedResultsOffset(), SearchOp.class);
        }
        if (supportedControls.contains(SortRequest.OID)) {
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildSortKeys(), SearchOp.class);
        }

        connIdSchema = schemaBuilder.build();
        LOG.ok("Translated schema {0}", connIdSchema);
        return connIdSchema;
    }

    protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        // Nothing to do. Expected to be overridden in subclasses.
    }

    protected boolean shouldTranslateObjectClass(String ldapObjectClassName) {
        return true;
    }

    protected String toIcfObjectClassType(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        return ldapObjectClass.getName();
    }

    protected String toLdapObjectClassName(ObjectClass icfObjectClass) {
        return icfObjectClass.getObjectClassValue();
    }

    /**
     * Make sure that we have icfSchema
     */
    public void prepareConnIdSchema(ConnectionManager<C> connectionManager, ErrorHandler errorHandler) {
        if (connIdSchema == null) {
            translateSchema(connectionManager, errorHandler);
        }
    }

    private void addAttributeTypes(Map<String, AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {

        // ICF UID
        String uidAttribudeLdapName = configuration.getUidAttribute();
        Boolean areAssociationsManaged = !ArrayUtils.isEmpty(configuration.getManagedAssociationPairs());
        AttributeInfoBuilder uidAib = new AttributeInfoBuilder(Uid.NAME);
        uidAib.setNativeName(uidAttribudeLdapName);
        uidAib.setRequired(false); // Must be optional. It is not present for create operations
        AttributeType uidAttributeLdapType = null;

        try {
            uidAttributeLdapType = schemaManager.lookupAttributeTypeRegistry(uidAttribudeLdapName);
        } catch (LdapException e) {
            // We can live with this
            LOG.ok("Got exception looking up UID atribute {0}: {1} ({2}) (probabably harmless)", uidAttribudeLdapName,
                    e.getMessage(), e.getClass());
        }

        // UID must be string. It is hardcoded in the framework.
        uidAib.setType(String.class);

        if (uidAttributeLdapType != null) {
            uidAib.setSubtype(toConnIdSubtype(String.class, uidAttributeLdapType, Uid.NAME));
            setAttributeMultiplicityAndPermissions(uidAttributeLdapType, Uid.NAME, uidAib);
        } else {
            uidAib.setCreateable(false);
            uidAib.setUpdateable(false);
            uidAib.setReadable(true);
        }

        AttributeInfo attributeInfo = uidAib.build();
        attrInfoList.put(attributeInfo.getName(), attributeInfo);

        // ICF NAME
        AttributeInfoBuilder nameAib = new AttributeInfoBuilder(Name.NAME);
        nameAib.setType(String.class);
        nameAib.setNativeName(LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME);
        nameAib.setSubtype(AttributeInfo.Subtypes.STRING_LDAP_DN);
        nameAib.setRequired(true);
        attributeInfo = nameAib.build();
        attrInfoList.put(attributeInfo.getName(), attributeInfo);

        // AUXILIARY_OBJECT_CLASS
        attrInfoList.put(PredefinedAttributeInfos.AUXILIARY_OBJECT_CLASS.getName(), PredefinedAttributeInfos.AUXILIARY_OBJECT_CLASS);

        if(areAssociationsManaged){

            addReferences(attrInfoList, ldapObjectClass);
        }
        addAttributeTypesFromLdapSchema(attrInfoList, ldapObjectClass);
        addExtraOperationalAttributes(attrInfoList);

        if(areAssociationsManaged){
        scrapeOriginalMembershipAttrs(attrInfoList);
        }
    }

    private void occupyOriginalMembershipAttrs(Map<String, AttributeInfo> attrInfoList, String name) {

        //adds some place holders into the "key" portion of the map, limiting complex operation,
        // we will remove this later

        attrInfoList.put(name, new AttributeInfoBuilder(name).setNativeName(SCHEMA_PLACEHOLVER_REMOVE).build());
        attrInfoList.values().forEach(v ->v.getNativeName());
    }

    private void scrapeOriginalMembershipAttrs(Map<String, AttributeInfo> attrInfoList) {

        //This will remove the placeholders from the map, (lets use the structure we have generated for association pairs)

        attrInfoList.entrySet().removeIf(entry -> (SCHEMA_PLACEHOLVER_REMOVE.equals(entry.getValue().getNativeName())));
    }

    private void addReferences(Map<String, AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        Set<AssociationHolder> associationHolders = saturateAssociationHolders(ldapObjectClass);

        if (associationHolders != null && !associationHolders.isEmpty()) {
        } else {
            return;
        }

        for (AssociationHolder associationHolder : associationHolders) {

            occupyOriginalMembershipAttrs(attrInfoList, associationHolder.getAssociationAttributeName());

            AttributeInfoBuilder attributeInfoBuilder = new AttributeInfoBuilder(associationHolder.getName(),
                    ConnectorObjectReference.class);

            AttributeType attributeType = null;

            try {
                attributeType = schemaManager.lookupAttributeTypeRegistry(associationHolder.
                        getAssociationAttributeName());
            } catch (LdapException e) {
                // Ignore.
            }

            // TODO # A have this based on the original schema or make it static ?

            if(attributeType!=null){
                /// TODO # A Evaluate if original membership attribute is amongst operational, in that case other options may apply
            setAttributeMultiplicityAndPermissions(attributeType, associationHolder.getAssociationAttributeName(),
                    attributeInfoBuilder);
            } else {

                attributeInfoBuilder.setCreateable(false);
                attributeInfoBuilder.setUpdateable(false);
                attributeInfoBuilder.setReadable(true);
                attributeInfoBuilder.setMultiValued(true);
                // TODO #A test
                attributeInfoBuilder.setReturnedByDefault(false);
            }

            if(R_I_R_SUBJECT.equals(associationHolder.getRoleInReference())){

// TODO # A have this based on the original schema or make it static ?
                attributeInfoBuilder.setCreateable(true);
                attributeInfoBuilder.setUpdateable(true);
                attributeInfoBuilder.setReadable(true);
                attributeInfoBuilder.setMultiValued(true);
                attributeInfoBuilder.setRoleInReference(associationHolder.getRoleInReference());
// TODO # A END, the rest, in regards to the "Subject" references should be kept.
                attributeInfoBuilder.setRequired(associationHolder.isRequired());
                attributeInfoBuilder.setReturnedByDefault(true);
                attributeInfoBuilder.setSubtype(associationHolder.getSubtype());
            } else {
                attributeInfoBuilder.setRoleInReference(associationHolder.getRoleInReference());
                attributeInfoBuilder.setRequired(associationHolder.isRequired());
                attributeInfoBuilder.setSubtype(associationHolder.getSubtype());
                attributeInfoBuilder.setReturnedByDefault(false);
            }

            AttributeInfo ai = attributeInfoBuilder.build();
            attrInfoList.put(ai.getName(), ai);
        }
    }

    private Set<AssociationHolder> saturateAssociationHolders(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {

        Set<AssociationHolder> associationHolders = new HashSet<>();
        String currentOcName = ldapObjectClass.getName();
        List<AttributeType> mustAttributeTypes = ldapObjectClass.getMustAttributeTypes();

        if (getSubjectAssociationSets() != null && getSubjectAssociationSets()
                .containsKey(currentOcName)) {


            // TODO #A test trace log, remove
            LOG.ok("Association holder being generated for {0}, the subject set is being generated.", currentOcName);

            Set<AssociationHolder> associationSet = subjectAssociationSets.get(currentOcName);
            for (AssociationHolder holder : associationSet) {

                // TODO #A test trace log, remove
                LOG.ok("Association holder being generated for {0}, the subject set is being generated." +
                        " Native membership attribute {1}",currentOcName, holder.getAssociationAttributeName());

                holder.setRequired(mustAttributeTypes.stream().anyMatch(x -> Objects.equals(x.getName(),
                        holder.getAssociationAttributeName())));
                associationHolders.add(holder);
            }
        }

        if (getObjectAssociationSets() != null && getObjectAssociationSets()
                .containsKey(currentOcName)) {

            // TODO #A test trace log, remove
            LOG.ok("Association holder being generated for {0}, the object set is being generated.", currentOcName );

            Set<AssociationHolder> associationSet = objectAssociationSets.get(currentOcName);

            for (AssociationHolder holder : associationSet) {

                LOG.ok("Association holder being generated for {0}, the object set is being generated." +
                        " using the attribute {1} for target reference parameter data ", currentOcName ,holder.getAssociationAttributeName());

                holder.setRequired(mustAttributeTypes.stream().anyMatch(x -> Objects.equals(x.getName(),
                        holder.getAssociationAttributeName())));
                associationHolders.add(holder);
            }
        }

        return associationHolders;
    }

    private void addExtraOperationalAttributes(Map<String, AttributeInfo> attrInfoList) {
        for (String operationalAttributeLdapName: configuration.getOperationalAttributes()) {
            if (containsAttribute(attrInfoList, operationalAttributeLdapName)) {
                continue;
            }
            AttributeInfoBuilder aib = new AttributeInfoBuilder(operationalAttributeLdapName);
            aib.setRequired(false);
            aib.setNativeName(operationalAttributeLdapName);

            AttributeType attributeType = null;
            try {
                attributeType = schemaManager.lookupAttributeTypeRegistry(operationalAttributeLdapName);
            } catch (LdapException e) {
                // Ignore. We want this attribute even if it is not in the LDAP schema
            }

            if (attributeType != null) {
                LdapSyntax ldapSyntax = getSyntax(attributeType);
                Class<?> icfType = toConnIdType(ldapSyntax, operationalAttributeLdapName);
                aib.setType(icfType);
                aib.setSubtype(toConnIdSubtype(icfType, attributeType, operationalAttributeLdapName));
                LOG.ok("Translating {0} -> {1} ({2} -> {3}) (operational)", operationalAttributeLdapName, operationalAttributeLdapName,
                        ldapSyntax==null?null:ldapSyntax.getOid(), icfType);
                setAttributeMultiplicityAndPermissions(attributeType, operationalAttributeLdapName, aib);
            } else {
                LOG.ok("Translating {0} -> {1} ({2} -> {3}) (operational, not defined in schema)", operationalAttributeLdapName, operationalAttributeLdapName,
                        null, String.class);
                aib.setType(String.class);
                aib.setMultiValued(false);
            }
            aib.setReturnedByDefault(false);

            AttributeInfo attributeInfo = aib.build();
            attrInfoList.put(attributeInfo.getName(), attributeInfo);
        }

    }

    private void addAttributeTypesFromLdapSchema(Map<String, AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        LOG.ok("  ... translating attributes from {0}:\n{1}\nMUST\n{2}", ldapObjectClass.getName(), ldapObjectClass, ldapObjectClass.getMustAttributeTypes());
        addAttributeTypes(attrInfoList, ldapObjectClass.getMustAttributeTypes(), true);
        LOG.ok("  ... translating attributes from {0}:\n{1}\nMAY\n{2}", ldapObjectClass.getName(), ldapObjectClass, ldapObjectClass.getMayAttributeTypes());
        addAttributeTypes(attrInfoList, ldapObjectClass.getMayAttributeTypes(), false);

        List<org.apache.directory.api.ldap.model.schema.ObjectClass> superiors = ldapObjectClass.getSuperiors();
        if ((superiors != null) && (superiors.size() > 0)) {
            for (org.apache.directory.api.ldap.model.schema.ObjectClass superior: superiors) {
                addAttributeTypesFromLdapSchema(attrInfoList, superior);
            }
        }
    }

    private void addAttributeTypes(Map<String, AttributeInfo> attrInfoList, List<AttributeType> attributeTypes, boolean isRequired) {
        for (AttributeType ldapAttribute: attributeTypes) {

            if (!shouldTranslateAttribute(ldapAttribute.getName())) {
                LOG.ok("Skipping translation of attribute {0} because it should not be translated", ldapAttribute.getName());
                continue;
            }

            // Compare the name *or* the OID (the name may be null)
            if ((SchemaConstants.OBJECT_CLASS_AT.equalsIgnoreCase( ldapAttribute.getName()))
                || SchemaConstants.OBJECT_CLASS_AT_OID.equals( ldapAttribute.getOid() )) {
                continue;
            }
            if (ldapAttribute.getName().equalsIgnoreCase(getConfiguration().getUidAttribute())) {
                // This is handled separately as __UID__ attribute
                continue;
            }
            String connIdAttributeName = toConnIdAttributeName(ldapAttribute.getName());
            if (containsAttribute(attrInfoList, connIdAttributeName)) {
                LOG.ok("Skipping translation of attribute {0} because it is already translated", ldapAttribute.getName());
                continue;
            }
            AttributeInfoBuilder aib = new AttributeInfoBuilder(connIdAttributeName);
            aib.setRequired(isRequired);

            LdapSyntax ldapSyntax = getSyntax(ldapAttribute);
            if (ldapSyntax == null) {
                LOG.warn("No syntax for attribute: {0}", ldapAttribute.getName());
            }

            Class<?> connIdType = toConnIdType(ldapSyntax, connIdAttributeName);
            aib.setType(connIdType);
            aib.setSubtype(toConnIdSubtype(connIdType, ldapAttribute, connIdAttributeName));
            aib.setNativeName(ldapAttribute.getName());
            if (isOperational(ldapAttribute)) {
                aib.setReturnedByDefault(false);
            }
            setAttributeMultiplicityAndPermissions(ldapAttribute, connIdAttributeName, aib);
            LOG.ok("Translating {0} -> {1} ({2} -> {3})", ldapAttribute.getName(), connIdAttributeName,
                    ldapSyntax==null?null:ldapSyntax.getOid(), connIdType);
            AttributeInfo attributeInfo = aib.build();
            attrInfoList.put(attributeInfo.getName(), attributeInfo);
        }
    }

    protected boolean isOperational(AttributeType ldapAttribute) {
        if (ldapAttribute.isOperational()) {
            return true;
        }
        return isConfiguredAsOperational(ldapAttribute.getName());
    }

    protected boolean isConfiguredAsOperational(String ldapAttributeName) {
        // Note: attributeName is raw name from resource, it may have wild letter case.
        // However, we stick to case-sensitive comparison by default. This may be overridden in subclasses (e.g. AD).
        return ArrayUtils.contains(getOperationalAttributes(), ldapAttributeName);
    }

    protected void setAttributeMultiplicityAndPermissions(AttributeType ldapAttributeType, String icfAttributeName, AttributeInfoBuilder aib) {
        if (ldapAttributeType.isSingleValued()) {
            aib.setMultiValued(false);
        } else {
            aib.setMultiValued(true);
        }
        if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
            switch (configuration.getPasswordReadStrategy()) {
                case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_READABLE:
                case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_INCOMPLETE_READ:
                    aib.setReadable(true);
                    break;
                case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_UNREADABLE:
                    aib.setReturnedByDefault(false);
                    aib.setReadable(false);
                    break;
                default:
                    throw new ConfigurationException("Unknown passoword read strategy "+configuration.getPasswordReadStrategy());
            }
        } else {
            aib.setReadable(true);
        }
        if (!ldapAttributeType.isUserModifiable()) {
            aib.setCreateable(false);
            aib.setUpdateable(false);
        } else {
            aib.setCreateable(true);
            aib.setUpdateable(true);
        }
    }

    private boolean containsAttribute(Map<String, AttributeInfo> attrInfoList, String icfAttributeName) {
        return attrInfoList.containsKey( icfAttributeName );
    }

    private String toConnIdAttributeName(String ldapAttributeName) {
        if (ldapAttributeName.equalsIgnoreCase(configuration.getPasswordAttribute())) {
            return OperationalAttributeInfos.PASSWORD.getName();
        }
        return ldapAttributeName;
    }

    public org.apache.directory.api.ldap.model.schema.ObjectClass toLdapObjectClass(ObjectClass icfObjectClass) {
        String ldapObjectClassName = toLdapObjectClassName(icfObjectClass);
        try {
            return schemaManager.lookupObjectClassRegistry(ldapObjectClassName);
        } catch (LdapException e) {
            throw new IllegalArgumentException("Unknown object class "+icfObjectClass+": "+e.getMessage(), e);
        }
    }

    /**
     * Throws exception if the attribute is illegal.
     * Return null if the attribute is legal, but we do not have any definition for it.
     */
    public AttributeType toLdapAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, String connIdAttributeName) {
        if (Name.NAME.equals(connIdAttributeName)) {
            return null;
        }
        String ldapAttributeName;
        if (Uid.NAME.equals(connIdAttributeName)) {
            ldapAttributeName = configuration.getUidAttribute();
        } else if (OperationalAttributeInfos.PASSWORD.is(connIdAttributeName)) {
            ldapAttributeName = configuration.getPasswordAttribute();
        } else {
            ldapAttributeName = connIdAttributeName;
        }
        if (isVirtualAttribute(connIdAttributeName)) {
            return null;
        }
        try {
            AttributeType attributeType = schemaManager.getAttributeTypeRegistry().lookup(ldapAttributeName);
            if (attributeType == null) {
                if (allowAttributeWithoutDefinition(ldapAttributeName)) {
                    // Create fake attribute type
                    attributeType = createFauxAttributeType(ldapAttributeName);
                } else {
                    throw new IllegalArgumentException("Unknown LDAP attribute " + ldapAttributeName + " (translated from ConnId attribute " + connIdAttributeName + ")");
                }
            }
            return attributeType;
        } catch (LdapNoSuchAttributeException e) {
            if (allowAttributeWithoutDefinition(ldapAttributeName)) {
                // Create fake attribute type
                return createFauxAttributeType(ldapAttributeName);
            } else {
                throw new IllegalArgumentException("Unknown LDAP attribute " + ldapAttributeName + " (translated from ConnId attribute "+connIdAttributeName+"): " + e.getMessage(), e);
            }
        } catch (LdapException e) {
            throw new IllegalArgumentException("Error translating LDAP attribute " + ldapAttributeName + " (translated from ConnId attribute "+connIdAttributeName+"): " + e.getMessage(), e);
        }
    }

    protected boolean isVirtualAttribute(String connIdAttributeName) {
        return false;
    }

    private boolean allowAttributeWithoutDefinition(String ldapAttributeName) {
        return isConfiguredAsOperational(ldapAttributeName)  || configuration.isAllowUnknownAttributes();
    }

    public AttributeType createFauxAttributeType(String attributeName) {
        AttributeType mutableLdapAttributeType = new AttributeType(attributeName);
        mutableLdapAttributeType.setNames(attributeName);
        mutableLdapAttributeType.setSyntaxOid(SchemaConstants.DIRECTORY_STRING_SYNTAX);
        return mutableLdapAttributeType;
    }

    public Class<?> toConnIdType(LdapSyntax syntax, String connIdAttributeName) {
        if (OperationalAttributeInfos.PASSWORD.is(connIdAttributeName)) {
            return GuardedString.class;
        }
        if (syntax == null) {
            // We may be in a quirks mode. Server schema may not be consistent (e.g. 389ds schema).
            // Therefore syntax may be null. Fall back to default in that case.
            return String.class;
        }
        Class<?> type = null;
        TypeSubType typeSubtype = SYNTAX_MAP.get( syntax.getName() );

        if (typeSubtype != null) {
            type = typeSubtype.type;
            if (type == ZonedDateTime.class) {
                switch (getConfiguration().getTimestampPresentation()) {
                    case AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_NATIVE:
                        type = ZonedDateTime.class;
                        break;
                    case AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_UNIX_EPOCH:
                        type = long.class;
                        break;
                    case AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_STRING:
                        type = String.class;
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown value of timestampPresentation: "+getConfiguration().getTimestampPresentation());
                }
            }
        }

        if (type == null) {
            LOG.warn("No type mapping for syntax {0}, using string", syntax.getName());
            return String.class;
        } else {
            return type;
        }
    }

    public String toConnIdSubtype(Class<?> connIdType, AttributeType ldapAttribute, String connIdAttributeName) {
        if (OperationalAttributeInfos.PASSWORD.is(connIdAttributeName)) {
            return null;
        }
        if (ldapAttribute == null) {
            return null;
        }
        if (hasEqualityMatching(ldapAttribute, SchemaConstants.CASE_IGNORE_MATCH_MR, SchemaConstants.CASE_IGNORE_MATCH_MR_OID)) {
            return AttributeInfo.Subtypes.STRING_CASE_IGNORE.toString();
        }
        if (hasEqualityMatching(ldapAttribute, SchemaConstants.CASE_IGNORE_IA5_MATCH_MR, SchemaConstants.CASE_IGNORE_IA5_MATCH_MR_OID)) {
            return AttributeInfo.Subtypes.STRING_CASE_IGNORE.toString();
        }
        if (hasEqualityMatching(ldapAttribute, SchemaConstants.UUID_MATCH_MR, SchemaConstants.UUID_MATCH_MR_OID)) {
            return AttributeInfo.Subtypes.STRING_UUID.toString();
        }
        String syntaxOid = ldapAttribute.getSyntaxOid();
        if (syntaxOid == null) {
            return null;
        }
        if (SYNTAX_MAP.get(syntaxOid) == null) {
            if (connIdType == String.class) {
                return AttributeInfo.Subtypes.STRING_CASE_IGNORE.toString();
            } else {
                return null;
            }
        }
        return SYNTAX_MAP.get(syntaxOid).subtype;
    }

    private boolean hasEqualityMatching(AttributeType ldapAttribute, String matchingRuleName,
            String matchingRuleOid) {
        if (ldapAttribute == null) {
            return false;
        }
        if (ldapAttribute.getEquality() != null && matchingRuleOid.equalsIgnoreCase(ldapAttribute.getEquality().getOid())) {
            return true;
        }
        if (matchingRuleOid.equalsIgnoreCase(ldapAttribute.getEqualityOid())) {
            return true;
        }
        if (matchingRuleName.equalsIgnoreCase(ldapAttribute.getEqualityName())) {
            return true;
        }
        if (ldapAttribute.getSuperior() != null) {
            if (hasEqualityMatching(ldapAttribute.getSuperior(), matchingRuleName, matchingRuleOid)) {
                return true;
            }
        }
        return false;
    }

    public boolean isPolyAttribute(AttributeType ldapAttributeType, String connIdAttributeName, List<Object> connIdValues) {
        return false;
    }

    public boolean isPolyAttribute(AttributeInfo connIdAttributeInfo) {
        return false;
    }

    public List<Value> toLdapValues(AttributeType ldapAttributeType, List<Object> icfAttributeValues) {
        List<Value> ldapValues = new ArrayList<>(icfAttributeValues.size());
        for (Object icfValue: icfAttributeValues) {
            ldapValues.add(toLdapValue(ldapAttributeType, icfValue));
        }
        return ldapValues;
    }

    /**
     * Method to convert "poly" values, such as PolyString.
     *
     * @return map with attribute name as a key (with option) and list of values as value.
     */
    public Map<String, List<Value>> toLdapPolyValues(AttributeType ldapAttributeType, List<Object> values) {
        throw new UnsupportedOperationException("Poly-attributes are not supported (attribute '"+ldapAttributeType.getName()+"'");
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Value toLdapValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
        if (icfAttributeValue == null) {
            return null;
        }
        if (ldapAttributeType == null) {
            // We have no definition for this attribute. Assume string.
            return new Value(icfAttributeValue.toString());
        }

        if (ldapAttributeType.getName().equalsIgnoreCase(configuration.getPasswordAttribute())) {
            return toLdapPasswordValue(ldapAttributeType, icfAttributeValue);
        }

        return wrapInLdapValueClass(ldapAttributeType, icfAttributeValue);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    protected Value wrapInLdapValueClass(AttributeType ldapAttributeType, Object connIdAttributeValue) {
        String syntaxOid = ldapAttributeType.getSyntaxOid();
        if (isTimeSyntax(syntaxOid)) {
            if (connIdAttributeValue instanceof Long) {
                try {
                    return new Value(ldapAttributeType, LdapUtil.toGeneralizedTime((Long)connIdAttributeValue, acceptsFractionalGeneralizedTime()));
                } catch (LdapInvalidAttributeValueException e) {
                    throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                        +"; attributeType="+ldapAttributeType, e);
                }
            } else if (connIdAttributeValue instanceof ZonedDateTime) {
                try {
                    return new Value(ldapAttributeType, LdapUtil.toGeneralizedTime((ZonedDateTime)connIdAttributeValue, acceptsFractionalGeneralizedTime()));
                } catch (LdapInvalidAttributeValueException e) {
                    throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                        +"; attributeType="+ldapAttributeType, e);
                }
            } else if (connIdAttributeValue instanceof String) {
                try {
                        return new Value(ldapAttributeType, connIdAttributeValue.toString());
                    } catch (LdapInvalidAttributeValueException e) {
                        throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                                +"; attributeType="+ldapAttributeType, e);
                    }
            } else {
                throw new InvalidAttributeValueException("Wrong type for attribute "+ldapAttributeType+": "+connIdAttributeValue.getClass());
            }
        } else if (connIdAttributeValue instanceof Boolean) {
            LOG.ok("Converting to LDAP: {0} ({1}): boolean", ldapAttributeType.getName(), syntaxOid);
            try {
                return new Value(ldapAttributeType, connIdAttributeValue.toString().toUpperCase());
            } catch (LdapInvalidAttributeValueException e) {
                throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                        +"; attributeType="+ldapAttributeType, e);
            }
        } else if (connIdAttributeValue instanceof GuardedString) {
            try {
                return new GuardedStringValue(ldapAttributeType, (GuardedString) connIdAttributeValue);
            } catch (LdapInvalidAttributeValueException e) {
                throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                        +"; attributeType="+ldapAttributeType, e);
            }
        } else if (isBinarySyntax(syntaxOid)) {
            LOG.ok("Converting to LDAP: {0} ({1}): explicit binary", ldapAttributeType.getName(), syntaxOid);

            if (connIdAttributeValue instanceof byte[]) {
                // Do NOT set attributeType in the Value in this case.
                // The attributeType might not match the Value class
                // e.g. human-readable jpegPhoto attribute will expect StringValue
                return new Value((byte[])connIdAttributeValue);
            } else if (connIdAttributeValue instanceof String) {
                // this can happen for userPassword
                byte[] bytes;
                try {
                    bytes = ((String)connIdAttributeValue).getBytes("UTF-8");
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalArgumentException("Cannot encode attribute value to UTF-8 for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                            +"; attributeType="+ldapAttributeType, e);
                }
                // Do NOT set attributeType in the Value in this case.
                // The attributeType might not match the Value class
                // e.g. human-readable jpegPhoto attribute will expect StringValue
                return new Value(bytes);
            } else {
                throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": expected byte[] but got "+connIdAttributeValue.getClass()
                        +"; attributeType="+ldapAttributeType);
            }
        } else if (!isBinarySyntax(syntaxOid)) {
            LOG.ok("Converting to LDAP: {0} ({1}): explicit string", ldapAttributeType.getName(), syntaxOid);
            try {
                return new Value(ldapAttributeType, connIdAttributeValue.toString());
            } catch (LdapInvalidAttributeValueException e) {
                throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                        +"; attributeType="+ldapAttributeType, e);
            }
        } else {
            if (connIdAttributeValue instanceof byte[]) {
                LOG.ok("Converting to LDAP: {0} ({1}): detected binary", ldapAttributeType.getName(), syntaxOid);
                try {
                    return new Value(ldapAttributeType, (byte[])connIdAttributeValue);
                } catch (LdapInvalidAttributeValueException e) {
                    throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                            +"; attributeType="+ldapAttributeType, e);
                }
            } else {
                LOG.ok("Converting to LDAP: {0} ({1}): detected string", ldapAttributeType.getName(), syntaxOid);
                try {
                    return new Value(ldapAttributeType, connIdAttributeValue.toString());
                } catch (LdapInvalidAttributeValueException e) {
                    throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                            +"; attributeType="+ldapAttributeType, e);
                }
            }
        }
    }

    protected Value toLdapPasswordValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
        if (configuration.getPasswordHashAlgorithm() != null
                && !LdapConfiguration.PASSWORD_HASH_ALGORITHM_NONE.equals(configuration.getPasswordHashAlgorithm())) {
            icfAttributeValue = hashLdapPassword(icfAttributeValue);
        }
        return wrapInLdapValueClass(ldapAttributeType, icfAttributeValue);
    }

    protected boolean acceptsFractionalGeneralizedTime() {
        return true;
    }

    /**
     * Used to parse __UID__ and __NAME__.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Value toLdapIdentifierValue(AttributeType ldapAttributeType, String icfAttributeValue) {
        if (icfAttributeValue == null) {
            return null;
        }
        if (ldapAttributeType == null) {
            // We have no definition for this attribute. Assume string.
            return new Value(icfAttributeValue);
        }

        String syntaxOid = ldapAttributeType.getSyntaxOid();
        if (isBinarySyntax(syntaxOid)) {
            // Expect hex-encoded value (see toIcfIdentifierValue())
            byte[] bytes = LdapUtil.hexToBinary(icfAttributeValue);
            // Do NOT set attributeType in the Value in this case.
            // The attributeType might not match the Value class
            return new Value(bytes);
        } else {
            try {
                return new Value(ldapAttributeType, icfAttributeValue);
            } catch (LdapInvalidAttributeValueException e) {
                throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
                        +"; attributeType="+ldapAttributeType, e);
            }
        }
    }

    public Value toLdapValue(AttributeType ldapAttributeType, List<Object> icfAttributeValues) {
        if (icfAttributeValues == null || icfAttributeValues.isEmpty()) {
            return null;
        }
        if (icfAttributeValues.size() > 1) {
            throw new IllegalArgumentException("More than one value specified for LDAP attribute "+ldapAttributeType.getName());
        }
        return toLdapValue(ldapAttributeType, icfAttributeValues.get(0));
    }

    protected Object toConnIdValue(String connIdAttributeName, Value ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
        if (ldapValue == null) {
            return null;
        }
        if (OperationalAttributeInfos.PASSWORD.is(connIdAttributeName)) {
            return new GuardedString(ldapValue.getString().toCharArray());
        } else {
            String syntaxOid = null;
            if (ldapAttributeType != null) {
                syntaxOid = ldapAttributeType.getSyntaxOid();
            }
            if (isTimeSyntax(syntaxOid)) {
                switch (getConfiguration().getTimestampPresentation()) {
                    case AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_NATIVE:
                        try {
                            return LdapUtil.generalizedTimeStringToZonedDateTime(ldapValue.getString());
                        } catch (ParseException e) {
                            throw new InvalidAttributeValueException("Wrong generalized time format in LDAP attribute "+ldapAttributeName+": "+e.getMessage(), e);
                        }
                    case AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_UNIX_EPOCH:
                        try {
                            GeneralizedTime gt = new GeneralizedTime(ldapValue.getString());
                            return gt.getCalendar().getTimeInMillis();
                        } catch (ParseException e) {
                            throw new InvalidAttributeValueException("Wrong generalized time format in LDAP attribute "+ldapAttributeName+": "+e.getMessage(), e);
                        }
                    case AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_STRING:
                        return ldapValue.getString();
                    default:
                        throw new IllegalArgumentException("Unknown value of timestampPresentation: "+getConfiguration().getTimestampPresentation());
                }
            } else if (isBooleanSyntax(syntaxOid)) {
                return Boolean.parseBoolean(ldapValue.getString());
            } else if (isIntegerSyntax(syntaxOid)) {
                return new BigInteger(ldapValue.getString());
            } else if (isJavaIntSyntax(syntaxOid)) {
                return Integer.parseInt(ldapValue.getString());
            } else if (isJavaLongSyntax(syntaxOid)) {
                return Long.parseLong(ldapValue.getString());
            } else if (isBinarySyntax(syntaxOid)) {
                LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): explicit binary", ldapAttributeName, syntaxOid, ldapValue.getClass());
                return ldapValue.getBytes();
            } else if (isStringSyntax(syntaxOid)) {
                LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): explicit string", ldapAttributeName, syntaxOid, ldapValue.getClass());
                return ldapValue.getString();
            } else {
                if (ldapValue.isHumanReadable()) {
                    LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): detected string", ldapAttributeName, syntaxOid, ldapValue.getClass());
                    return ldapValue.getString();
                } else {
                    LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): detected binary", ldapAttributeName, syntaxOid, ldapValue.getClass());
                    return ldapValue.getBytes();
                }
            }
        }
    }

    protected boolean isIntegerSyntax(String syntaxOid) {
        return isSyntaxOfClass(syntaxOid, BigInteger.class);
    }

    protected boolean isJavaIntSyntax(String syntaxOid) {
        return isSyntaxOfClass(syntaxOid, int.class);
    }

    protected boolean isJavaLongSyntax(String syntaxOid) {
        return isSyntaxOfClass(syntaxOid, long.class);
    }

    protected boolean isTimeSyntax(String syntaxOid) {
        return isSyntaxOfClass(syntaxOid, ZonedDateTime.class);
    }

    protected boolean isBooleanSyntax(String syntaxOid) {
        return isSyntaxOfClass(syntaxOid, Boolean.class);
    }

    private boolean isSyntaxOfClass(String syntaxOid, Class clazz) {
        TypeSubType typeSubType = SYNTAX_MAP.get(syntaxOid);
        if (typeSubType == null) {
            return false;
        }
        return clazz.equals(typeSubType.type);
    }

    /**
     * Tells if the given Syntax OID is String. It checks only a subset of
     * know syntaxes :
     * <ul>
     *   <li>DIRECTORY_STRING_SYNTAX</li>
     *   <li>IA5_STRING_SYNTAX</li>
     *   <li>OBJECT_CLASS_TYPE_SYNTAX</li>
     *   <li>DN_SYNTAX</li>
     *   <li>PRINTABLE_STRING_SYNTAX</li>
     * </ul>
     * @param syntaxOid The Syntax OID
     * @return <tt>true</tt> if the syntax OID is one of the listed syntaxes
     */
    public boolean isStringSyntax(String syntaxOid) {
        if (syntaxOid == null) {
            // If there is no syntax information we assume that is is string type
            return true;
        }
        switch (syntaxOid) {
            case SchemaConstants.DIRECTORY_STRING_SYNTAX :
            case SchemaConstants.IA5_STRING_SYNTAX :
            case SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX :
            case SchemaConstants.DN_SYNTAX :
            case SchemaConstants.PRINTABLE_STRING_SYNTAX :
                return true;
            default :
                return false;
        }
    }

    /**
     * Tells if the given Syntax OID is binary. It checks only a subset of
     * know syntaxes :
     * <ul>
     *   <li>OCTET_STRING_SYNTAX</li>
     *   <li>JPEG_SYNTAX</li>
     *   <li>BINARY_SYNTAX</li>
     *   <li>BIT_STRING_SYNTAX</li>
     *   <li>CERTIFICATE_SYNTAX</li>
     *   <li>CERTIFICATE_LIST_SYNTAX</li>
     *   <li>CERTIFICATE_PAIR_SYNTAX</li>
     * </ul>
     * @param syntaxOid The Syntax OID
     * @return <tt>true</tt> if the syntax OID is one of the listed syntaxes
     */
    protected boolean isBinarySyntax(String syntaxOid) {
        if (syntaxOid == null) {
            return false;
        }
        switch (syntaxOid) {
            case SchemaConstants.OCTET_STRING_SYNTAX:
            case SchemaConstants.JPEG_SYNTAX:
            case SchemaConstants.BINARY_SYNTAX:
            case SchemaConstants.BIT_STRING_SYNTAX:
            case SchemaConstants.CERTIFICATE_SYNTAX:
            case SchemaConstants.CERTIFICATE_LIST_SYNTAX:
            case SchemaConstants.CERTIFICATE_PAIR_SYNTAX:
                return true;
            default :
                return false;
        }
    }

    /**
     * Check if an Attribute is binary or String. We use either the H/R flag, if present,
     * or a set of static syntaxes. In this case, here are the statically defined matches :
     * <ul>
     *   <li>
     *     Binary syntaxes :
     *     <ul>
     *       <li>BINARY_SYNTAX</li>
     *       <li>BIT_STRING_SYNTAX</li>
     *       <li>CERTIFICATE_LIST_SYNTAX</li>
     *       <li>CERTIFICATE_PAIR_SYNTAX</li>
     *       <li>CERTIFICATE_SYNTAX</li>
     *       <li>JPEG_SYNTAX</li>
     *       <li>OCTET_STRING_SYNTAX</li>
     *     </ul>
     *   </li>
     *   <li>
     *     String syntaxes :
     *     <ul>
     *       <li>DIRECTORY_STRING_SYNTAX</li>
     *       <li>DN_SYNTAX</li>
     *       <li>IA5_STRING_SYNTAX</li>
     *       <li>OBJECT_CLASS_TYPE_SYNTAX</li>
     *       <li>PRINTABLE_STRING_SYNTAX</li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param attributeId The Attribute name or its OID
     * @return <tt>true</tt> if the attribute is binary, <tt>false</tt> otherwise
     */
    public boolean isBinaryAttribute(String attributeId) {
        // Get rid of the attribute's options
        String ldapAttributeName = getLdapAttributeName(attributeId);

        // Retrieve the attributeType from the schema
        AttributeType attributeType = schemaManager.getAttributeType(ldapAttributeName);

        if (attributeType == null) {
            // Not found. Let's try with the set of hard-coded attributeType
            if (STRING_ATTRIBUTE_NAMES.contains(attributeId.toLowerCase())) {
                return false;
            }

            LOG.warn("Unknown attribute {0}, cannot determine if it is binary", ldapAttributeName);

            return false;
        }

        // Ok, we have the AttributeType, let's get its Syntax
        LdapSyntax syntax = getSyntax(attributeType);

        // Should *never* happen, as the getSyntax() method always
        // return a syntax....
        if (syntax == null) {
            // OpenLDAP does not define some syntaxes that it uses
            return false;
        }

        String syntaxOid = syntax.getOid();

        // First check in the pre-defined list, just in case
        if (isBinarySyntax(syntaxOid)) {
            return true;
        }

        if (isStringSyntax(syntaxOid)) {
            return false;
        }

        // Ok, if the syntax is not one of the pre-defined we know of,
        // try to ask the syntax about its status.
        return !syntax.isHumanReadable();
    }


    /**
     * Retrieve the Syntax associated with an AttributeType. In theory, every AttributeType
     * must have a syntax, but some rogue and not compliant LDAP Servers don't do that.
     * Typically, if an AttributeType does not have a Syntax, then it should inherit from
     * its parent's Syntax.
     *
     * @param attributeType The AttributeType for which we want the Syntax
     * @return The LdapSyntax instance for this AttributeType
     */
    private LdapSyntax getSyntax(AttributeType attributeType) {
        if (attributeType == null) {
            return null;
        }
        LdapSyntax syntax = attributeType.getSyntax();

        if (syntax == null && attributeType.getSyntaxOid() != null) {
            // HACK to support ugly servers (such as AD) that do not declare
            // ldapSyntaxes in the schema
            // We will first check if we can't find the syntax from the
            // SchemaManager, and if not, we will create it
            try
            {
                syntax = schemaManager.lookupLdapSyntaxRegistry( attributeType.getSyntaxOid() );
            }
            catch ( LdapException e )
            {
                // Fallback...
                syntax = new LdapSyntax(attributeType.getSyntaxOid());
            }
        }

        return syntax;
    }

    private String getSyntaxOid(AttributeType attributeType) {
        LdapSyntax syntax = getSyntax(attributeType);
        if (syntax == null) {
            return null;
        } else {
            return syntax.getOid();
        }
    }

    /**
     * Used to format __UID__ and __NAME__.
     */
    public String toConnIdIdentifierValue(Value ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
        if (ldapValue == null) {
            return null;
        }
        if (ldapAttributeType == null) {
            // E.g. ancient OpenLDAP does not have entryUUID in schema
            if (!configuration.isAllowUnknownAttributes()) {
                throw new InvalidAttributeValueException("Unknown LDAP attribute "+ldapAttributeName + " (not present in LDAP schema)");
            }
        }

        if ((ldapAttributeType != null) && isBinaryAttribute(ldapAttributeName)) {
            if (LOG.isOk()) {
                LOG.ok("Converting identifier to ConnId: {0} (syntax {1}, value {2}): explicit binary",
                        ldapAttributeName, getSyntaxOid(ldapAttributeType), ldapValue.getClass());
            }

            byte[] bytes = ldapValue.getBytes();

            if (bytes == null && ldapValue.getString() != null) {
                // Binary value incorrectly detected as string value.
                // TODO: Conversion to Java string may has broken the data. Do we need to do some magic to fix it?
                bytes = ldapValue.getString().getBytes(StandardCharsets.UTF_8);
            }

            // Assume that identifiers are short. It is more readable to use hex representation than base64.
            return LdapUtil.binaryToHex(bytes);
        } else {
            if (LOG.isOk()) {
                LOG.ok("Converting identifier to ConnId: {0} (syntax {1}, value {2}): implicit string",
                        ldapAttributeName, getSyntaxOid(ldapAttributeType), ldapValue.getClass());
            }

            return ldapValue.getString();
        }
    }

    public ObjectClassInfo findObjectClassInfo(ObjectClass icfObjectClass) {
        return connIdSchema.findObjectClassInfo(icfObjectClass.getObjectClassValue());
    }

    /**
     * Tells if a given Entry has an UID attribute
     *
     * @param entry The Entry to check
     * @return <tt>true</tt> if the entry contains an UID attribute
     */
    public boolean hasUidAttribute(Entry entry) {
        String uidAttributeName = configuration.getUidAttribute();

        if (LdapUtil.isDnAttribute(uidAttributeName)) {
            return true;
        } else {
            return entry.get(uidAttributeName) != null;
        }
    }

    public ConnectorObject toConnIdObject(LdapNetworkConnection connection, ObjectClass icfObjectClass, Entry entry, AttributeHandler attributeHandler) {
        ObjectClassInfo icfObjectClassInfo = findObjectClassInfo(icfObjectClass);
        if (icfObjectClassInfo == null) {
            throw new InvalidAttributeValueException("No definition for object class "+icfObjectClass);
        }
        return toConnIdObject(connection, icfObjectClassInfo, entry, null, attributeHandler);
    }

    public ConnectorObject toConnIdObject(LdapNetworkConnection connection, ObjectClassInfo icfObjectClass, Entry entry, AttributeHandler attributeHandler) {

        return toConnIdObject(connection, icfObjectClass, entry, null, attributeHandler);
    }

    public ConnectorObject toConnIdObject(LdapNetworkConnection connection, ObjectClassInfo icfStructuralObjectClassInfo, Entry entry) {
        return toConnIdObject(connection, icfStructuralObjectClassInfo, entry, null, null);
    }

    public ConnectorObject toConnIdObject(LdapNetworkConnection connection, ObjectClassInfo icfStructuralObjectClassInfo, Entry entry, String dn) {
        return toConnIdObject(connection, icfStructuralObjectClassInfo, entry, dn, null);
    }

    // TODO: use version from SchemaUtil
    private AttributeInfo findAttributeInfo(ObjectClassInfo connIdObjectClassInfo, String connIdAttributeName) {
        for (AttributeInfo attributeInfo: connIdObjectClassInfo.getAttributeInfo()) {
            if (attributeInfo.is(connIdAttributeName)) {
                return attributeInfo;
            }
        }
        return null;
    }

    public ConnectorObject toConnIdObject(LdapNetworkConnection connection, ObjectClassInfo connIdStructuralObjectClassInfo, Entry entry, String dn, AttributeHandler attributeHandler) {
        LdapObjectClasses ldapObjectClasses = processObjectClasses(entry);
        if (connIdStructuralObjectClassInfo == null) {
            connIdStructuralObjectClassInfo = connIdSchema.findObjectClassInfo(ldapObjectClasses.getLdapLowestStructuralObjectClass().getName());
        }
        ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
        String connIdStructuralObjectClassType = connIdStructuralObjectClassInfo.getType();
        if (dn == null) {
            dn = getDn(entry);
        }
        cob.setName(dn);
        cob.setObjectClass(new ObjectClass(connIdStructuralObjectClassType));

        List<ObjectClassInfo> connIdAuxiliaryObjectClassInfos = new ArrayList<>(ldapObjectClasses.getLdapAuxiliaryObjectClasses().size());

        for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapAuxiliaryObjectClass : ldapObjectClasses.getLdapAuxiliaryObjectClasses()) {
            connIdAuxiliaryObjectClassInfos.add(connIdSchema.findObjectClassInfo(ldapAuxiliaryObjectClass.getName()));
        }

        if (configuration.isStructuralObjectClassesToAuxiliary()) {
            for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass : ldapObjectClasses.getLdapStructuralObjectClasses()) {
                ObjectClassInfo objectClassInfo = connIdSchema.findObjectClassInfo(ldapStructuralObjectClass.getName());

                if ((!connIdStructuralObjectClassInfo.equals(objectClassInfo)) && (!hasSubclass(ldapStructuralObjectClass, ldapObjectClasses.getLdapStructuralObjectClasses()))) {
                    connIdAuxiliaryObjectClassInfos.add(objectClassInfo);
                }
            }
        }

        if (!connIdAuxiliaryObjectClassInfos.isEmpty()) {
            AttributeBuilder auxAttrBuilder = new AttributeBuilder();

            auxAttrBuilder.setName(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME);

            for (ObjectClassInfo objectClassInfo : connIdAuxiliaryObjectClassInfos) {
                auxAttrBuilder.addValue(objectClassInfo.getType());
            }

            cob.addAttribute(auxAttrBuilder.build());
        }

        String uidAttributeName = configuration.getUidAttribute();
        String uid;
        if (LdapUtil.isDnAttribute(uidAttributeName)) {
            uid = dn;
        } else {
            org.apache.directory.api.ldap.model.entry.Attribute uidAttribute = entry.get(uidAttributeName);
            if (uidAttribute == null) {
                throw new IllegalArgumentException("LDAP entry "+dn+" does not have UID attribute "+uidAttributeName);
            }
            if (uidAttribute.size() > 1) {
                throw new IllegalArgumentException("LDAP entry "+dn+" has more than one value for UID attribute "+uidAttributeName);
            }
            AttributeType attributeType = schemaManager.getAttributeType(uidAttribute.getId());
            uid = toConnIdIdentifierValue(uidAttribute.get(), uidAttribute.getId(), attributeType);
        }
        cob.setUid(uid);

        Map<String,PolyAttributeStruct> polyAttributes = new HashMap<>();

        Iterator<org.apache.directory.api.ldap.model.entry.Attribute> iterator = entry.iterator();
        while (iterator.hasNext()) {
            org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute = iterator.next();
            String ldapAttrName = getLdapAttributeName(ldapAttribute);

//            LOG.ok("Processing attribute {0} (UP: {1})", ldapAttrName, ldapAttribute.getUpId());
            if (!shouldTranslateAttribute(ldapAttrName)) {

//                LOG.ok("Should not translate attribute {0}, skipping", ldapAttrName);
                continue;
            }
            AttributeType ldapAttributeType = schemaManager.getAttributeType(ldapAttrName);

//            LOG.ok("Type for attribute {0}: {1}", ldapAttrName, ldapAttributeType);
            String ldapAttributeNameFromSchema = ldapAttrName;
            if (ldapAttributeType == null) {
                if (!configuration.isAllowUnknownAttributes()) {
                    throw new InvalidAttributeValueException("Unknown LDAP attribute " + ldapAttrName + " (not present in LDAP schema)");
                }
            } else {
                ldapAttributeNameFromSchema = ldapAttributeType.getName();
            }
            if (uidAttributeName.equals(ldapAttributeNameFromSchema)) {
                continue;
            }

            PolyAttributeStruct polyStruct = polyAttributes.get(ldapAttributeNameFromSchema);
            if (polyStruct != null) {
                // We know that this attribute is poly. Just collect the data.
                // And we can avoid the rest of the processing because it was done already.
                polyStruct.addAttribute(ldapAttribute);
                continue;
            }

            String connIdAttributeName = toConnIdAttributeName(ldapAttributeNameFromSchema);

            // TODO: use findAttributeInfo from SchemaUtil
            AttributeInfo connIdAttributeInfo = findAttributeInfo(connIdStructuralObjectClassInfo, connIdAttributeName);

            if (!ArrayUtils.isEmpty(configuration.getManagedAssociationPairs())) {
                if (isAssociationAttribute(connIdStructuralObjectClassType, connIdAttributeName)) {

                    if (attributeHandler !=null && (attributeHandler instanceof ReferenceAttributeHandler)) {

                        ((ReferenceAttributeHandler) attributeHandler).setConnectorObjectBuilder(cob);
                        saturateConnIdReferences(connIdAttributeName, ldapAttrName,
                                ldapAttributeType, ldapAttribute, connection, attributeHandler, null);

                        continue;
                    } else {

                        LOG.warn("Reference attribute handler missing in case of association attribute handling");
                    }
                }
            }
            if (connIdAttributeInfo == null) {
                for (ObjectClassInfo icfAuxiliaryObjectClassInfo: connIdAuxiliaryObjectClassInfos) {
                    // TODO: use version of findAttributeInfo from SchemaUtil
                    connIdAttributeInfo = findAttributeInfo(icfAuxiliaryObjectClassInfo, connIdAttributeName);
                  //  LOG.ok("Looking for ConnId attribute {0} info in auxiliary class {1}: {2}", icfAttribute, icfAuxiliaryObjectClassInfo==null?null:icfAuxiliaryObjectClassInfo.getType(), attributeInfo);
                    if (connIdAttributeInfo != null) {
                        break;
                    }
                }
            }
          //  LOG.ok("ConnId attribute info for {0} ({1}): {2}", icfAttribute.getName(), ldapAttrName, attributeInfo);

            if (connIdAttributeInfo == null) {

                LOG.ok("ConnId attribute {0} is not part of ConnId schema, skipping", connIdAttributeName);
                continue;
            }

            if (isPolyAttribute(connIdAttributeInfo)) {

                // Defer processing of poly attributes for later. We do not have all the values yet. Just collect the values now.
                polyAttributes.put(ldapAttributeNameFromSchema, new PolyAttributeStruct(ldapAttributeType, connIdAttributeName, ldapAttribute));

            } else {
                // Process simple (non-poly) attributes right here. We are not waiting for anything else.

                Attribute connIdAttribute = toConnIdAttribute(connIdAttributeName, ldapAttributeNameFromSchema, ldapAttributeType, ldapAttribute,
                        connection, entry, attributeHandler);
//                LOG.ok("ConnId attribute for {0}: {1}", ldapAttrName, connIdAttribute);
                if (connIdAttribute != null) {
                    cob.addAttribute(connIdAttribute);
                }
            }

        }
        for (Map.Entry<String, PolyAttributeStruct> polyAttributesEntry : polyAttributes.entrySet()) {
            String ldapAttributeNameFromSchema = polyAttributesEntry.getKey();

            Attribute connIdAttribute = toConnIdAttributePoly(polyAttributesEntry.getValue().getConnIdAttributeName(), ldapAttributeNameFromSchema, polyAttributesEntry.getValue().getLdapAttributeType(),
                    polyAttributesEntry.getValue().getLdapAttributes(),
                    connection, entry, attributeHandler);

            if (connIdAttribute != null) {
                cob.addAttribute(connIdAttribute);
            }

        }

        extendConnectorObject(cob, entry, connIdStructuralObjectClassInfo.getType());
        
        return cob.build();
    }

    class PolyAttributeStruct {

        private AttributeType ldapAttributeType;
        private String connIdAttributeName;
        private List<org.apache.directory.api.ldap.model.entry.Attribute> ldapAttributes = new ArrayList<>();

        public PolyAttributeStruct(AttributeType ldapAttributeType,
                String connIdAttributeName, org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
            super();
            this.ldapAttributeType = ldapAttributeType;
            this.connIdAttributeName = connIdAttributeName;
            this.ldapAttributes.add(ldapAttribute);
        }

        public AttributeType getLdapAttributeType() {
            return ldapAttributeType;
        }

        public String getConnIdAttributeName() {
            return connIdAttributeName;
        }

        public List<org.apache.directory.api.ldap.model.entry.Attribute> getLdapAttributes() {
            return ldapAttributes;
        }

        public void addAttribute(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
            ldapAttributes.add(ldapAttribute);
        }

    }

    private Attribute toConnIdAttribute(String connIdAttributeName, String ldapAttributeNameFromSchema, AttributeType ldapAttributeType,
                                        org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute,
                                        LdapNetworkConnection connection, Entry entry, AttributeHandler attributeHandler) {
        return toConnIdAttribute(null, connIdAttributeName, ldapAttributeNameFromSchema, ldapAttributeType,
                ldapAttribute, connection, entry, attributeHandler);
    }

    private Attribute toConnIdAttribute(ObjectClass oc, String connIdAttributeName, String ldapAttributeNameFromSchema, AttributeType ldapAttributeType,
                                        org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute,
                                        LdapNetworkConnection connection, Entry entry, AttributeHandler attributeHandler) {
        AttributeBuilder ab = new AttributeBuilder();
        ab.setName(connIdAttributeName);
        if (attributeHandler != null && !(attributeHandler instanceof ReferenceAttributeHandler)) {
            attributeHandler.handle(connection, entry, ldapAttribute, ab);
        }
        boolean incompleteRead = false;
        if (OperationalAttributeInfos.PASSWORD.is(connIdAttributeName)) {
            switch (configuration.getPasswordReadStrategy()) {
                case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_READABLE:
                    // Nothing to do. Proceed with ordinary read.
                    break;
                case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_INCOMPLETE_READ:
                    incompleteRead = true;
                    break;
                case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_UNREADABLE:
                    return null;
                default:
                    throw new ConfigurationException("Unknown passoword read strategy "+configuration.getPasswordReadStrategy());
            }
        }
        Iterator<Value> iterator = ldapAttribute.iterator();
        boolean hasValidValue = false;
        while (iterator.hasNext()) {
            Value ldapValue = iterator.next();
            Object connIdValue = toConnIdValue(connIdAttributeName, ldapValue, ldapAttributeNameFromSchema, ldapAttributeType);
            if (connIdValue != null) {
                if (!incompleteRead && shouldValueBeIncluded(connIdValue, ldapAttributeNameFromSchema)) {
                    ab.addValue(connIdValue);
                }
                hasValidValue = true;
            }
        }
        if (!hasValidValue) {
            // Do not even try to build. The build will fail.
            return null;
        }
        if (incompleteRead) {
            ab.setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
        }
        try {
            return ab.build();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage() + ", attribute "+connIdAttributeName+" (ldap: "+ldapAttributeNameFromSchema+")", e);
        }
    }

    private void saturateConnIdReferences(String connIdAttributeName,
                                                     String ldapAttributeNameFromSchema , AttributeType ldapAttributeType,
                                                     org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute,
                                                     LdapNetworkConnection connection, AttributeHandler handler, Entry entry) {



        if (ldapAttribute != null) {
            Iterator<Value> iterator = ldapAttribute.iterator();
            while (iterator.hasNext()) {
                Value ldapValue = iterator.next();
                // TODO #A Assuming this is a identificator (dn, I guess a conditional confirming this could be used )
                Object connIdValue = toConnIdValue(connIdAttributeName, ldapValue, ldapAttributeNameFromSchema, ldapAttributeType);

                if (connIdValue != null) {
                    if (shouldValueBeIncluded(connIdValue, ldapAttributeNameFromSchema)) {

                        handler.handle(connection, entry, ldapAttribute, null);
                    }
                }
            }
        }
    }

    private void constructAssociationSets(){

        // TODO # A Cleanup and divide

        String[] associationPairs = configuration.getManagedAssociationPairs();

        for (String associationPair : associationPairs) {

            String[] pairArray = associationPair.split(CONF_ASSOC_DELIMITER);

            if (pairArray.length == 2) {

                String memberObjectClassAndAttribute = pairArray[0].trim();
                String targetObjectClassAndAttribute = pairArray[1].trim();

                String[] subjectObjectClassAndAttributes = memberObjectClassAndAttribute.split(CONF_ASSOC_ATTR_DELIMITER);
                String[] objectObjectClassAndAttributes = targetObjectClassAndAttribute.split(CONF_ASSOC_ATTR_DELIMITER);

                String subjectObjectClass = null;
                String subjectObjectClassAssociationAttrName = null;
                String objectObjectClass = null;
                String objectObjectClassAssociationAttrName = null;

                if (subjectObjectClassAndAttributes.length == 2) {

                    subjectObjectClass = subjectObjectClassAndAttributes[1].trim();
                    // We need to remove the leading " character
                    subjectObjectClassAssociationAttrName = subjectObjectClassAndAttributes[0].trim().substring(1);
                } else {

                    LOG.warn("Association pair syntax contain no or " +
                            "multiple delimiters \" " + configuration.CONF_ASSOC_ATTR_DELIMITER + " \"");
                    LOG.warn("Skipping association pair: {0}", associationPair);
                }

                if (objectObjectClassAndAttributes.length == 2) {

                    objectObjectClass = objectObjectClassAndAttributes[1].trim();
                    // We need to remove the leading " character
                    objectObjectClassAssociationAttrName = objectObjectClassAndAttributes[0].trim().substring(1);
                } else {

                    LOG.warn("Association pair syntax contain no or " +
                            "multiple delimiters \" " + configuration.CONF_ASSOC_ATTR_DELIMITER + " \"");
                    LOG.warn("Skipping association pair: {0}", associationPair);
                }

                // TODO #A trace log, remove
                LOG.ok("Association set, subject objectClass {0} and target objectClass {1}", subjectObjectClass,
                        objectObjectClass);

                if (objectAssociationSets !=null && !objectAssociationSets.isEmpty()) {

                    LOG.ok("Add to object association set with {0} and {1}", subjectObjectClass,objectObjectClass);

                    if (objectAssociationSets.containsKey(objectObjectClass)) {

                        Set<AssociationHolder> memberAssociations = objectAssociationSets.get(objectObjectClass);
// TODO #A remove subtype
                        AssociationHolder memberAssociation = new AssociationHolder("grantee", subjectObjectClass, objectObjectClass,
                                objectObjectClassAssociationAttrName, subjectObjectClass+"-grantee", R_I_R_OBJECT, subjectObjectClassAssociationAttrName);
                        memberAssociations.add(memberAssociation);
                        objectAssociationSets.put(objectObjectClass, memberAssociations);
                    } else {
                        // TODO #A remove subtype
                        AssociationHolder memberAssociation = new AssociationHolder("grantee", subjectObjectClass, objectObjectClass,
                                objectObjectClassAssociationAttrName, subjectObjectClass+"-grantee", R_I_R_OBJECT, subjectObjectClassAssociationAttrName);

                        objectAssociationSets.put(objectObjectClass, new HashSet<>(Arrays.asList(memberAssociation)));
                    }

                } else {

                    LOG.ok("Initiating object association set with {0} and {1}", subjectObjectClass,objectObjectClass);
                    objectAssociationSets = new HashMap<>();
// TODO #A remove subtype
                    AssociationHolder memberAssociation = new AssociationHolder("grantee", subjectObjectClass, objectObjectClass,
                            objectObjectClassAssociationAttrName, subjectObjectClass+"-grantee", R_I_R_OBJECT, subjectObjectClassAssociationAttrName);

                    objectAssociationSets.put(objectObjectClass, new HashSet<>(Arrays.asList(memberAssociation)));
                }

                if (subjectAssociationSets !=null && !subjectAssociationSets.isEmpty()) {
                    LOG.ok("Add to subject association set with {0} and {1}", subjectObjectClass,objectObjectClass);
                    if (subjectAssociationSets.containsKey(subjectObjectClass)) {

                        Set<AssociationHolder> objectAssociations = subjectAssociationSets.get(subjectObjectClass);
// TODO #A remove subtype
                        AssociationHolder objectAssociation = new AssociationHolder("grant", subjectObjectClass, objectObjectClass,
                                subjectObjectClassAssociationAttrName, objectObjectClass+"-grant", R_I_R_SUBJECT, objectObjectClassAssociationAttrName);

                        objectAssociations.add(objectAssociation);
                        subjectAssociationSets.put(subjectObjectClass, objectAssociations);

                    } else {
                        // TODO #A remove subtype
                        AssociationHolder objectAssociation = new AssociationHolder("grant", subjectObjectClass, objectObjectClass,
                                subjectObjectClassAssociationAttrName, objectObjectClass+"-grant", R_I_R_SUBJECT, objectObjectClassAssociationAttrName);
                        subjectAssociationSets.put(subjectObjectClass, new HashSet<>(Arrays.asList(objectAssociation)));
                    }

                } else {
                    LOG.ok("Initiating member association set with {0} and {1}", subjectObjectClass,objectObjectClass);
                    subjectAssociationSets = new HashMap<>();
// TODO #A remove subtype
                    AssociationHolder objectAssociation = new AssociationHolder("grant", subjectObjectClass, objectObjectClass,
                            subjectObjectClassAssociationAttrName, objectObjectClass+"-grant", R_I_R_SUBJECT, objectObjectClassAssociationAttrName);
                    subjectAssociationSets.put(subjectObjectClass, new HashSet<>(Arrays.asList(objectAssociation)));
                }
            } else {

                LOG.warn("Association pair syntax contain no or " +
                        "multiple delimiters \" " + configuration.CONF_ASSOC_DELIMITER + " \"");
                LOG.warn("Skipping association pair: {0}", associationPair);
            }
        }
    }

    private boolean isAssociationAttribute(String objectClassName, String connIdAttributeName) {

        Set<AssociationHolder> associationHoldersSubject = getSubjectAssociationSets().get(objectClassName);
        Set<AssociationHolder> associationHoldersObject = getObjectAssociationSets().get(objectClassName);

        if (associationHoldersSubject != null) {
            for (AssociationHolder associationHolder : associationHoldersSubject) {
                if (connIdAttributeName.equalsIgnoreCase(associationHolder.getAssociationAttributeName())) {

                    return true;
                }
            }
        }

        if (associationHoldersObject != null) {
            for (AssociationHolder associationHolder : associationHoldersObject) {
                if (connIdAttributeName.equalsIgnoreCase(associationHolder.getAssociationAttributeName())) {

                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Decide if value should be included in case filtering for memberOf attribute is set.
     * All other attributes and their value will not be checked for condition matching.
     *
     * @param connIdValue {@link Object} value of attribute to be checked
     * @param ldapAttributeNameFromSchema {@link String} ldap attribute name to determine, if value should be checked
     *
     * @return Boolean true if value should be included, false in case value should be removed. Default: true
     */
    public boolean shouldValueBeIncluded(Object connIdValue, String ldapAttributeNameFromSchema) {
        if (configuration.isFilterOutMemberOfValues() && ATTRIBUTE_MEMBER_OF_NAME.equalsIgnoreCase(ldapAttributeNameFromSchema)) {
            String[] allowedValues = configuration.getMemberOfAllowedValues();
            if (allowedValues.length == 0) {
                LOG.ok("MemberOfAllowedValues is empty, using baseContext for filtering");
                allowedValues = new String[]{ configuration.getBaseContext() };
                configuration.setMemberOfAllowedValues(allowedValues);
            }

            if (connIdValue instanceof String) {
                LOG.ok("Filtering memberOf attribute value: {0}", connIdValue);
                String connIdValueString = (String) connIdValue;
                return Arrays.stream(allowedValues)
                             .filter(Predicate.not(String::isEmpty))
                             .anyMatch(allowedValue -> connIdValueString.regionMatches(
                                     true,
                                     connIdValueString.length() - allowedValue.length(),
                                     allowedValue,
                                     0,
                                     allowedValue.length()));
            }
        }
        return true;
    }

    protected Attribute toConnIdAttributePoly(String connIdAttributeName, String ldapAttributeNameFromSchema, AttributeType ldapAttributeType,
            List<org.apache.directory.api.ldap.model.entry.Attribute> ldapAttributes,
            LdapNetworkConnection connection, Entry entry, AttributeHandler attributeHandler) {
        throw new UnsupportedOperationException("Poly-attributes are not supported (attribute '"+ldapAttributeNameFromSchema+"'");
    }

    public String determinePolyKey(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
        throw new UnsupportedOperationException("Poly-attributes are not supported");
    }

    public String getDn(Entry entry) {
        return entry.getDn().getName();
    }

    public String getLdapAttributeName(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
        return getLdapAttributeName(ldapAttribute.getId());
    }

    /**
     * Get back the attribute name, without the options. Typically, RFC 4512
     * defines an Attribute description as :
     * <pre>
     * attributedescription = attributetype options
     * attributetype = oid
     * options = *( SEMI option )
     * option = 1*keychar
     * </pre>
     *
     * where <em>oid</em> can be a String or an OID. An example is :
     * <pre>
     * cn;lang-de;lang-en
     * </pre>
     * where the attribute name is <em>cn</em>.
     * <p>
     * @param attributeId The attribute descriptio to parse
     * @return The attribute name, without the options
     */
    public String getLdapAttributeName(String attributeId) {
        int iSemicolon = attributeId.indexOf(';');

        if (iSemicolon < 0) {
            return attributeId;
        }

        return attributeId.substring(0, iSemicolon);
    }

    public String getLdapAttributeOption(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
        return getLdapAttributeOption(ldapAttribute.getUpId());
    }

    public String getLdapAttributeOption(String attributeUpId) {
        int iSemicolon = attributeUpId.indexOf(';');

        if (iSemicolon < 0) {
            return null;
        }

        return attributeUpId.substring(iSemicolon + 1);
    }

    protected boolean shouldTranslateAttribute(String attrName) {
        return true;
    }

    protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
        // Nothing to do here. This is supposed to be overriden by subclasses.
    }

    private LdapObjectClasses processObjectClasses(Entry entry) {
        LdapObjectClasses ocs = new LdapObjectClasses();
        org.apache.directory.api.ldap.model.entry.Attribute objectClassAttribute = entry.get(SchemaConstants.OBJECT_CLASS_AT);
        if (objectClassAttribute == null) {
            throw new InvalidAttributeValueException("No object class attribute in entry "+entry.getDn());
        }
        // Neither structural nor auxiliary. Should not happen. But it does.
        List<org.apache.directory.api.ldap.model.schema.ObjectClass> outstandingObjectClasses = new ArrayList<>();
        for (Value objectClassVal: objectClassAttribute) {
            String objectClassString = objectClassVal.getString();
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass;
            try {
                ldapObjectClass = schemaManager.lookupObjectClassRegistry(objectClassString);
            } catch (LdapException e) {
                throw new InvalidAttributeValueException(e.getMessage(), e);
            }
            if (ldapObjectClass.isStructural()) {
//                LOG.ok("Objectclass {0}: structural)", ldapObjectClass.getName());
                ocs.getLdapStructuralObjectClasses().add(ldapObjectClass);
            } else if (ldapObjectClass.isAuxiliary()) {
//                LOG.ok("Objectclass {0}: auxiliary)", ldapObjectClass.getName());
                ocs.getLdapAuxiliaryObjectClasses().add(ldapObjectClass);
            } else if (ldapObjectClass.isAbstract()) {
//                LOG.ok("Objectclass {0}: abstract)", ldapObjectClass.getName());
                // We are ignoring this. This is 'top' and things like that.
                // These are not directly useful, not even in the alternative mechanism.
            } else {
//                LOG.ok("Objectclass {0}: outstanding)", ldapObjectClass.getName());
                outstandingObjectClasses.add(ldapObjectClass);
            }
        }
        if (ocs.getLdapStructuralObjectClasses().isEmpty()) {
            throw new InvalidAttributeValueException("Entry "+entry.getDn()+" has no structural object classes");
        }
        if (ocs.getLdapStructuralObjectClasses().size() == 1) {
            ocs.setLdapLowestStructuralObjectClass(ocs.getLdapStructuralObjectClasses().get(0));
        } else {
            for (org.apache.directory.api.ldap.model.schema.ObjectClass structObjectClass: ocs.getLdapStructuralObjectClasses()) {
                if (!hasSubclass(structObjectClass, ocs.getLdapStructuralObjectClasses())) {
                    ocs.setLdapLowestStructuralObjectClass(structObjectClass);
                    break;
                }
            }
            if (ocs.getLdapLowestStructuralObjectClass() == null) {
                throw new InvalidAttributeValueException("Cannot determine lowest structural object class for set of object classes: "+objectClassAttribute);
            }
        }
        if (getConfiguration().isAlternativeObjectClassDetection()) {
            for (org.apache.directory.api.ldap.model.schema.ObjectClass objectClass: outstandingObjectClasses) {
                // Extra filter to filter out classes such as 'top' if they are not
                // properly marked as abstract
                if (hasSubclass(objectClass, outstandingObjectClasses)) {
                    continue;
                }
                if (hasSubclass(objectClass, ocs.getLdapStructuralObjectClasses())) {
                    continue;
                }
                if (hasSubclass(objectClass, ocs.getLdapAuxiliaryObjectClasses())) {
                    continue;
                }
                LOG.ok("Detected auxliary objectclasse (alternative method): {0})", ocs);
                ocs.getLdapAuxiliaryObjectClasses().addAll(outstandingObjectClasses);
            }
        }
//        LOG.ok("Detected objectclasses: {0})", ocs);
        return ocs;
    }

    /**
     * Returns true if any of the otherObjectClasses is a superclass of this objectClass.
     * I.e. if this objectClass is subclass of any of the otherObjectClasses.
     */
    private boolean hasSubclass(org.apache.directory.api.ldap.model.schema.ObjectClass objectClass,
            List<org.apache.directory.api.ldap.model.schema.ObjectClass> otherObjectClasses) {
//        LOG.ok("Trying {0} ({1})", structObjectClass.getName(), structObjectClass.getOid());
        for (org.apache.directory.api.ldap.model.schema.ObjectClass otherObjectClass: otherObjectClasses) {
            if (objectClass.getOid().equals(otherObjectClass.getOid())) {
                continue;
            }
//            LOG.ok("  with {0} ({1})", otherObjectClass.getName(), structObjectClass.getOid());
//            LOG.ok("    superiorOids: {0}", otherObjectClass.getSuperiorOids());
            if (otherObjectClass.getSuperiorOids().contains(objectClass.getOid())
                    || otherObjectClass.getSuperiorOids().contains(objectClass.getName())) {
//                LOG.ok("    hasSubclass");
                return true;
            }
        }
        return false;
    }

    private Object hashLdapPassword(Object icfAttributeValue) {
        if (icfAttributeValue == null) {
            return null;
        }
        byte[] bytes;
        if (icfAttributeValue instanceof String) {
            try {
                bytes = ((String)icfAttributeValue).getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        } else if (icfAttributeValue instanceof GuardedString) {
            final String[] out = new String[1];
            ((GuardedString)icfAttributeValue).access(new GuardedString.Accessor() {
                @Override
                public void access(char[] clearChars) {
                    out[0] = new String(clearChars);
                }
            });
            try {
                bytes = out[0].getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        } else if (icfAttributeValue instanceof byte[]) {
            bytes = (byte[])icfAttributeValue;
        } else {
            throw new InvalidAttributeValueException("Unsupported type of password attribute: "+icfAttributeValue.getClass());
        }
        return hashBytes(bytes, configuration.getPasswordHashAlgorithm(), 0);
    }

    private String hashBytes(byte[] clear, String alg, long seed) {
        MessageDigest md = null;

        try {
            if (alg.equalsIgnoreCase("SSHA") || alg.equalsIgnoreCase("SHA")) {
                    md = MessageDigest.getInstance("SHA-1");
            } else if ( alg.equalsIgnoreCase("SMD5") || alg.equalsIgnoreCase("MD5") ) {
                md = MessageDigest.getInstance("MD5");
            } else if ( alg.equalsIgnoreCase("SSHA-256") || alg.equalsIgnoreCase("SHA-256") ) {
                md = MessageDigest.getInstance("SHA-256");
            } else if ( alg.equalsIgnoreCase("SSHA-384") || alg.equalsIgnoreCase("SHA-384") ) {
                md = MessageDigest.getInstance("SHA-384");
            }  else if ( alg.equalsIgnoreCase("SSHA-512") || alg.equalsIgnoreCase("SHA-512") ) {
                md = MessageDigest.getInstance("SHA-512");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new ConnectorException("Could not find MessageDigest algorithm: "+alg);
        }

        if (md == null) {
            throw new ConnectorException("Unsupported MessageDigest algorithm: " + alg);
        }

        byte[] salt = {};
        if (alg.equalsIgnoreCase("SSHA") || alg.equalsIgnoreCase("SMD5")
                || alg.equalsIgnoreCase("SSHA-256") || alg.equalsIgnoreCase("SSHA-384")
                || alg.equalsIgnoreCase("SSHA-512")) {
            Random rnd = new Random();
            rnd.setSeed(System.currentTimeMillis() + seed);
            salt = new byte[8];
            rnd.nextBytes(salt);
        }

        md.reset();
        md.update(clear);
        md.update(salt);
        byte[] hash = md.digest();

        byte[] hashAndSalt = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, hashAndSalt, 0, hash.length);
        System.arraycopy(salt, 0, hashAndSalt, hash.length, salt.length);

        StringBuilder resSb = new StringBuilder(alg.length() + hashAndSalt.length);
        resSb.append('{');
        resSb.append(alg);
        resSb.append('}');
        resSb.append(Base64.getEncoder().encodeToString(hashAndSalt));

        return resSb.toString();
    }


    public Dn toDn(AttributeDelta delta) {
        if (delta == null) {
            return null;
        }
        return toDn(SchemaUtil.getSingleStringNonBlankReplaceValue(delta));
    }

    public Dn toDn(Attribute attribute) {
        if (attribute == null) {
            return null;
        }
        return toDn(SchemaUtil.getSingleStringNonBlankValue(attribute));
    }

    public Dn toDn(Uid icfUid) {
        if (icfUid == null) {
            return null;
        }
        return toDn(icfUid.getUidValue());
    }

    public Dn toDn(String stringDn) {
        if (stringDn == null) {
            return null;
        }
        try {
            return new Dn(stringDn);
        } catch (LdapInvalidDnException e) {
            throw new InvalidAttributeValueException("Invalid DN '"+stringDn+"': "+e.getMessage(), e);
        }
    }

    public Dn toSchemaAwareDn(Attribute attribute) {
        if (attribute == null) {
            return null;
        }
        return toSchemaAwareDn(SchemaUtil.getSingleStringNonBlankValue(attribute));
    }

    public Dn toSchemaAwareDn(Uid icfUid) {
        if (icfUid == null) {
            return null;
        }
        return toSchemaAwareDn(icfUid.getUidValue());
    }

    public Dn toSchemaAwareDn(String stringDn) {
        if (stringDn == null) {
            return null;
        }
        try {
            return new Dn(schemaManager, stringDn);
        } catch (LdapInvalidDnException e) {
            throw new InvalidAttributeValueException("Invalid DN '"+stringDn+"': "+e.getMessage(), e);
        }
    }

    // This may seems strange. But it converts non-schema-aware DNs to schema-aware DNs.
    public Dn toSchemaAwareDn(Dn dn) {
        if (dn == null) {
            return null;
        }
        if (dn.isSchemaAware()) {
            return dn;
        }
        try {
            dn = new Dn(schemaManager, dn);
        } catch (LdapInvalidDnException e) {
            throw new InvalidAttributeValueException("Invalid DN '"+dn+"': "+e.getMessage(), e);
        }
        return dn;
    }

    /**
     * Find an attribute that is part of the specified object class definition.
     * Returns the first attribute from the list of candidate attributes that matches.
     */
    public String selectAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
            List<String> candidates) {
        for (String candidate: candidates) {
            if (getConfiguration().getUidAttribute().equalsIgnoreCase(candidate)) {
                return candidate;
            }
            if (hasAttribute(ldapObjectClass, candidate)) {
                return candidate;
            }
        }
        for(org.apache.directory.api.ldap.model.schema.ObjectClass superClass: ldapObjectClass.getSuperiors()) {
            String selectedAttribute = selectAttribute(superClass, candidates);
            if (selectedAttribute != null) {
                return selectedAttribute;
            }
        }
        return null;
    }

    private boolean hasAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
            String attributeName) {
        if (hasAttribute(ldapObjectClass.getMustAttributeTypes(), attributeName) ||
                hasAttribute(ldapObjectClass.getMayAttributeTypes(), attributeName)) {
            return true;
        }
        for (org.apache.directory.api.ldap.model.schema.ObjectClass superior: ldapObjectClass.getSuperiors()) {
            if (superior.getName().equalsIgnoreCase(SchemaConstants.TOP_OC)) {
                // Do not even try top object class. Standard top objectclass has nothing to offer.
                // And some non-standard (e.g. AD) definitions will only screw everything up as they
                // contain definition for attributes that are not really meaningful.
                continue;
            }
            if (hasAttribute(superior, attributeName)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasAttribute(List<AttributeType> attrTypeList, String attributeName) {
        for (AttributeType attrType: attrTypeList) {
            for (String name: attrType.getNames()) {
                if (attributeName.equalsIgnoreCase(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    public String[] getOperationalAttributes() {
        return configuration.getOperationalAttributes();
    }

    public boolean isOperationalAttribute(String icfAttr) {
        String[] operationalAttributes = getOperationalAttributes();
        if (operationalAttributes == null) {
            return false;
        }
        for (String opAt: operationalAttributes) {
            if (opAt.equals(icfAttr)) {
                return true;
            }
        }
        return false;
    }

    public String getUidAttribute() {
        return configuration.getUidAttribute();
    }


    public String[] determineAttributesToGet(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
                                              OperationOptions options, String... additionalAttributes) {
        String[] operationalAttributes = getOperationalAttributes();
        if (options == null || options.getAttributesToGet() == null) {
            String[] ldapAttrs = new String[2 + operationalAttributes.length + additionalAttributes.length];
            ldapAttrs[0] = "*";
            ldapAttrs[1] = getUidAttribute();
            int i = 2;
            for (String operationalAttribute: operationalAttributes) {
                ldapAttrs[i] = operationalAttribute;
                i++;
            }
            for (String additionalAttribute: additionalAttributes) {
                ldapAttrs[i] = additionalAttribute;
                i++;
            }
            return ldapAttrs;
        }
        String[] connidAttrs = options.getAttributesToGet();
        int extraAttrs = 2;
        if (options.getReturnDefaultAttributes() != null && options.getReturnDefaultAttributes()) {
            extraAttrs++;
        }
        List<String> ldapAttrs = new ArrayList<String>(connidAttrs.length + operationalAttributes.length + extraAttrs);
        if (options.getReturnDefaultAttributes() != null && options.getReturnDefaultAttributes()) {
            ldapAttrs.add("*");
        }
        for (String connidAttr: connidAttrs) {
            if (Name.NAME.equals(connidAttr)) {
                continue;
            }
            AttributeType ldapAttributeType = toLdapAttribute(ldapObjectClass, connidAttr);
            if (isValidAttributeToGet(connidAttr, ldapAttributeType)) {
                if (ldapAttributeType == null) {
                    // No definition for this attribute. It is most likely operational attribute that is not in the schema.
                    if (isOperationalAttribute(connidAttr)) {
                        ldapAttrs.add(connidAttr);
                    } else {
                        throw new InvalidAttributeValueException("Unknown attribute '" + connidAttr + "' (in attributesToGet)");
                    }
                } else {
                    ldapAttrs.add(ldapAttributeType.getName());
                }
            }
        }
        for (String operationalAttribute: operationalAttributes) {
            ldapAttrs.add(operationalAttribute);
        }
        for (String additionalAttribute: additionalAttributes) {
            ldapAttrs.add(additionalAttribute);
        }
        ldapAttrs.add(getUidAttribute());
        ldapAttrs.add(SchemaConstants.OBJECT_CLASS_AT);
        return ldapAttrs.toArray(new String[ldapAttrs.size()]);
    }

    // To be overridden in subclasses.
    protected boolean isValidAttributeToGet(String connidAttr, AttributeType ldapAttributeType) {
        return true;
    }

    public ExprNode createUidSearchFilter(String uidValue,
                                                 org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        AttributeType ldapAttributeType = toLdapAttribute(ldapObjectClass, Uid.NAME);
        Value ldapValue = toLdapIdentifierValue(ldapAttributeType, uidValue);
        return new EqualityNode<>(ldapAttributeType, ldapValue);
    }

    private static class TypeSubType {
        Class<?> type;
        String subtype;

        public TypeSubType(Class<?> type, String subtype) {
            super();
            this.type = type;
            this.subtype = subtype;
        }
    }

    private static void addToSyntaxMap(String syntaxOid, Class<?> type) {
        SYNTAX_MAP.put(syntaxOid, new TypeSubType(type, null));
    }

    private static void addToSyntaxMap(String syntaxOid, Class<?> type, String subtype) {
        SYNTAX_MAP.put(syntaxOid, new TypeSubType(type, subtype));
    }

    private static void addToSyntaxMap(String syntaxOid, Class<?> type, AttributeInfo.Subtypes subtype) {
        SYNTAX_MAP.put(syntaxOid, new TypeSubType(type, subtype.toString()));
    }

    static {
        addToSyntaxMap(SchemaConstants.NAME_OR_NUMERIC_ID_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_CASE_IGNORE);
        addToSyntaxMap(SchemaConstants.NUMERIC_OID_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.ATTRIBUTE_TYPE_USAGE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.NUMBER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OID_LEN_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OBJECT_NAME_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.ACI_ITEM_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.ACCESS_POINT_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.ATTRIBUTE_TYPE_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.AUDIO_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.BINARY_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.BIT_STRING_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.BOOLEAN_SYNTAX, Boolean.class);
        addToSyntaxMap(SchemaConstants.CERTIFICATE_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.CERTIFICATE_LIST_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.CERTIFICATE_PAIR_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.COUNTRY_STRING_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DN_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_LDAP_DN);
        addToSyntaxMap(SchemaConstants.DATA_QUALITY_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DELIVERY_METHOD_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DIRECTORY_STRING_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DIT_CONTENT_RULE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DIT_STRUCTURE_RULE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DL_SUBMIT_PERMISSION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DSA_QUALITY_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DSE_TYPE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.ENHANCED_GUIDE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.FACSIMILE_TELEPHONE_NUMBER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.FAX_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.GENERALIZED_TIME_SYNTAX, ZonedDateTime.class); // but this may be changed by the configuration
        addToSyntaxMap(SchemaConstants.GUIDE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.IA5_STRING_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.INTEGER_SYNTAX, BigInteger.class);
        addToSyntaxMap(SchemaConstants.JPEG_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.MASTER_AND_SHADOW_ACCESS_POINTS_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.MATCHING_RULE_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.MATCHING_RULE_USE_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.MAIL_PREFERENCE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.MHS_OR_ADDRESS_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.NAME_AND_OPTIONAL_UID_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.NAME_FORM_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.NUMERIC_STRING_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OBJECT_CLASS_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OID_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OTHER_MAILBOX_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.OCTET_STRING_SYNTAX, byte[].class);
        addToSyntaxMap(SchemaConstants.POSTAL_ADDRESS_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.PROTOCOL_INFORMATION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.PRESENTATION_ADDRESS_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.PRINTABLE_STRING_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SUBTREE_SPECIFICATION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SUPPLIER_INFORMATION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SUPPLIER_OR_CONSUMER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SUPPLIER_AND_CONSUMER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SUPPORTED_ALGORITHM_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.TELEPHONE_NUMBER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.TELETEX_TERMINAL_IDENTIFIER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.TELEX_NUMBER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.UTC_TIME_SYNTAX, ZonedDateTime.class);
        addToSyntaxMap(SchemaConstants.LDAP_SYNTAX_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.MODIFY_RIGHTS_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.LDAP_SCHEMA_DEFINITION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.LDAP_SCHEMA_DESCRIPTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SUBSTRING_ASSERTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.ATTRIBUTE_CERTIFICATE_ASSERTION_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.UUID_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.CSN_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.CSN_SID_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.JAVA_BYTE_SYNTAX, byte.class);
        addToSyntaxMap(SchemaConstants.JAVA_CHAR_SYNTAX, char.class);
        addToSyntaxMap(SchemaConstants.JAVA_SHORT_SYNTAX, short.class);
        addToSyntaxMap(SchemaConstants.JAVA_LONG_SYNTAX, long.class);
        addToSyntaxMap(SchemaConstants.JAVA_INT_SYNTAX, int.class);
        addToSyntaxMap(SchemaConstants.COMPARATOR_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.NORMALIZER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SYNTAX_CHECKER_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.SEARCH_SCOPE_SYNTAX, String.class);
        addToSyntaxMap(SchemaConstants.DEREF_ALIAS_SYNTAX, String.class);
        addToSyntaxMap(SYNTAX_AUTH_PASSWORD, String.class);
        addToSyntaxMap(SYNTAX_COLLECTIVE_CONFLICT_BEHAVIOR, String.class);
        addToSyntaxMap(SYNTAX_SUN_DEFINED_ACCESS_CONTROL_INFORMATION, String.class);
        addToSyntaxMap(SYNTAX_NIS_NETGROUP_TRIPLE_SYNTAX, String.class);
        addToSyntaxMap(SYNTAX_NIS_BOOT_PARAMETER_SYNTAX, String.class);
        addToSyntaxMap(SYNTAX_AD_CASE_IGNORE_STRING_TELETEX_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_CASE_IGNORE);
        addToSyntaxMap(SYNTAX_AD_CASE_IGNORE_STRING_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_CASE_IGNORE);
        addToSyntaxMap(SYNTAX_AD_DN_WITH_STRING_SYNTAX, String.class);
        addToSyntaxMap(SYNTAX_AD_DN_WITH_BINARY_SYNTAX, String.class);
        addToSyntaxMap(SYNTAX_AD_OBJECT_DS_DN, String.class);
        addToSyntaxMap(SYNTAX_AD_STRING_OBJECT_IDENTIFIER, String.class);
        addToSyntaxMap(SYNTAX_AD_STRING_CASE, String.class);
        addToSyntaxMap(SYNTAX_AD_STRING_TELETEX, String.class);
        addToSyntaxMap(SYNTAX_AD_STRING_IA5, String.class);
        addToSyntaxMap(SYNTAX_AD_STRING_NUMERIC, String.class);
        addToSyntaxMap(SYNTAX_AD_OBJECT_DN_BINARY, String.class);
        addToSyntaxMap(SYNTAX_AD_ADSTYPE_INTEGER, int.class);
        addToSyntaxMap(SYNTAX_AD_INTEGER8_SYNTAX, long.class);
        addToSyntaxMap(SYNTAX_AD_LARGE_INTEGER, long.class);
        addToSyntaxMap(SYNTAX_AD_ADSTYPE_OCTET_STRING, byte[].class);
        addToSyntaxMap(SYNTAX_AD_SECURITY_DESCRIPTOR_SYNTAX, byte[].class);
        addToSyntaxMap(SYNTAX_AD_ADSTYPE_NT_SECURITY_DESCRIPTOR, byte[].class);
        addToSyntaxMap(SYNTAX_AD_ADSTYPE_BOOLEAN, Boolean.class);
        addToSyntaxMap(SYNTAX_AD_UTC_TIME, ZonedDateTime.class);
        addToSyntaxMap(SYNTAX_AD_STRING_UNICODE, String.class);
        addToSyntaxMap(SYNTAX_AD_OBJECT_PRESENTATION_ADDRESS, String.class);
        addToSyntaxMap(SYNTAX_AD_OBJECT_ACCESS_POINT, String.class);
        // Even though this is "String(Sid)", it is not really string. It is binary as long as LDAP is concerned.
        // But we convert that in the connector to a string form. Therefore the ConnId it really can see as String.
        addToSyntaxMap(SYNTAX_AD_STRING_SID, String.class);

        // AD strangeness
        addToSyntaxMap("OctetString", byte[].class);

        // Make sure that these attributes are always resolved as string attributes
        // These are mostly root DSE attributes
        // WARNING: all attribute names must be in lowercase
        STRING_ATTRIBUTE_NAMES.add("namingcontexts");
        STRING_ATTRIBUTE_NAMES.add("defaultnamingcontext");
        STRING_ATTRIBUTE_NAMES.add("schemanamingcontext");
        STRING_ATTRIBUTE_NAMES.add("supportedcontrol");
        STRING_ATTRIBUTE_NAMES.add("configurationnamingcontext");
        STRING_ATTRIBUTE_NAMES.add("rootdomainnamingcontext");
        STRING_ATTRIBUTE_NAMES.add("supportedldapversion");
        STRING_ATTRIBUTE_NAMES.add("supportedldappolicies");
        STRING_ATTRIBUTE_NAMES.add("supportedsaslmechanisms");
        STRING_ATTRIBUTE_NAMES.add("highestcommittedusn");
        STRING_ATTRIBUTE_NAMES.add("ldapservicename");
        STRING_ATTRIBUTE_NAMES.add("supportedcapabilities");
        STRING_ATTRIBUTE_NAMES.add("issynchronized");
        STRING_ATTRIBUTE_NAMES.add("isglobalcatalogready");
        STRING_ATTRIBUTE_NAMES.add("domainfunctionality");
        STRING_ATTRIBUTE_NAMES.add("forestfunctionality");
        STRING_ATTRIBUTE_NAMES.add("domaincontrollerfunctionality");
        STRING_ATTRIBUTE_NAMES.add("currenttime");
        STRING_ATTRIBUTE_NAMES.add("dsservicename");
        STRING_ATTRIBUTE_NAMES.add(ATTRIBUTE_389DS_FIRSTCHANGENUMBER.toLowerCase());
        STRING_ATTRIBUTE_NAMES.add(ATTRIBUTE_389DS_LASTCHANGENUMBER.toLowerCase());

    }

    public Map<String, Set<AssociationHolder>> getObjectAssociationSets() {

        if(objectAssociationSets !=null && !objectAssociationSets.isEmpty()){

            return objectAssociationSets;
        } else {

            constructAssociationSets();
            return objectAssociationSets;
        }
    }

    public Map<String, Set<AssociationHolder>> getSubjectAssociationSets() {

        if(subjectAssociationSets !=null && !subjectAssociationSets.isEmpty()){

            return subjectAssociationSets;
        } else {

            constructAssociationSets();
            return subjectAssociationSets;
        }
    }
}
