package com.evolveum.polygon.connector.ldap.schema;

import com.evolveum.polygon.connector.ldap.*;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import java.util.*;


public class ReferenceAttributeHandler implements AttributeHandler {

    private static final Log LOG = Log.getLog(ReferenceAttributeHandler.class);
    private ErrorHandler errorHandler;
    private ConnectorObjectBuilder connectorObjectBuilder;
    private AbstractLdapConfiguration configuration;
    private AbstractSchemaTranslator translator;
    private ObjectClass objectClass;

    public ReferenceAttributeHandler(AbstractLdapConfiguration configuration,
                                     ErrorHandler errorHandler, AbstractSchemaTranslator translator, ObjectClass objectClass) {
        this.errorHandler = errorHandler;
        this.configuration = configuration;
        this.translator = translator;
        this.objectClass = objectClass;
    }

    @Override
    public void handle(LdapNetworkConnection connection, Entry entry, Attribute ldapAttribute, AttributeBuilder ab) {
        String ldapAttributeName = ldapAttribute.getId();

        AttributeType attributeType = ldapAttribute.getAttributeType();
        Iterator<Value> iterator = ldapAttribute.iterator();
        Map<String, Set<AssociationHolder>> objectAssociationSets = translator.getObjectAssociationSets();
        Map<String, Set<AssociationHolder>> subjectAssociationSets = translator.getSubjectAssociationSets();
        String objectClassName = objectClass.getObjectClassValue();
        String referenceAttributeName= null;
        String syntaxOid = null;
        if (ldapAttribute != null) {
            if (attributeType != null) {

                syntaxOid = attributeType.getSyntaxOid();
            }
        }

        Map<String, AttributeBuilder> referenceAttributes = new HashMap<>();
        Boolean isSubject = false;
        //Set<String> validReferenceObjectClasses;


        if (subjectAssociationSets.containsKey(objectClassName)) {

            isSubject = true;
            Set<AssociationHolder> holders = subjectAssociationSets.get(objectClassName);
            for (AssociationHolder holder : holders) {
                if (objectClassName.equals(holder.getSubjectObjectClassName())) {
                    if (ldapAttributeName != null && ldapAttributeName.
                            equalsIgnoreCase(holder.getAssociationAttributeName())) {

                        referenceAttributeName = holder.getName();
                    }
                }
            }
        }

        if (objectAssociationSets.containsKey(objectClassName)) {

            if (isSubject) {

                Set<AssociationHolder> holders = objectAssociationSets.get(objectClassName);
                // In this case we are iterating through the members parameter of an OC which can be both subject and object
                for (AssociationHolder holder : holders) {
                    if (objectClassName.equals(holder.getSubjectObjectClassName())) {
                        if (ldapAttributeName != null && ldapAttributeName.
                                equalsIgnoreCase(holder.getAssociationAttributeName())) {
                            referenceAttributeName = holder.getName();
                            isSubject = false;
                        }
                    }
                }
            }
        }


        if (iterator != null) {

            while (iterator.hasNext()) {
                Value ldapValue = iterator.next();
                String tanslatedValue;

                if (translator.isStringSyntax(syntaxOid)) {

                    LOG.ok("Converting: {0} (syntax {1}, value {2}): explicit string", ldapAttributeName, syntaxOid, ldapValue.getClass());
                    tanslatedValue = ldapValue.getString();
                } else if (ldapValue.isHumanReadable()) {

                    LOG.ok("Converting: {0} (syntax {1}, value {2}): detected string", ldapAttributeName, syntaxOid, ldapValue.getClass());
                    tanslatedValue = ldapValue.getString();
                } else {

                    LOG.error("Could not handle the value of association attribute: {0}. Syntax non interpretable as" +
                            " string is not supported.", ldapAttributeName);

                    return;
                }

                if (tanslatedValue != null && !tanslatedValue.isEmpty()) {


                    if (!translator.shouldValueBeIncluded(tanslatedValue, ldapAttributeName)) {

                        continue;
                    }

//                    Entry referencedEntry = null;
//                    OperationLog.logOperationReq(connection, "Search REQ identificator={0}, filter={1}, scope={2}",
//                            tanslatedValue, AbstractLdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT);

//                    try {

                    /// TODO # A this should not happen, or will only be reserved to "non MemberOf" deployments
                    /// referencedEntry = connection.lookup(tanslatedValue, uidAttr, nameAttr, SchemaConstants.OBJECT_CLASS_AT);

//                        if (referencedEntry == null) {
//
//                            ///TODO #A include this or add exclude to config?? What OC should it have ???
//                            if ("cn=dummy,o=whatever".equals(tanslatedValue)) {
//
//                                continue;
//                            }
//
//                            OperationLog.logOperationErr(connection, "Entry not found for {0}", tanslatedValue);
//                            throw errorHandler.processLdapException("Reference search for " + tanslatedValue + " failed",
//                                    new LdapNoSuchObjectException("No entry found for " + tanslatedValue));
//                        }
//                        ConnectorObject referencedObject = translator.toConnIdObject(connection, null, referencedEntry);

//                        String referencedObjectObjectClassName = referencedObject.getObjectClass().getObjectClassValue();

//                        if (!validReferenceObjectClasses.contains(referencedObjectObjectClassName)) {
//
//                            continue;
//                        }
                    ConnectorObjectIdentification connectorObjectIdentification = null;

                    if (!isSubject) {

                        connectorObjectIdentification = new ConnectorObjectIdentification(null, constructIDAttributes(tanslatedValue));
                    } else {

                        //TODO this might be eventually removed if this is done by the IAM
                        /// TODO # A change the current definition of the map from set to only single objects?
                        String targetOcName = null;
                        Set<AssociationHolder> targets = (Set<AssociationHolder>) translator.getSubjectAssociationSets()
                                .get(objectClass.getObjectClassValue());

                            LOG.ok("### The ldap attr name {0}", ldapAttributeName);
                        for (AssociationHolder target : targets) {

                            /// Assuming that each OC would have a different association attribute (memberOf, uniqueMember)

                            LOG.ok("### The asoc attr name {0}", target.getAssociationAttributeName());
                            if(ldapAttributeName.equalsIgnoreCase(target.getAssociationAttributeName())){
                                targetOcName = target.getObjectObjectClassName();
                                break;
                            }

                        }

                        connectorObjectIdentification = new ConnectorObjectIdentification(new ObjectClass(targetOcName),
                                constructIDAttributes(tanslatedValue));
                    }


                    ConnectorObjectReference connectorObjectReference =
                            new ConnectorObjectReference(connectorObjectIdentification);
// TODO # A test
//                    String referenceAttributeName = constructReferenceAttributeName(isSubject);

//                        if (!referenceAttributes.isEmpty()) {


                    if (referenceAttributes.containsKey(referenceAttributeName)) {

                        AttributeBuilder attributeBuilder = referenceAttributes.get(referenceAttributeName);
                        attributeBuilder.addValue(connectorObjectReference);
                        referenceAttributes.put(referenceAttributeName, attributeBuilder);
                    } else {

                        AttributeBuilder attributeBuilder = new AttributeBuilder();
                        attributeBuilder.addValue(connectorObjectReference);
                        attributeBuilder.setName(referenceAttributeName);

                        referenceAttributes.put(referenceAttributeName, attributeBuilder);
                    }
                }
            }
        }


        if (!referenceAttributes.isEmpty()) {

            for (AttributeBuilder referenceAttribute : referenceAttributes.values()) {

                connectorObjectBuilder.addAttribute(referenceAttribute.build());
            }
        }
    }

//    private String constructReferenceAttributeName(Boolean isSubject) {
//
//        if (isSubject) {
//
//            return "group";
//        } else {
//
//            return "members";
//        }
//    }

    private Set<? extends org.identityconnectors.framework.common.objects.Attribute>
    constructIDAttributes(String tanslatedValue) {

        //TODO # A check syntax, set name accordingly (can be different in case of other object Classes)

        Set<org.identityconnectors.framework.common.objects.Attribute> idAttributes = new HashSet<>();

        org.identityconnectors.framework.common.objects.Attribute attribute =
                new AttributeBuilder().setName(Name.NAME).addValue(Collections.singleton(tanslatedValue)).build();
        idAttributes.add(attribute);

        return idAttributes;
    }

    private void fetchEntryMemberships(LdapNetworkConnection connection, Entry entry,
                                       Set<String> objectClassNames) {

        String dn = translator.getDn(entry);
        SearchScope scope = configuration.getDefaultSearchScope() == AbstractLdapConfiguration.SEARCH_SCOPE_SUB ?
                SearchScope.SUBTREE : SearchScope.ONELEVEL;
        Dn base = translator.toDn(configuration.getBaseContext());

//        LdapFilterTranslator filterTranslator =
        // Multiple requests or a filter requesting multiple objectClasses ?


        SearchRequest req = new SearchRequestImpl();
        req.setBase(base);
        req.setScope(scope);
        req.setFilter(prepareFilter(dn, objectClassNames).getFilter());

        // TODO # A execute search (e.g. check search strategies)
    }

    private ScopedFilter prepareFilter(String dn,
                                       Set<String> objectClassNames) {

        List<ExprNode> ocNodes = List.of();
        String nameForAttrTranslation = null;

        for (String name : objectClassNames) {

            ocNodes.add(new EqualityNode<>(SchemaConstants.OBJECT_CLASS_AT, name));

            if (nameForAttrTranslation == null) {

                nameForAttrTranslation = name;
            }
        }

        // TODO # A group member list attr name to be used here
        EqualityNode memberNode = new EqualityNode<>("member", dn);


        OrNode ocNode = new OrNode(ocNodes);
        AndNode andNode = new AndNode(ocNode, memberNode);

        return new ScopedFilter(andNode);

    }

    public void setConnectorObjectBuilder(ConnectorObjectBuilder connectorObjectBuilder) {
        this.connectorObjectBuilder = connectorObjectBuilder;
    }
}
