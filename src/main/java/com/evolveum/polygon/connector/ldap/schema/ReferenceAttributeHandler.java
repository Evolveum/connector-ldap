package com.evolveum.polygon.connector.ldap.schema;

import com.evolveum.polygon.connector.ldap.*;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;



import java.util.*;
import java.util.function.Predicate;

import static com.evolveum.polygon.connector.ldap.LdapConstants.ATTRIBUTE_MEMBER_OF_NAME;

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
        String uidAttr = configuration.getUidAttribute();
        String nameAttr = configuration.PSEUDO_ATTRIBUTE_DN_NAME;
        Map<String, AttributeBuilder> referenceAttributes = new HashMap<>();

        Set<String> validReferenceObjectClasses = new HashSet<>();


        if(configuration.getMembershipAttribute()!=null &&
                configuration.getMembershipAttribute().equalsIgnoreCase(ldapAttributeName)){

            validReferenceObjectClasses = (Set<String>) translator.getMemberAssociationSets().
                    get(objectClass.getObjectClassValue());
        } else if(LdapConstants.MEMBERSHIP_ATTRIBUTES.values().contains(ldapAttributeName)) {

            validReferenceObjectClasses = (Set<String>) translator.getTargetAssociationSets().
                    get(objectClass.getObjectClassValue());
        } else {

            LOG.error("Error, ObjectClass not found in either target nor member set.");
        }

        while (iterator.hasNext()) {
            Value ldapValue = iterator.next();
            String syntaxOid = null;
            String tanslatedValue = null;
            if (ldapAttribute != null) {
                if(attributeType!=null){

                    syntaxOid = attributeType.getSyntaxOid();
                }
            }

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

                if(!translator.shouldValueBeIncluded(tanslatedValue, ldapAttributeName)){

                    continue;
                }

                Entry referencedEntry = null;
                OperationLog.logOperationReq(connection, "Search REQ identificator={0}, filter={1}, scope={2}",
                        tanslatedValue, AbstractLdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT);

                try {

                    referencedEntry = connection.lookup(tanslatedValue, uidAttr, nameAttr, SchemaConstants.OBJECT_CLASS_AT);

                    if (referencedEntry == null) {

                        ///TODO #A add to config??
                        if("cn=dummy,o=whatever".equals(tanslatedValue)){

                            continue;
                        }

                        OperationLog.logOperationErr(connection, "Entry not found for {0}", tanslatedValue);
                        throw errorHandler.processLdapException("Reference search for " + tanslatedValue + " failed",
                                new LdapNoSuchObjectException("No entry found for " + tanslatedValue));
                    }
                    ConnectorObject referencedObject = translator.toConnIdObject(connection, null, referencedEntry);

                    String referencedObjectObjectClassName = referencedObject.getObjectClass().getObjectClassValue();

                    if(!validReferenceObjectClasses.contains(referencedObjectObjectClassName)){

                        continue;
                    }

                    ConnectorObjectReference connectorObjectReference = new ConnectorObjectReference(referencedObject);

                    if (!referenceAttributes.isEmpty()) {


                        if (referenceAttributes.containsKey(referencedObjectObjectClassName)) {

                            AttributeBuilder attributeBuilder = referenceAttributes.get(referencedObjectObjectClassName);
                            attributeBuilder.addValue(connectorObjectReference);
                            referenceAttributes.put(referencedObjectObjectClassName, attributeBuilder);
                        } else {

                            AttributeBuilder attributeBuilder = new AttributeBuilder();
                            attributeBuilder.addValue(connectorObjectReference);
                            attributeBuilder.setName(referencedObjectObjectClassName);

                            referenceAttributes.put(referencedObjectObjectClassName, attributeBuilder);
                        }
                    } else {

                        AttributeBuilder attributeBuilder = new AttributeBuilder();
                        attributeBuilder.addValue(connectorObjectReference);
                        attributeBuilder.setName(referencedObjectObjectClassName);

                        referenceAttributes.put(referencedObjectObjectClassName, attributeBuilder);
                    }

                } catch (LdapException e) {
                    OperationLog.logOperationErr(connection, "Search ERR {0}: {1}", e.getClass().getName(),
                            e.getMessage(), e);
                    throw errorHandler.processLdapException("Search for " + tanslatedValue +
                            " failed", e);
                }
            }
        }

        if(!referenceAttributes.isEmpty()){

            for(AttributeBuilder referenceAttribute : referenceAttributes.values()){

                connectorObjectBuilder.addAttribute(referenceAttribute.build());
            }
        }
    }

    public void setConnectorObjectBuilder(ConnectorObjectBuilder connectorObjectBuilder) {
        this.connectorObjectBuilder = connectorObjectBuilder;
    }
}
