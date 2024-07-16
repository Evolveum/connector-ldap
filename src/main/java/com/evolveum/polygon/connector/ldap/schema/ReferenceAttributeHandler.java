package com.evolveum.polygon.connector.ldap.schema;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.OperationLog;
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
    private SearchStrategy<LdapConfiguration> searchStrategy;
    private ConnectorObjectBuilder connectorObjectBuilder;
    private AbstractLdapConfiguration configuration;
    private AbstractSchemaTranslator translator;

    public ReferenceAttributeHandler(AbstractLdapConfiguration configuration,
                                     SearchStrategy<LdapConfiguration> searchStrategy, AbstractSchemaTranslator translator) {
        this.searchStrategy = searchStrategy;
        this.configuration = configuration;
        this.translator = translator;
    }

    @Override
    public void handle(LdapNetworkConnection connection, Entry entry, Attribute ldapAttribute, AttributeBuilder ab) {

        String ldapAttributeName = ldapAttribute.getId();
        AttributeType attributeType = ldapAttribute.getAttributeType();
        Iterator<Value> iterator = ldapAttribute.iterator();
        String uidAttr = configuration.getUidAttribute();
        String nameAttr = configuration.PSEUDO_ATTRIBUTE_DN_NAME;
        Map<String, AttributeBuilder> referenceAttributes = new HashMap<>();

        while (iterator.hasNext()) {
            Value ldapValue = iterator.next();
            String syntaxOid = null;
            String tanslatedValue = null;
            if (ldapAttribute != null) {
                syntaxOid = attributeType.getSyntaxOid();
            }

            if (isStringSyntax(syntaxOid)) {
                LOG.ok("Converting: {0} (syntax {1}, value {2}): explicit string", ldapAttributeName, syntaxOid, ldapValue.getClass());
                tanslatedValue = ldapValue.getString();
            } else if (ldapValue.isHumanReadable()) {
                LOG.ok("Converting: {0} (syntax {1}, value {2}): detected string", ldapAttributeName, syntaxOid, ldapValue.getClass());
                tanslatedValue = ldapValue.getString();
            } else {

                ///           // TODO   #A warning or error?
                LOG.error("Could not handle the value of association attribute: {0}. Syntax non interpretable as" +
                        " string is not supported.", ldapAttributeName);
                return;
            }

            if (tanslatedValue != null && !tanslatedValue.isEmpty()) {

                if(!shouldValueBeIncluded(tanslatedValue, ldapAttributeName)){

                    continue;
                }

                Entry referencedEntry = null;
                OperationLog.logOperationReq(connection, "Search REQ identificator={0}, filter={1}, scope={2}",
                        tanslatedValue, AbstractLdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT);

                try {
                    ///TODO #A
                    referencedEntry = connection.lookup(tanslatedValue, uidAttr, nameAttr);

                    if (referencedEntry == null) {
                        OperationLog.logOperationErr(connection, "Entry not found for {0}", tanslatedValue);
                        throw searchStrategy.getErrorHandler().processLdapException("Reference search for " + tanslatedValue + " failed",
                                new LdapNoSuchObjectException("No entry found for " + tanslatedValue));
                    }
                    ConnectorObject referencedObject = translator.toConnIdObject(connection, null, entry);
                    ConnectorObjectReference connectorObjectReference = new ConnectorObjectReference(referencedObject);
                    String attributeName = referencedObject.getObjectClass().getDisplayNameKey();

                    if (!referenceAttributes.isEmpty()) {
                        if (referenceAttributes.containsKey(attributeName)) {

                            AttributeBuilder attributeBuilder = referenceAttributes.get(attributeName);
                            attributeBuilder.addValue(connectorObjectReference);
                            referenceAttributes.put(attributeName, attributeBuilder);
                        }
                    } else {

                        AttributeBuilder attributeBuilder = new AttributeBuilder();
                        attributeBuilder.addValue(connectorObjectReference);
                        attributeBuilder.setName(attributeName);

                        referenceAttributes.put(attributeName, attributeBuilder);
                    }

                } catch (LdapException e) {
                    OperationLog.logOperationErr(connection, "Search ERR {0}: {1}", e.getClass().getName(),
                            e.getMessage(), e);
                    searchStrategy.getConnectionLog().error(connection, "search", e, tanslatedValue
                            + " OBJECT " + AbstractLdapConfiguration.SEARCH_FILTER_ALL);
                    throw searchStrategy.getErrorHandler().processLdapException("Range search for " + tanslatedValue +
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

    ///           // TODO   #A copy, create some utility class and port there?
    protected boolean isStringSyntax(String syntaxOid) {
        if (syntaxOid == null) {
            // If there is no syntax information we assume that is is string type
            return true;
        }
        switch (syntaxOid) {
            case SchemaConstants.DIRECTORY_STRING_SYNTAX:
            case SchemaConstants.IA5_STRING_SYNTAX:
            case SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX:
            case SchemaConstants.DN_SYNTAX:
            case SchemaConstants.PRINTABLE_STRING_SYNTAX:
                return true;
            default:
                return false;
        }
    }

    ///           // TODO   #A copy, create some utility class and port there?
    private boolean shouldValueBeIncluded(Object connIdValue, String ldapAttributeNameFromSchema) {
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

    public void setConnectorObjectBuilder(ConnectorObjectBuilder connectorObjectBuilder) {
        this.connectorObjectBuilder = connectorObjectBuilder;
    }
}
