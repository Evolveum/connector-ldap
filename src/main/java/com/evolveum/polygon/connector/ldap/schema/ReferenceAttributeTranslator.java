package com.evolveum.polygon.connector.ldap.schema;

import com.evolveum.polygon.connector.ldap.*;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import java.util.*;
public class ReferenceAttributeTranslator {

    private static final Log LOG = Log.getLog(ReferenceAttributeTranslator.class);
    private ConnectorObjectBuilder connectorObjectBuilder;
    private final AbstractSchemaTranslator translator;
    private ObjectClass objectClass;
    private final OperationOptions options;


    public ReferenceAttributeTranslator(AbstractSchemaTranslator translator, ObjectClass objectClass
            , OperationOptions options) {

        this.translator = translator;
        this.objectClass = objectClass;
        this.options = options;
    }


    public void translate(Attribute ldapAttribute) {
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
            } else {

                referenceAttributeName = LdapConstants.ATTR_SCHEMA_OBJECT;
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

                    ConnectorObjectIdentification connectorObjectIdentification;
                    if (!isSubject) {

                        connectorObjectIdentification = new ConnectorObjectIdentification(null, constructIDAttributes(tanslatedValue));
                    } else {

                        String targetOcName = null;
                        Set<AssociationHolder> targets = (Set<AssociationHolder>) translator.getSubjectAssociationSets()
                                .get(objectClass.getObjectClassValue());
                        for (AssociationHolder target : targets) {

                            /// Assuming that each OC would have a different association attribute (memberOf, uniqueMember)
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

    private Set<? extends org.identityconnectors.framework.common.objects.Attribute>
    constructIDAttributes(String tanslatedValue) {

        Set<org.identityconnectors.framework.common.objects.Attribute> idAttributes = new HashSet<>();
        org.identityconnectors.framework.common.objects.Attribute attribute =
                new AttributeBuilder().setName(Name.NAME).addValue(Collections.singleton(tanslatedValue)).build();
        idAttributes.add(attribute);

        return idAttributes;
    }

    public void setConnectorObjectBuilder(ConnectorObjectBuilder connectorObjectBuilder) {
        this.connectorObjectBuilder = connectorObjectBuilder;
    }

    public ObjectClass getObjectClass() {
        return objectClass;
    }

    public void setObjectClass(ObjectClass objectClass) {
        this.objectClass = objectClass;
    }

}
