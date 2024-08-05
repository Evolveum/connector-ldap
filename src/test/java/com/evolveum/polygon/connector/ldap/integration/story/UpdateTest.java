/*
 * Copyright (c) 2010-2023 Evolveum
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

package com.evolveum.polygon.connector.ldap.integration.story;


import com.evolveum.polygon.connector.ldap.integration.util.CommonTestClass;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.testng.annotations.Test;

import java.rmi.server.UID;
import java.util.*;

public class UpdateTest extends CommonTestClass {
    private static final Log LOG = Log.getLog(UpdateTest.class);

    @Test()
    public void updateAddInetOrgPersonGroupOfNamesReference() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<AttributeDelta> attributesUpdateGroup = new HashSet<>();

        ConnectorObjectReference connectorObjectReference = new ConnectorObjectReference(buildConnectorObject(
                "cn=all-users-test,ou=groups,dc=example,dc=com", "dee9735e-e299-103e-9005-ff6f76f1f206"));

        attributesUpdateGroup.add(AttributeDeltaBuilder.build(ATTR_NAME_REF_SUBJECT, Collections.singletonList(connectorObjectReference),
                null));
        ObjectClass objectClassAccount = new ObjectClass(OC_NAME_INET_ORG_PERSON);

        ldapConnector.updateDelta(objectClassAccount, new Uid("1db3c63c-dd33-103e-9a58-d35fa81d9727"), attributesUpdateGroup, options);
    }

    @Test()
    public void updateRemoveInetOrgPersonGroupOfNamesReference() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<AttributeDelta> attributesUpdateGroup = new HashSet<>();

        ConnectorObjectReference connectorObjectReference = new ConnectorObjectReference(buildConnectorObject(
                "cn=all-users-test,ou=groups,dc=example,dc=com", "dee9735e-e299-103e-9005-ff6f76f1f206"));

        attributesUpdateGroup.add(AttributeDeltaBuilder.build(ATTR_NAME_REF_SUBJECT, null,
                Collections.singletonList(connectorObjectReference)));
        ObjectClass objectClassAccount = new ObjectClass(OC_NAME_INET_ORG_PERSON);

        ldapConnector.updateDelta(objectClassAccount, new Uid("1db3c63c-dd33-103e-9a58-d35fa81d9727"), attributesUpdateGroup, options);
    }

    @Test()
    public void updateReplaceInetOrgPersonGroupOfNamesReference() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<AttributeDelta> attributesUpdateGroup = new HashSet<>();

        ConnectorObjectReference connectorObjectReferenceKeep = new ConnectorObjectReference(buildConnectorObject(
                "cn=all-users-test,ou=groups,dc=example,dc=com", "dee9735e-e299-103e-9005-ff6f76f1f206"));

        ConnectorObjectReference connectorObjectReferenceAdd = new ConnectorObjectReference(buildConnectorObject(
                "cn=administrators,ou=groups,dc=example,dc=com", "1e11fb6c-dd33-103e-9a81-d35fa81d9727"));

        ArrayList<ConnectorObjectReference> references = new ArrayList<>();
        references.add(connectorObjectReferenceAdd);
        references.add(connectorObjectReferenceKeep);

        attributesUpdateGroup.add(AttributeDeltaBuilder.build(ATTR_NAME_REF_SUBJECT, references));
        ObjectClass objectClassAccount = new ObjectClass(OC_NAME_INET_ORG_PERSON);

        ldapConnector.updateDelta(objectClassAccount, new Uid("1db3c63c-dd33-103e-9a58-d35fa81d9727"), attributesUpdateGroup, options);
    }

    @Test()
    public void updateReplaceGroupOfNamesGroupOfNamesReference() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<AttributeDelta> attributesUpdateGroup = new HashSet<>();

        ConnectorObjectReference connectorObjectReferenceKeep = new ConnectorObjectReference(buildConnectorObject(
                "cn=super-administrators,ou=groups,dc=example,dc=com", "9895879c-e6c4-103e-8a99-81358095b3c8"));

        ConnectorObjectReference connectorObjectReferenceAdd = new ConnectorObjectReference(buildConnectorObject(
                "cn=all-users,ou=groups,dc=example,dc=com", "9893955e-e6c4-103e-8a97-81358095b3c8"));

        ArrayList<ConnectorObjectReference> references = new ArrayList<>();
        references.add(connectorObjectReferenceAdd);
        references.add(connectorObjectReferenceKeep);

        attributesUpdateGroup.add(AttributeDeltaBuilder.build(ATTR_NAME_REF_SUBJECT, references));
        ObjectClass objectClassAccount = new ObjectClass(OC_NAME_GROUP_OF_NAMES);

        ldapConnector.updateDelta(objectClassAccount, new Uid("989496ac-e6c4-103e-8a98-81358095b3c8"), attributesUpdateGroup, options);
    }

    @Test()
    public void updateGroupMemberAttribute() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConfiguration.setManagedAssociationPairs(new String[0]);
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<AttributeDelta> attributesUpdateGroup = new HashSet<>();
        attributesUpdateGroup.add(AttributeDeltaBuilder.build("member", Collections.singletonList("cn=Charles Whitehead,ou=users,dc=example,dc=com"),
                null));
        ObjectClass objectClassAccount = new ObjectClass("groupOfNames");

        ldapConnector.updateDelta(objectClassAccount, new Uid("b4fee9d8-ccb5-103e-9bc1-3f7c99bf69c3"), attributesUpdateGroup, options);
    }


}

