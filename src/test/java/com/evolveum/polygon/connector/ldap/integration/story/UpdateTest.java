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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class UpdateTest extends CommonTestClass {
    private static final Log LOG = Log.getLog(UpdateTest.class);

    @Test()
    public void updateGroupObjectReference() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<AttributeDelta> attributesUpdateGroup = new HashSet<>();
        ConnectorObjectBuilder cob = new ConnectorObjectBuilder();

        ConnectorObjectReference connectorObjectReference = new ConnectorObjectReference(buildConnectorObject());

        attributesUpdateGroup.add(AttributeDeltaBuilder.build("inetOrgPerson", Collections.singletonList(connectorObjectReference),
                null));
        ObjectClass objectClassAccount = new ObjectClass("groupOfNames");

        ldapConnector.updateDelta(objectClassAccount, new Uid("b4fee9d8-ccb5-103e-9bc1-3f7c99bf69c3"), attributesUpdateGroup, options);
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

    ConnectorObject buildConnectorObject(){
        ConnectorObjectBuilder cob = new ConnectorObjectBuilder();

        cob.addAttribute((new AttributeBuilder().setName(Name.NAME).addValue("cn=Charles Whitehead,ou=users,dc=example,dc=com")).build());
        cob.addAttribute((new AttributeBuilder().setName(Uid.NAME).addValue("b4cd0ddc-ccb5-103e-9b9e-3f7c99bf69c3")).build());
        cob.setObjectClass(new ObjectClass("inetOrgPerson"));

        return cob.build();
    }
}

