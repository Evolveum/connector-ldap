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
import com.evolveum.polygon.connector.ldap.integration.util.TestSearchResultsHandler;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.*;

public class CreateTests extends CommonTestClass {
    private static final Log LOG = Log.getLog(CreateTests.class);

    @Test()
    public void createUser() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        GuardedString pass = new GuardedString("Password99".toCharArray());
        Set<Attribute> attributesAccount = new HashSet<>();
        attributesAccount.add(AttributeBuilder.build(Name.NAME, "cn=Ania Baker,ou=users,dc=example,dc=com"));
        attributesAccount.add(AttributeBuilder.build("initials", "aj"));
        attributesAccount.add(AttributeBuilder.build("displayName", "Bakera"));
        attributesAccount.add(AttributeBuilder.build("uid", "bakera"));
        attributesAccount.add(AttributeBuilder.build("userPassword", pass));
        attributesAccount.add(AttributeBuilder.build("title", "Tester"));
        attributesAccount.add(AttributeBuilder.build("sn", "Baker"));
        attributesAccount.add(AttributeBuilder.build("cn", "Ania"));
        attributesAccount.add(AttributeBuilder.build("l", "SR"));
        attributesAccount.add(AttributeBuilder.build("givenName", "Ania"));
        attributesAccount.add(AttributeBuilder.build("employeeNumber", "123322999"));
        ObjectClass objectClassAccount = new ObjectClass(OC_NAME_INET_ORG_PERSON);

        Uid testUid = ldapConnector.create(objectClassAccount, attributesAccount, options);
    }

    @Test()
    public void createGroup() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        Set<Attribute> attributesGroup = new HashSet<>();
        attributesGroup.add(AttributeBuilder.build(Name.NAME, "cn=some-users-test-2,ou=groups,dc=example,dc=com"));
        attributesGroup.add(AttributeBuilder.build("cn", "some-users-test-1"));
        attributesGroup.add(AttributeBuilder.build("member", Collections.singletonList("cn=dummy,o=whatever")));

        ObjectClass objectClassAccount = new ObjectClass(OC_NAME_GROUP_OF_NAMES);

        Uid testUid = ldapConnector.create(objectClassAccount, attributesGroup, options);
    }
}

