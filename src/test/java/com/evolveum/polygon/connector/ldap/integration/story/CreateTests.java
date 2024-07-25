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
        attributesAccount.add(AttributeBuilder.build(Name.NAME, "cn=John Johnson,ou=users,dc=example,dc=com"));
        attributesAccount.add(AttributeBuilder.build("initials", "jj"));
        attributesAccount.add(AttributeBuilder.build("displayName", "Johnson"));
        attributesAccount.add(AttributeBuilder.build("uid", "johnsonj"));
        attributesAccount.add(AttributeBuilder.build("userPassword", pass));
        attributesAccount.add(AttributeBuilder.build("title", "Tester"));
        attributesAccount.add(AttributeBuilder.build("sn", "Johnson"));
        attributesAccount.add(AttributeBuilder.build("cn", "John"));
        attributesAccount.add(AttributeBuilder.build("l", "SR"));
        attributesAccount.add(AttributeBuilder.build("givenName", "John"));
        attributesAccount.add(AttributeBuilder.build("employeeNumber", "123321899"));
        ObjectClass objectClassAccount = new ObjectClass("inetOrgPerson");

        Uid testUid = ldapConnector.create(objectClassAccount, attributesAccount, options);
    }

    @Test()
    public void createGroup() {

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);

        OperationOptions options = new OperationOptions(new HashMap<>());

        GuardedString pass = new GuardedString("Password99".toCharArray());
        Set<Attribute> attributesAccount = new HashSet<>();
        attributesAccount.add(AttributeBuilder.build(Name.NAME, "cn=John Johnson,ou=users,dc=example,dc=com"));
        attributesAccount.add(AttributeBuilder.build("initials", "jj"));
        attributesAccount.add(AttributeBuilder.build("displayName", "Johnson"));
        attributesAccount.add(AttributeBuilder.build("uid", "johnsonj"));
        attributesAccount.add(AttributeBuilder.build("userPassword", pass));
        attributesAccount.add(AttributeBuilder.build("title", "Tester"));
        attributesAccount.add(AttributeBuilder.build("sn", "Johnson"));
        attributesAccount.add(AttributeBuilder.build("cn", "John"));
        attributesAccount.add(AttributeBuilder.build("l", "SR"));
        attributesAccount.add(AttributeBuilder.build("givenName", "John"));
        attributesAccount.add(AttributeBuilder.build("employeeNumber", "123321899"));
        ObjectClass objectClassAccount = new ObjectClass("inetOrgPerson");

        Uid testUid = ldapConnector.create(objectClassAccount, attributesAccount, options);
    }
}

