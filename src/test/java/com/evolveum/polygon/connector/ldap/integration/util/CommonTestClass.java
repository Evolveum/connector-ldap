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

package com.evolveum.polygon.connector.ldap.integration.util;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.SortKey;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommonTestClass implements ObjectConstants {

    private static final Log LOG = Log.getLog(CommonTestClass.class);
    protected final PropertiesParser parser = new PropertiesParser();
    protected LdapConfiguration ldapConfiguration = new LdapConfiguration();
    protected LdapConnector ldapConnector = new LdapConnector();

    public CommonTestClass() {
        init();
    }

    protected LdapConfiguration initializeAndFetchLDAPConfiguration() {

        ldapConfiguration = new LdapConfiguration();

        ldapConfiguration.setHost(parser.getHost());
        ldapConfiguration.setPort(parser.getPort());
        ldapConfiguration.setBindDn(parser.getBindDn());
        ldapConfiguration.setBindPassword(parser.getBindPassword());
        ldapConfiguration.setBaseContext(parser.getBaseContext());
        ldapConfiguration.setPasswordHashAlgorithm(parser.getPasswordHashAlgorithm());
        ldapConfiguration.setPagingStrategy(parser.getPagingStrategy());
        ldapConfiguration.setVlvSortAttribute(parser.getVlvSortAttribute());

        ldapConfiguration.setVlvSortOrderingRule(parser.getVlvSortOrderingRule());
        ldapConfiguration.setUsePermissiveModify(parser.getUsePermissiveModify());
        ldapConfiguration.setManagedAssociationPairs(parser.getManagedAssociationPairs());
        ldapConfiguration.setOperationalAttributes(parser.getOperationalAttributes());
        ldapConfiguration.setLockoutStrategy(parser.getLockoutStrategy());

        ldapConfiguration.validate();
        return ldapConfiguration;
    }

    protected TestSearchResultsHandler getSearchResultHandler() {

        return new TestSearchResultsHandler();
    }

    protected TestSyncResultsHandler getSyncResultHandler() {

        return new TestSyncResultsHandler();
    }


    protected OperationOptions getDefaultOperationOptions(String objectClassName) {

        return getDefaultOperationOptions(objectClassName, null, null,
                null, null, true, true);
    }

    protected OperationOptions getDefaultOperationOptions(String objectClassName, List<String> attrsToGet) {

        return getDefaultOperationOptions(objectClassName, attrsToGet, null,
                null, null, true, true);
    }

    protected OperationOptions getDefaultOperationOptions(String objectClassName, List<String> attrsToGet
            , String pageCookie, Integer pageOffset, Integer pageSize, Boolean defaultAttributes,
                                                          Boolean allowPartialAttributeValues) {


        Map<String, Object> operationOptions = new HashMap<>();


        if (pageOffset != null) {

            operationOptions.put(OperationOptions.OP_PAGED_RESULTS_OFFSET, pageOffset);
        }

        if (pageSize != null) {

            operationOptions.put(OperationOptions.OP_PAGE_SIZE, pageSize);
        }

        if (pageCookie != null) {

            operationOptions.put(OperationOptions.OP_PAGED_RESULTS_COOKIE, pageCookie);
        }

        if (defaultAttributes != null) {

            operationOptions.put(OperationOptions.OP_RETURN_DEFAULT_ATTRIBUTES,defaultAttributes);
        }

        if (attrsToGet != null) {

            operationOptions.put(OperationOptions.OP_ATTRIBUTES_TO_GET,attrsToGet.toArray(new String[attrsToGet.size()]));
        }

        if (allowPartialAttributeValues != null) {

            operationOptions.put(OperationOptions.OP_ALLOW_PARTIAL_ATTRIBUTE_VALUES,allowPartialAttributeValues);
        }
        if (allowPartialAttributeValues != null) {

            operationOptions.put(OperationOptions.OP_SORT_KEYS,CollectionUtil.newList(new SortKey("cn",
                    true)).toArray(new SortKey[0]));
        }

        OperationOptions options = new OperationOptions(operationOptions);

        return options;
    }

    @BeforeMethod
    protected void init() {
        ldapConnector = new LdapConnector();
        initializeAndFetchLDAPConfiguration();
    }

    @AfterMethod
    protected void cleanup() {
        ldapConnector.dispose();
    }

}
