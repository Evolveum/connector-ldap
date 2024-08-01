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
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SearchTests extends CommonTestClass {
    private static final Log LOG = Log.getLog(SearchTests.class);

    @Test()
    public void searchAllGroupOfNames() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName());

        OperationOptions options = getDefaultOperationOptions("groupOfNames", attrsToGet, null,
               1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSearchResultsHandler handler = getSearchResultHandler();

        ldapConnector.executeQuery(new ObjectClass("groupOfNames"), null, handler, options);

        ArrayList<ConnectorObject> results = handler.getResult();

        for (ConnectorObject result : results) {

            LOG.info("### START ### Attribute set for the object {0}", result.getName());
            result.getAttributes().forEach(obj -> LOG.info("The attribute: {0}, with value {1}",
                    obj.getName(), obj.getValue()));
            LOG.info("### END ###");

        }
    }

    @Test()
    public void searchAllInetOrgPerson() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName());

        OperationOptions options = getDefaultOperationOptions(OC_NAME_INET_ORG_PERSON, attrsToGet, null,
                1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSearchResultsHandler handler = getSearchResultHandler();

        ldapConnector.executeQuery(new ObjectClass(OC_NAME_INET_ORG_PERSON), null, handler, options);

        ArrayList<ConnectorObject> results = handler.getResult();

        for (ConnectorObject result : results) {

            LOG.info("### START ### Attribute set for the object {0}", result.getName());
            result.getAttributes().forEach(obj -> LOG.info("The attribute: {0}, with value {1}",
                    obj.getName(), obj.getValue()));
            LOG.info("### END ###");

        }
    }

    @Test()
    public void searchByUidGroupOfNames() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName());

        OperationOptions options = getDefaultOperationOptions("groupOfNames", attrsToGet, null,
                1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSearchResultsHandler handler = getSearchResultHandler();

        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.build(Uid.NAME,
                "1e100da2-dd33-103e-9a80-d35fa81d9727"));
        ldapConnector.executeQuery(new ObjectClass("groupOfNames"), filter, handler, options);

        ArrayList<ConnectorObject> results = handler.getResult();

        for (ConnectorObject result : results) {

            LOG.info("### START ### Attribute set for the object {0}", result.getName());
            result.getAttributes().forEach(obj -> LOG.info("The attribute: {0}, with value {1}",
                    obj.getName(), obj.getValue()));
            Set<Attribute> attributeSet = result.getAttributes();

            for(Attribute attribute : attributeSet){
                List<Object> attrValueList = attribute.getValue();


                for(Object object : attrValueList){
                    if(object instanceof ConnectorObjectReference){

                        LOG.ok("The reference attribute: {0}. The value: {1}",attribute.getName(),
                                String.valueOf(((ConnectorObjectReference) object).getValue().getAttributeByName(Name.NAME)));
                    }
                }
            }

            LOG.info("### END ###");

            Assert.assertEquals(result.getUid().getUidValue(), "1e100da2-dd33-103e-9a80-d35fa81d9727");
        }
    }

    @Test()
    public void searchByUidInetOrgPerson() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName(),
                ATTR_NAME_MEMBER_OF);

        OperationOptions options = getDefaultOperationOptions(OC_NAME_INET_ORG_PERSON, attrsToGet, null,
                1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSearchResultsHandler handler = getSearchResultHandler();

        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.build(Uid.NAME,
                "1db1136a-dd33-103e-9a57-d35fa81d9727"));
        ldapConnector.executeQuery(new ObjectClass(OC_NAME_INET_ORG_PERSON), filter, handler, options);

        ArrayList<ConnectorObject> results = handler.getResult();

        for (ConnectorObject result : results) {

            LOG.info("### START ### Attribute set for the object {0}", result.getName());
            result.getAttributes().forEach(obj -> LOG.info("The attribute: {0}, with value {1}",
                    obj.getName(), obj.getValue()));
            Set<Attribute> attributeSet = result.getAttributes();

            for(Attribute attribute : attributeSet){
                List<Object> attrValueList = attribute.getValue();


                for(Object object : attrValueList){
                    if(object instanceof ConnectorObjectReference){

                        LOG.ok("The reference attribute: {0}. The value: {1}. The OC {2}",attribute.getName(),
                                String.valueOf(((ConnectorObjectReference) object).getValue().getAttributeByName(Name.NAME)),
                                ((ConnectorObjectReference) object).getValue().getObjectClass()!=null ?
                                        ((ConnectorObjectReference) object).getValue().getObjectClass().getObjectClassValue(): "NULL");

                    }
                }
            }

            LOG.info("### END ###");

            Assert.assertEquals(result.getUid().getUidValue(), "1db1136a-dd33-103e-9a57-d35fa81d9727");
        }
    }


    @Test()
    public void searchContainsAllValuesGroupOfNames() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName());

        OperationOptions options = getDefaultOperationOptions(OC_NAME_GROUP_OF_NAMES, attrsToGet, null,
                1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSearchResultsHandler handler = getSearchResultHandler();

        ContainsAllValuesFilter filter = (ContainsAllValuesFilter) FilterBuilder.containsAllValues(AttributeBuilder.build("member",
                "cn=Alexander Freeman,ou=users,dc=example,dc=com"));
        ldapConnector.executeQuery(new ObjectClass(OC_NAME_GROUP_OF_NAMES), filter, handler, options);

        ArrayList<ConnectorObject> results = handler.getResult();

        for (ConnectorObject result : results) {

            LOG.info("### START ### Attribute set for the object {0}", result.getName());
            result.getAttributes().forEach(obj -> LOG.info("The attribute: {0}, with value {1}",
                    obj.getName(), obj.getValue()));
            Set<Attribute> attributeSet = result.getAttributes();

            for(Attribute attribute : attributeSet){
                List<Object> attrValueList = attribute.getValue();


                for(Object object : attrValueList){
                    if(object instanceof ConnectorObjectReference){

                        LOG.ok("The reference attribute: {0}. The value: {1}",attribute.getName(),
                                String.valueOf(((ConnectorObjectReference) object).getValue().getAttributeByName(Name.NAME)));
                    }
                }
            }

            LOG.info("### END ###");

//            Assert.assertEquals(result.getUid().getUidValue(), "1db1136a-dd33-103e-9a57-d35fa81d9727");
        }
    }


}
