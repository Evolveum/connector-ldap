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
import com.evolveum.polygon.connector.ldap.integration.util.TestSyncResultsHandler;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SyncTests extends CommonTestClass {
    private static final Log LOG = Log.getLog(SyncTests.class);

    @Test()
    public void syncGroupOfNames() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName());

        OperationOptions options = getDefaultOperationOptions(OC_NAME_GROUP_OF_NAMES, attrsToGet, null,
                1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSyncResultsHandler handler = getSyncResultHandler();
        SyncToken syncToken =  ldapConnector.getLatestSyncToken(new ObjectClass(OC_NAME_GROUP_OF_NAMES));

        LOG.ok("Latest sync token: {0}", syncToken);

        ldapConnector.sync(new ObjectClass(OC_NAME_GROUP_OF_NAMES),
                new SyncToken("20240724124001Z"), handler, options);

        for (SyncDelta result : handler.getResult()) {

            LOG.info("### START ### Attribute set for the object {0}", result);

            Set<Attribute> attrs  = result.getObject().getAttributes();

            for(Attribute attribute : attrs){
                List<Object> attrValueList = attribute.getValue();
                for(Object object : attrValueList){
                    if(object instanceof ConnectorObjectReference){

                        LOG.ok("The reference attribute: {0}. The value: {1}",attribute.getName(),
                                String.valueOf(((ConnectorObjectReference) object).getValue().getAttributeByName(Name.NAME)));
                    }
                }
            }
            LOG.info("### END ###");
        }

    }

    @Test()
    public void syncInetOrgPerson() {

        List<String> attrsToGet = CollectionUtil.newList(OperationalAttributeInfos.PASSWORD.getName(),
                OperationalAttributeInfos.LOCK_OUT.getName(),
                OperationalAttributeInfos.ENABLE.getName());

        OperationOptions options = getDefaultOperationOptions(OC_NAME_INET_ORG_PERSON, attrsToGet, null,
                1, 20, true, true);

        ldapConfiguration = initializeAndFetchLDAPConfiguration();
        ldapConnector.init(ldapConfiguration);
        TestSyncResultsHandler handler = getSyncResultHandler();
        SyncToken syncToken =  ldapConnector.getLatestSyncToken(new ObjectClass(OC_NAME_INET_ORG_PERSON));

        LOG.ok("Latest sync token: {0}", syncToken);

        ldapConnector.sync(new ObjectClass(OC_NAME_INET_ORG_PERSON),
                new SyncToken("20240729132122Z"), handler, options);

        for (SyncDelta result : handler.getResult()) {

            LOG.info("### START ### Attribute set for the object {0}", result);

            Set<Attribute> attrs  = result.getObject().getAttributes();

            for(Attribute attribute : attrs){
                List<Object> attrValueList = attribute.getValue();
                for(Object object : attrValueList){
                    if(object instanceof ConnectorObjectReference){

                        LOG.ok("The reference attribute: {0}. The value: {1}",attribute.getName(),
                                String.valueOf(((ConnectorObjectReference) object).getValue().getAttributeByName(Name.NAME)));
                    }
                }
            }
            LOG.info("### END ###");
        }

    }
}

