/**
 * Copyright (c) 2016-2018 Evolveum
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
package com.evolveum.polygon.connector.ldap.ad;

import com.evolveum.polygon.connector.ldap.ConnectionLog;
import com.evolveum.polygon.connector.ldap.ErrorHandler;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.framework.common.objects.OperationOptions;

import com.evolveum.polygon.connector.ldap.connection.ConnectionManager;

/**
 * @author semancik
 *
 */
public class GlobalCatalogConnectionManager extends ConnectionManager<AdLdapConfiguration> {

    public GlobalCatalogConnectionManager(AdLdapConfiguration configuration, ErrorHandler errorHandler, ConnectionLog connectionLog) {
        super(configuration, errorHandler, connectionLog);
    }

    @Override
    protected String[] getServersConfiguration() {
        return getConfiguration().getGlobalCatalogServers();
    }

}
