/**
 * Copyright (c) 2016 Evolveum
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
package com.evolveum.polygon.connector.ldap.schema;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.framework.common.objects.AttributeBuilder;

/**
 * @author semancik
 *
 */
public interface AttributeHandler {

    void handle(LdapNetworkConnection connection, Entry entry, org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute, AttributeBuilder ab);

}
