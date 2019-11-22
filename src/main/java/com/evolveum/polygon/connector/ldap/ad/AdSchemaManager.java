/**
 * Copyright (c) 2019 Evolveum
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

import java.io.IOException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaObjectWrapper;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;

/**
 * @author semancik
 *
 */
public class AdSchemaManager extends DefaultSchemaManager {

    public AdSchemaManager(AdSchemaLoader schemaLoader) {
        super(schemaLoader);
    }

    @Override
    protected void addSchemaObjects( Schema schema, Registries registries ) throws LdapException {
        for (SchemaObjectWrapper objectWrapper : schema.getContent()) {
            addSchemaObject(registries, objectWrapper.get(), schema);
        }
    }

}
