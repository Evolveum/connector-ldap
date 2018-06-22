/**
 * Copyright (c) 2015-2018 Evolveum
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

import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.identityconnectors.common.security.GuardedString;

/**
 * Fake LDAP value that stores string as GuardedString.
 * We want to decrypt GuardedString at the very last moment to avoid
 * recording the value in logs.
 * 
 * @author semancik
 *
 */
public class GuardedStringValue extends Value {

	GuardedString guardedStringValue;
	
	public GuardedStringValue(AttributeType attributeType, GuardedString val) throws LdapInvalidAttributeValueException {
		super(attributeType, val.toString());
		this.guardedStringValue = val;
	}

	public GuardedString getGuardedStringValue() {
		return guardedStringValue;
	}
	

}
