/**
 * Copyright (c) 2015 Evolveum
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
package com.evolveum.polygon.connector.ldap.edirectory;

import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.LessEqNode;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.ScopedFilter;

/**
 * @author semancik
 *
 */
public class EDirectoryLdapFilterTranslator extends LdapFilterTranslator {

	public EDirectoryLdapFilterTranslator(SchemaTranslator schemaTranslator, ObjectClass ldapObjectClass) {
		super(schemaTranslator, ldapObjectClass);
	}

	@Override
	protected ScopedFilter translateEqualsFilter(EqualsFilter icfFilter) {
		if (OperationalAttributes.LOCK_OUT_NAME.equals(icfFilter.getAttribute().getName())) {
			return new ScopedFilter(
					new AndNode(new EqualityNode<String>(EDirectoryConstants.LOCKOUT_ATTRIBUTE_LOCKED_NAME, 
									new StringValue(AbstractLdapConfiguration.BOOLEAN_TRUE)
								),
								new LessEqNode<String>(EDirectoryConstants.LOCKOUT_ATTRIBUTE_RESET_TIME_NAME,
									new StringValue(LdapUtil.toGeneralizedTime(System.currentTimeMillis()))
								)
					)
			);
		} else {
			return super.translateEqualsFilter(icfFilter);
		}
	}

	
}
