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
package com.evolveum.polygon.connector.ldap.edirectory;

import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.ScopedFilter;

/**
 * @author semancik
 *
 */
public class EDirectoryLdapFilterTranslator extends LdapFilterTranslator<EDirectoryLdapConfiguration> {

	public EDirectoryLdapFilterTranslator(AbstractSchemaTranslator schemaTranslator, ObjectClass ldapObjectClass) {
		super(schemaTranslator, ldapObjectClass);
	}

	@Override
	protected ScopedFilter translateEqualsFilter(EqualsFilter icfFilter) {
		if (OperationalAttributes.ENABLE_NAME.equals(icfFilter.getAttribute().getName())) {
			List<Object> values = icfFilter.getAttribute().getValue();
			if (values.size() != 1) {
				throw new InvalidAttributeValueException("Unexpected number of values in filter "+icfFilter);
			}
			Boolean value = (Boolean)values.get(0);
			if (value) {
				return new ScopedFilter(createLoginDisabledFilter(AbstractLdapConfiguration.BOOLEAN_FALSE));
			} else {
				return new ScopedFilter(createLoginDisabledFilter(AbstractLdapConfiguration.BOOLEAN_TRUE));
			}
		} else if (OperationalAttributes.LOCK_OUT_NAME.equals(icfFilter.getAttribute().getName())) {
			List<Object> values = icfFilter.getAttribute().getValue();
			if (values.size() != 1) {
				throw new InvalidAttributeValueException("Unexpected number of values in filter "+icfFilter);
			}
			Boolean value = (Boolean)values.get(0);
			if (value) {
				return new ScopedFilter(createLockoutFilter());
			} else {
				return new ScopedFilter(new NotNode(createLockoutFilter()));
			}
		} else {
			return super.translateEqualsFilter(icfFilter);
		}
	}

	private ExprNode createLockoutFilter() {
		try {
			return new AndNode(new EqualityNode<String>(EDirectoryConstants.ATTRIBUTE_LOCKOUT_LOCKED_NAME, 
					AbstractLdapConfiguration.BOOLEAN_TRUE
				),
				new GreaterEqNode<String>(EDirectoryConstants.ATTRIBUTE_LOCKOUT_RESET_TIME_NAME,
					LdapUtil.toGeneralizedTime(System.currentTimeMillis(), false)
				)
			);
		} catch (LdapSchemaException e) {
			throw new IllegalArgumentException("Invalid value in lockout filter", e);
		}
	}
	
	private ExprNode createLoginDisabledFilter(String value) {
		return new EqualityNode<String>(EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME, value);
	}
	
}
