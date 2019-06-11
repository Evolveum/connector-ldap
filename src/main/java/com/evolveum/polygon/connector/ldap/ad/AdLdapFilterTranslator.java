/**
 * Copyright (c) 2015-2019 Evolveum
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

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.common.logging.Log;

import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class AdLdapFilterTranslator extends LdapFilterTranslator<AdLdapConfiguration> {
	
	private static final Log LOG = Log.getLog(AdLdapFilterTranslator.class);

	public AdLdapFilterTranslator(AbstractSchemaTranslator<AdLdapConfiguration> schemaTranslator, ObjectClass ldapObjectClass) {
		super(schemaTranslator, ldapObjectClass);
	}
	
	@Override
	protected ExprNode createObjectClassFilter(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		if ((ldapObjectClass instanceof AdObjectClass)) {
			if (getConfiguration().isIncludeObjectCategoryFilter()) {
				String defaultObjectCategory = ((AdObjectClass)ldapObjectClass).getDefaultObjectCategory();
				if (defaultObjectCategory == null) {
					LOG.warn("Requested search by object category, but object class {0} does not have default object category defined in the schema.", ldapObjectClass.getName());
					return super.createObjectClassFilter(ldapObjectClass);
				}
				return LdapUtil.filterAnd(
						super.createObjectClassFilter(ldapObjectClass),
						new EqualityNode<>(AdConstants.ATTRIBUTE_OBJECT_CATEGORY_NAME, defaultObjectCategory));
			} else {
				return super.createObjectClassFilter(ldapObjectClass);
			}
		} else {
			return super.createObjectClassFilter(ldapObjectClass);
		}
	}
	
}
