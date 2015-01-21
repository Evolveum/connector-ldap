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
package com.evolveum.polygon;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.LessEqNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.filter.AndFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.ExternallyChainedFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.NotFilter;
import org.identityconnectors.framework.common.objects.filter.OrFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;

import com.evolveum.polygon.common.SchemaUtil;

/**
 * @author Radovan Semancik
 *
 */
public class LdapFilterTranslator {

	private SchemaTranslator schemaTranslator;
	private ObjectClass ldapObjectClass;
	
	public LdapFilterTranslator(SchemaTranslator schemaTranslator, ObjectClass ldapObjectClass) {
		super();
		this.schemaTranslator = schemaTranslator;
		this.ldapObjectClass = ldapObjectClass;
	}

	public ExprNode translate(Filter icfFilter) {
		// Long and hairy if else if ... but the set of filters is quite stable,
		// it is unlikely that they will appear every day. Therefore we do not need
		// any OO magic here. And this is still quite readable.
		
		if (icfFilter instanceof AndFilter) {
			Collection<Filter> icfSubfilters = ((AndFilter)icfFilter).getFilters();
			List<ExprNode> subNodes = new ArrayList<ExprNode>(icfSubfilters.size());
			for (Filter icfSubFilter: icfSubfilters) {
				subNodes.add(translate(icfSubFilter));
			}
			return new AndNode(subNodes);
			
		} else if (icfFilter instanceof OrFilter) {
			Collection<Filter> icfSubfilters = ((OrFilter)icfFilter).getFilters();
			List<ExprNode> subNodes = new ArrayList<ExprNode>(icfSubfilters.size());
			for (Filter icfSubFilter: icfSubfilters) {
				subNodes.add(translate(icfSubFilter));
			}
			return new OrNode(subNodes);
			
		} else if (icfFilter instanceof NotFilter) {
			Filter icfSubfilter = ((NotFilter)icfFilter).getFilter();
			ExprNode subNode = translate(icfSubfilter);
			return new NotNode(subNode);
			
		} else if (icfFilter instanceof EqualsFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			return new EqualityNode<Object>(ldapAttributeType, ldapValue);

		} else if (icfFilter instanceof ContainsAllValuesFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			List<Value<Object>> ldapValues = schemaTranslator.toLdapValues(ldapAttributeType, icfAttributeValue);
			if (ldapValues == null || ldapValues.isEmpty()) {
				throw new IllegalArgumentException("Does it make sense to have empty ContainsAllValuesFilter?");
			}
			if (ldapValues.size() == 1) {
				// Essentialy same as EqualsFilter, so let's optimize this
				return new EqualityNode<Object>(ldapAttributeType, ldapValues.get(0));
			}
			List<ExprNode> subNodes = new ArrayList<ExprNode>(ldapValues.size());
			for (Value<Object> ldapValue: ldapValues) {
				subNodes.add(new EqualityNode<Object>(ldapAttributeType, ldapValues.get(0)));
			}
			return new AndNode(subNodes);
			
		} else if (icfFilter instanceof ContainsFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot use wildcard filter on DN (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			List<String> anyPattern = new ArrayList<String>(1);
			anyPattern.add(SchemaUtil.getSingleStringNonBlankValue(icfAttribute));
			return new SubstringNode(anyPattern, ldapAttributeType, null, null);
			
		} else if (icfFilter instanceof StartsWithFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot use wildcard filter on DN (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			List<String> anyPattern = new ArrayList<String>(1);
			String pattern = SchemaUtil.getSingleStringNonBlankValue(icfAttribute);
			return new SubstringNode(ldapAttributeType, pattern, null);

		} else if (icfFilter instanceof EndsWithFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot use wildcard filter on DN (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			List<String> anyPattern = new ArrayList<String>(1);
			String pattern = SchemaUtil.getSingleStringNonBlankValue(icfAttribute);
			return new SubstringNode(ldapAttributeType, null, pattern);
			
		} else if (icfFilter instanceof GreaterThanFilter) {			
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			GreaterEqNode<Object> greaterEqNode = new GreaterEqNode<Object>(ldapAttributeType, ldapValue);
			EqualityNode<Object> equalityNode = new EqualityNode<Object>(ldapAttributeType, ldapValue);
			return new AndNode(greaterEqNode,new NotNode(equalityNode));
			
		} else if (icfFilter instanceof GreaterThanOrEqualFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			return new GreaterEqNode<Object>(ldapAttributeType, ldapValue);
			
		} else if (icfFilter instanceof LessThanFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			LessEqNode<Object> lessEqNode = new LessEqNode<Object>(ldapAttributeType, ldapValue);
			EqualityNode<Object> equalityNode = new EqualityNode<Object>(ldapAttributeType, ldapValue);
			return new AndNode(lessEqNode,new NotNode(equalityNode));
			
		} else if (icfFilter instanceof LessThanOrEqualFilter) {
			
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			return new LessEqNode<Object>(ldapAttributeType, ldapValue);
			
		} else if (icfFilter instanceof ExternallyChainedFilter) {
			return translate(((ExternallyChainedFilter)icfFilter).getFilter());
			
		} else {
			throw new IllegalArgumentException("Unknown filter "+icfFilter.getClass());
		}
	}

}
