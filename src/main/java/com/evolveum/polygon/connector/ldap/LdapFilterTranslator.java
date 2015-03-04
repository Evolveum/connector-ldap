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
package com.evolveum.polygon.connector.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.StringValue;
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
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
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

	/**
	 * Translate filter, also add AND statement for objectClass.
	 */
	public ScopedFilter translate(Filter icfFilter, ObjectClass ldapObjectClass) {
		ScopedFilter plainScopedFilter = translate(icfFilter);
		EqualityNode<String> objectClassEqFilter = createObjectClassEqFilter(ldapObjectClass);
		if (plainScopedFilter == null) {
			return new ScopedFilter(objectClassEqFilter);
		}
		ExprNode plainFilter = plainScopedFilter.getFilter();
		if (plainFilter == null) {
			return new ScopedFilter(objectClassEqFilter, plainScopedFilter.getBaseDn());
		}
		if (plainFilter instanceof AndNode) {
			((AndNode)plainFilter).addNode(objectClassEqFilter);
			return plainScopedFilter;
		} else {
			return new ScopedFilter(new AndNode(objectClassEqFilter, plainFilter), plainScopedFilter.getBaseDn()); 
		}
	}
	
	private EqualityNode<String> createObjectClassEqFilter(ObjectClass ldapObjectClass) {
		// TODO Auto-generated method stub
		Value<String> ldapValue = new StringValue(ldapObjectClass.getName());
		return new EqualityNode<String>(LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME, ldapValue);
	}

	public ScopedFilter translate(Filter icfFilter) {
		if (icfFilter == null) {
			return null;
		}
		
		// Long and hairy if else if ... but the set of filters is quite stable,
		// it is unlikely that they will appear every day. Therefore we do not need
		// any OO magic here. And this is still quite readable.
		
		if (icfFilter instanceof AndFilter) {
			Collection<Filter> icfSubfilters = ((AndFilter)icfFilter).getFilters();
			List<ExprNode> subNodes = new ArrayList<ExprNode>(icfSubfilters.size());
			String baseDn = null;
			for (Filter icfSubFilter: icfSubfilters) {
				ScopedFilter subNode = translate(icfSubFilter);
				if (subNode.getBaseDn() != null) {
					if (baseDn != null) {
						if (baseDn.equals(subNode.getBaseDn())) {
							// Same dn in both nodes, nothing to do
						} else {
							throw new InvalidAttributeValueException("Two search clauses for DN in one search filter");
						}						
					} else {
						baseDn = subNode.getBaseDn();
					}
				}
				if (subNode.getFilter() != null) {
					subNodes.add(subNode.getFilter());
				}
			}
			return new ScopedFilter(new AndNode(subNodes), baseDn);
			
		} else if (icfFilter instanceof OrFilter) {
			Collection<Filter> icfSubfilters = ((OrFilter)icfFilter).getFilters();
			List<ExprNode> subNodes = new ArrayList<ExprNode>(icfSubfilters.size());
			for (Filter icfSubFilter: icfSubfilters) {
				ScopedFilter subNode = translate(icfSubFilter);
				if (subNode.getBaseDn() != null) {
					throw new InvalidAttributeValueException("Filter for __NAME__ cannot be used in OR clauses");
				}
				subNodes.add(subNode.getFilter());
			}
			return new ScopedFilter(new OrNode(subNodes));
			
		} else if (icfFilter instanceof NotFilter) {
			Filter icfSubfilter = ((NotFilter)icfFilter).getFilter();
			ScopedFilter subNode = translate(icfSubfilter);
			if (subNode.getBaseDn() != null) {
				throw new InvalidAttributeValueException("Filter for __NAME__ cannot be used in NOT clauses");
			}
			return new ScopedFilter(new NotNode(subNode.getFilter()));
			
		} else if (icfFilter instanceof EqualsFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				String dn = SchemaUtil.getSingleStringNonBlankValue(icfAttribute);
				return new ScopedFilter(null, dn);
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			return new ScopedFilter(new EqualityNode<Object>(ldapAttributeType, ldapValue));

		} else if (icfFilter instanceof ContainsAllValuesFilter) {
			Attribute icfAttribute = ((ContainsAllValuesFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				String dn = SchemaUtil.getSingleStringNonBlankValue(icfAttribute);
				return new ScopedFilter(dn);
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			List<Value<Object>> ldapValues = schemaTranslator.toLdapValues(ldapAttributeType, icfAttributeValue);
			if (ldapValues == null || ldapValues.isEmpty()) {
				throw new IllegalArgumentException("Does it make sense to have empty ContainsAllValuesFilter?");
			}
			if (ldapValues.size() == 1) {
				// Essentialy same as EqualsFilter, so let's optimize this
				return new ScopedFilter(new EqualityNode<Object>(ldapAttributeType, ldapValues.get(0)));
			}
			List<ExprNode> subNodes = new ArrayList<ExprNode>(ldapValues.size());
			for (Value<Object> ldapValue: ldapValues) {
				subNodes.add(new EqualityNode<Object>(ldapAttributeType, ldapValues.get(0)));
			}
			return new ScopedFilter(new AndNode(subNodes));
			
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
			return new ScopedFilter(new SubstringNode(anyPattern, ldapAttributeType, null, null));
			
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
			return new ScopedFilter(new SubstringNode(ldapAttributeType, pattern, null));

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
			return new ScopedFilter(new SubstringNode(ldapAttributeType, null, pattern));
			
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
			return new ScopedFilter(new AndNode(greaterEqNode,new NotNode(equalityNode)));
			
		} else if (icfFilter instanceof GreaterThanOrEqualFilter) {
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			return new ScopedFilter(new GreaterEqNode<Object>(ldapAttributeType, ldapValue));
			
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
			return new ScopedFilter(new AndNode(lessEqNode,new NotNode(equalityNode)));
			
		} else if (icfFilter instanceof LessThanOrEqualFilter) {
			
			Attribute icfAttribute = ((EqualsFilter)icfFilter).getAttribute();
			String icfAttributeName = icfAttribute.getName();
			List<Object> icfAttributeValue = icfAttribute.getValue();
			if (Name.NAME.equals(icfAttributeName)) {
				throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
			return new ScopedFilter(new LessEqNode<Object>(ldapAttributeType, ldapValue));
			
		} else if (icfFilter instanceof ExternallyChainedFilter) {
			return translate(((ExternallyChainedFilter)icfFilter).getFilter());
			
		} else {
			throw new IllegalArgumentException("Unknown filter "+icfFilter.getClass());
		}
	}

}
