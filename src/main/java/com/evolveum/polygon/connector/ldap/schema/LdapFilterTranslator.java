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

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.filter.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Radovan Semancik
 *
 */
public class LdapFilterTranslator<C extends AbstractLdapConfiguration> {

	private AbstractSchemaTranslator<C> schemaTranslator;
	private ObjectClass ldapObjectClass;
	
	public LdapFilterTranslator(AbstractSchemaTranslator<C> schemaTranslator, ObjectClass ldapObjectClass) {
		super();
		this.schemaTranslator = schemaTranslator;
		this.ldapObjectClass = ldapObjectClass;
	}

	/**
	 * Translate filter, also add AND statement for objectClass.
	 */
	public ScopedFilter translate(Filter connIdFilter, ObjectClass ldapObjectClass) {
		ScopedFilter plainScopedFilter = translate(connIdFilter);
		if (plainScopedFilter != null) {
			return plainScopedFilter;
		} else {
			return new ScopedFilter(LdapUtil.createObjectClassFilter(ldapObjectClass));
		}
	}
	
	public ScopedFilter translate(AndFilter connIdFilter) {
        if (connIdFilter == null) {
            return null;
        }
        
        Collection<Filter> connIdSubfilters = connIdFilter.getFilters();
        List<ExprNode> subNodes = new ArrayList<ExprNode>(connIdSubfilters.size());
        Dn baseDn = null;
        
        for (Filter icfSubFilter: connIdSubfilters) {
            ScopedFilter subNode = translate(icfSubFilter);
            
            if (subNode.getBaseDn() != null) {
                if ((baseDn != null) && !baseDn.equals(subNode.getBaseDn())) {
                    throw new InvalidAttributeValueException("Two search clauses for DN in one search filter");
                } else {
                    baseDn = subNode.getBaseDn();
                }
            }
            
            if (subNode.getFilter() != null) {
                subNodes.add(subNode.getFilter());
            }
        }
        
        return new ScopedFilter(new AndNode(subNodes), baseDn);
	}


    public ScopedFilter translate(OrFilter connIdFilter) {
        if (connIdFilter == null) {
            return null;
        }
        
        Collection<Filter> connIdSubfilters = connIdFilter.getFilters();
        List<ExprNode> subNodes = new ArrayList<ExprNode>(connIdSubfilters.size());
        
        for (Filter connIdSubFilter: connIdSubfilters) {
            ScopedFilter subNode = translate(connIdSubFilter);
            
            if (subNode.getBaseDn() != null) {
                throw new InvalidAttributeValueException("Filter for __NAME__ cannot be used in OR clauses");
            }
            
            subNodes.add(subNode.getFilter());
        }
        
        return new ScopedFilter(new OrNode(subNodes));
    }


    public ScopedFilter translate(NotFilter connIdFilter) {
        if (connIdFilter == null) {
            return null;
        }
        
        Filter connIdSubfilter = connIdFilter.getFilter();
        ScopedFilter subNode = translate(connIdSubfilter);
        
        if (subNode.getBaseDn() != null) {
            throw new InvalidAttributeValueException("Filter for __NAME__ cannot be used in NOT clauses");
        }
        
        return new ScopedFilter(new NotNode(subNode.getFilter()));
    }


    public ScopedFilter translate(ContainsAllValuesFilter connIdFilter) {
        if (connIdFilter == null) {
            return null;
        }
        
        Attribute connIdAttribute = connIdFilter.getAttribute();
        String connIdAttributeName = connIdAttribute.getName();
        List<Object> connIdAttributeValue = connIdAttribute.getValue();
        
        if (Name.NAME.equals(connIdAttributeName)) {
            Dn dn = schemaTranslator.toDn(connIdAttribute);
            return new ScopedFilter(dn);
        }
        
        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, connIdAttributeName);
        List<Value> ldapValues = schemaTranslator.toLdapValues(ldapAttributeType, connIdAttributeValue);
        
        if (ldapValues == null || ldapValues.isEmpty()) {
            throw new IllegalArgumentException("Does it make sense to have empty ContainsAllValuesFilter?");
        }
        
        if (ldapValues.size() == 1) {
            // Essentialy same as EqualsFilter, so let's optimize this
            return new ScopedFilter(new EqualityNode<Object>(ldapAttributeType, ldapValues.get(0)));
        }
        
        List<ExprNode> subNodes = new ArrayList<>(ldapValues.size());
        
        for (Value ldapValue: ldapValues) {
            subNodes.add(new EqualityNode<>(ldapAttributeType, ldapValue));
        }
        
        return new ScopedFilter(new AndNode(subNodes));
    }

    public ScopedFilter translate(StartsWithFilter icfFilter) {
        return translate(icfFilter, true, false);
    }

    public ScopedFilter translate(EndsWithFilter icfFilter) {
        return translate(icfFilter, false, true);
    }

    public ScopedFilter translate(ContainsFilter icfFilter) {
        return translate(icfFilter, false, false);
    }

    public ScopedFilter translate(StringFilter icfFilter, boolean anchorStart, boolean anchorEnd) {
        if (icfFilter == null) {
            return null;
        }

        Attribute icfAttribute = icfFilter.getAttribute();
        String icfAttributeName = icfAttribute.getName();

        if (Name.NAME.equals(icfAttributeName)) {
            throw new IllegalArgumentException("Cannot use wildcard filter on DN (__NAME__)");
        }

        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
        String value = SchemaUtil.getSingleStringNonBlankValue(icfAttribute);

        SubstringNode node;
        if (!anchorStart && !anchorEnd) {
            //substring
            List<String> anyPattern = new ArrayList<>(1);
            anyPattern.add(value);

            node = new SubstringNode(anyPattern, ldapAttributeType, null, null);
        } else if (anchorStart && !anchorEnd) {
            //start with
            node = new SubstringNode(ldapAttributeType, value, null);
        } else if (!anchorStart && anchorEnd) {
            //ends with
            node = new SubstringNode(ldapAttributeType, null, value);
        } else {
            throw new IllegalStateException("Shouldn't happen");
        }

        return new ScopedFilter(node);
    }


    public ScopedFilter translate(EqualsFilter connIdFilter) {
        if (connIdFilter == null) {
            return null;
        }
        
        Attribute connIdAttribute = connIdFilter.getAttribute();
        String connIdAttributeName = connIdAttribute.getName();
        
        if (Name.NAME.equals(connIdAttributeName)) {
            throw new IllegalArgumentException("Cannot use wildcard filter on DN (__NAME__)");
        }
        
        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, connIdAttributeName);
        String pattern = SchemaUtil.getSingleStringNonBlankValue(connIdAttribute);
        
        return new ScopedFilter(new SubstringNode(ldapAttributeType, pattern, null));
    }


    public ScopedFilter translate(GreaterThanFilter icfFilter) {
        if (icfFilter == null) {
            return null;
        }
        
        Attribute icfAttribute = icfFilter.getAttribute();
        String icfAttributeName = icfAttribute.getName();
        List<Object> icfAttributeValue = icfAttribute.getValue();
        
        if (Name.NAME.equals(icfAttributeName)) {
            throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
        }
        
        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
        Value ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
        GreaterEqNode<Object> greaterEqNode;
		try {
			greaterEqNode = new GreaterEqNode<Object>(ldapAttributeType, ldapValue);
		} catch (LdapSchemaException e) {
			throw new IllegalArgumentException("Invalid value in filter for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
					+"; attributeType="+ldapAttributeType, e);
		}
        EqualityNode<Object> equalityNode = new EqualityNode<Object>(ldapAttributeType, ldapValue);
        
        return new ScopedFilter(new AndNode(greaterEqNode,new NotNode(equalityNode)));
    }


    public ScopedFilter translate(GreaterThanOrEqualFilter icfFilter) {
        if (icfFilter == null) {
            return null;
        }
        
        Attribute icfAttribute = icfFilter.getAttribute();
        String icfAttributeName = icfAttribute.getName();
        List<Object> icfAttributeValue = icfAttribute.getValue();
        
        if (Name.NAME.equals(icfAttributeName)) {
            throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
        }
        
        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
        Value ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
        
        try {
			return new ScopedFilter(new GreaterEqNode<Object>(ldapAttributeType, ldapValue));
		} catch (LdapSchemaException e) {
			throw new IllegalArgumentException("Invalid value in filter for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
					+"; attributeType="+ldapAttributeType, e);
		}
        
    }


    public ScopedFilter translate(LessThanFilter icfFilter) {
        if (icfFilter == null) {
            return null;
        }
        
        Attribute icfAttribute = icfFilter.getAttribute();
        String icfAttributeName = icfAttribute.getName();
        List<Object> icfAttributeValue = icfAttribute.getValue();
        
        if (Name.NAME.equals(icfAttributeName)) {
            throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
        }
        
        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
        Value ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
        LessEqNode<Object> lessEqNode;
		try {
			lessEqNode = new LessEqNode<Object>(ldapAttributeType, ldapValue);
		} catch (LdapSchemaException e) {
			throw new IllegalArgumentException("Invalid value in filter for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
					+"; attributeType="+ldapAttributeType, e);
		}
        EqualityNode<Object> equalityNode = new EqualityNode<Object>(ldapAttributeType, ldapValue);
        
        return new ScopedFilter(new AndNode(lessEqNode,new NotNode(equalityNode)));
    }


    public ScopedFilter translate(LessThanOrEqualFilter icfFilter) {
        if (icfFilter == null) {
            return null;
        }
        
        Attribute icfAttribute = icfFilter.getAttribute();
        String icfAttributeName = icfAttribute.getName();
        List<Object> icfAttributeValue = icfAttribute.getValue();
        
        if (Name.NAME.equals(icfAttributeName)) {
            throw new IllegalArgumentException("Cannot query LDAP objects by DN in a complex filter (__NAME__)");
        }
        
        AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttributeName);
        Value ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, icfAttributeValue);
        
        try {
			return new ScopedFilter(new LessEqNode<Object>(ldapAttributeType, ldapValue));
		} catch (LdapSchemaException e) {
			throw new IllegalArgumentException("Invalid value in filter for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
					+"; attributeType="+ldapAttributeType, e);
		}
        
    }

    
	public ScopedFilter translate(Filter connIdFilter) {
		if (connIdFilter == null) {
			return null;
		}
		
		// Long and hairy if else if ... but the set of filters is quite stable,
		// it is unlikely that they will appear every day. Therefore we do not need
		// any OO magic here. And this is still quite readable.
		
		if (connIdFilter instanceof AndFilter) {
			return translate((AndFilter)connIdFilter);
		} else if (connIdFilter instanceof OrFilter) {
            return translate((OrFilter)connIdFilter);
		} else if (connIdFilter instanceof NotFilter) {
            return translate((NotFilter)connIdFilter);
		} else if (connIdFilter instanceof EqualsFilter) {
			return translateEqualsFilter((EqualsFilter)connIdFilter);
		} else if (connIdFilter instanceof ContainsAllValuesFilter) {
            return translate((ContainsAllValuesFilter)connIdFilter);
        } else if (connIdFilter instanceof ContainsFilter) {
            return translate((ContainsFilter) connIdFilter);
        } else if (connIdFilter instanceof StartsWithFilter) {
            return translate((StartsWithFilter) connIdFilter);
        } else if (connIdFilter instanceof EndsWithFilter) {
            return translate((EndsWithFilter) connIdFilter);
        } else if (connIdFilter instanceof GreaterThanFilter) {
            return translate((GreaterThanFilter) connIdFilter);
        } else if (connIdFilter instanceof GreaterThanOrEqualFilter) {
            return translate((GreaterThanOrEqualFilter) connIdFilter);
        } else if (connIdFilter instanceof LessThanFilter) {
            return translate((LessThanFilter)connIdFilter);
		} else if (connIdFilter instanceof LessThanOrEqualFilter) {
            return translate((LessThanOrEqualFilter)connIdFilter);
		} else if (connIdFilter instanceof ExternallyChainedFilter) {
			return translate(((ExternallyChainedFilter)connIdFilter).getFilter());
			
		} else {
			throw new IllegalArgumentException("Unknown filter "+connIdFilter.getClass());
		}
	}

	protected ScopedFilter translateEqualsFilter(EqualsFilter connIdFilter) {
		Attribute connIdAttribute = connIdFilter.getAttribute();
		String connIdAttributeName = connIdAttribute.getName();
		List<Object> connIdAttributeValue = connIdAttribute.getValue();
		if (Name.NAME.equals(connIdAttributeName)) {
			Dn dn = schemaTranslator.toDn(connIdAttribute);
			return new ScopedFilter(null, dn);
		}
		AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, connIdAttributeName);
		Value ldapValue;
		if (Uid.NAME.equals(connIdAttributeName)) {
			if (connIdAttributeValue.size() != 1) {
				throw new InvalidAttributeValueException("Expected single value for UID, but got " + connIdAttributeValue);
			}
			ldapValue = schemaTranslator.toLdapIdentifierValue(ldapAttributeType, (String)connIdAttributeValue.get(0));
		} else {
			ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, connIdAttributeValue);
		}
		return new ScopedFilter(new EqualityNode<Object>(ldapAttributeType, ldapValue));
	}

}
