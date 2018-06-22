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

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeValueCompleteness;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.OperationLog;
import com.evolveum.polygon.connector.ldap.schema.AttributeHandler;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;

/**
 * This is an additional handler that will process incomplete (range) 
 * attributes such as members;range=0-1500
 * 
 * @author semancik
 *
 */
public class AdAttributeHandler implements AttributeHandler {
	
	private static final Log LOG = Log.getLog(AdAttributeHandler.class);
	
	private SearchStrategy<AdLdapConfiguration> searchStrategy;

	public AdAttributeHandler(SearchStrategy<AdLdapConfiguration> searchStrategy) {
		this.searchStrategy = searchStrategy;
	}

	@Override
	public void handle(LdapNetworkConnection connection, Entry entry, Attribute ldapAttribute, AttributeBuilder ab) {
		int semicolonIndex = ldapAttribute.getId().indexOf(';');
		if (semicolonIndex >= 0) {
			String attrName = ldapAttribute.getId().substring(0, semicolonIndex);
			String attrOption = ldapAttribute.getId().substring(semicolonIndex+1);
			if (attrOption.startsWith("range=")) {
				if (searchStrategy.allowPartialAttributeValues()) {
					LOG.ok("Got attribute {0} with range option {1}, do NOT following as partial values are allowed",
							attrName, attrOption);
					ab.setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
				} else {
					LOG.ok("Got attribute {0} with range option {1}, following as partial values are not allowed",
							attrName, attrOption);
					while (true) {
						Range range = parseRange(attrOption);
						if (range.top) {
							LOG.ok("reached the top ({0}), breaking", attrOption);
							break;
						}
						Attribute rangeAttribute = rangeSearch(connection, entry, attrName, range.high);
						if (rangeAttribute == null) {
							LOG.ok("no range attribute returned in response, breaking", attrOption);
							break;
						}
						for (Value rangeValue: rangeAttribute) {
							try {
								ldapAttribute.add(rangeValue);
							} catch (LdapInvalidAttributeValueException e) {
								throw new IllegalStateException("Error adding value "+rangeValue+" to attribute "+ldapAttribute+": "+e.getMessage(), e);
							}
						}
						semicolonIndex = ldapAttribute.getId().indexOf(';');
						if (semicolonIndex < 0) {
							// Strange. but it looks like we have all the values now
							LOG.ok("reached no option, breaking", attrOption);
							break;
						} else {
							attrOption = ldapAttribute.getId().substring(semicolonIndex+1);
						}
					}
				}
			} else {
				LOG.ok("Unknown attribute option: {0}", ldapAttribute.getId());
			}
		}
	}
	
	private Attribute rangeSearch(LdapNetworkConnection connection, Entry previousEntry, String attrName, int high) {
		Dn dn = previousEntry.getDn();
		String attributesToGet = attrName + ";range=" + (high + 1) + "-*";
		Entry entry = null;
		OperationLog.logOperationReq(connection, "Search REQ base={0}, filter={1}, scope={2}, attributes={3}", 
				dn, AbstractLdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT, attributesToGet);
		try {
			entry = connection.lookup( dn, attributesToGet );
			
			if ( entry==null ) {
	            OperationLog.logOperationErr(connection, "Entry not found for {0}", dn);
	            throw LdapUtil.processLdapException( "Range search for "+dn+" with "+attributesToGet+" failed", 
	                new LdapNoSuchObjectException("No entry found for " + dn));
			}
		} catch (LdapException e) {
			OperationLog.logOperationErr(connection, "Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
			throw LdapUtil.processLdapException("Range search for "+dn+" with "+attributesToGet+" failed", e);
		}
		
		OperationLog.logOperationRes(connection, "Search RES {0}", entry);
		
		return entry.get(attrName);
	}

	private Range parseRange(String opt) {
		int iEq = opt.indexOf('=');
		int iDash = opt.indexOf('-');
		Range range = new Range();
		range.low = Integer.parseInt(opt.substring(iEq + 1, iDash));
		String hiStr = opt.substring(iDash + 1);
		if ("*".equals(hiStr)) {
			range.top = true;
		} else {
			range.high = Integer.parseInt(hiStr);
		}
		return range;
	}

	private class Range {
		int low;
		int high;
		boolean top = false;
	}

}
