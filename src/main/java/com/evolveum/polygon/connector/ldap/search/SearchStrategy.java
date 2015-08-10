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
package com.evolveum.polygon.connector.ldap.search;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortRequestControlImpl;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SortKey;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;

/**
 * @author Radovan Semancik
 *
 */
public abstract class SearchStrategy {
	
	private static final Log LOG = Log.getLog(SearchStrategy.class);
	
	private LdapNetworkConnection connection;
	private AbstractLdapConfiguration configuration;
	private SchemaTranslator schemaTranslator;
	private ObjectClass objectClass;
	private org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass;
	private ResultsHandler handler;
	private OperationOptions options;
	private boolean isCompleteResultSet = true;
	
	protected SearchStrategy(LdapNetworkConnection connection, AbstractLdapConfiguration configuration,
			SchemaTranslator schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		super();
		this.connection = connection;
		this.configuration = configuration;
		this.schemaTranslator = schemaTranslator;
		this.objectClass = objectClass;
		this.ldapObjectClass = ldapObjectClass;
		this.handler = handler;
		this.options = options;
	}

	public LdapNetworkConnection getConnection() {
		return connection;
	}

	public AbstractLdapConfiguration getConfiguration() {
		return configuration;
	}
	
	public OperationOptions getOptions() {
		return options;
	}

	public SchemaTranslator getSchemaTranslator() {
		return schemaTranslator;
	}
	
	public ObjectClass getObjectClass() {
		return objectClass;
	}

	public org.apache.directory.api.ldap.model.schema.ObjectClass getLdapObjectClass() {
		return ldapObjectClass;
	}

	public abstract void search(String baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException;
	
	public int getRemainingPagedResults() {
		return -1;
	}
        
	public String getPagedResultsCookie() {
		return null;
	}
	
	public boolean isCompleteResultSet() {
		return isCompleteResultSet;
	}
	
	protected void setCompleteResultSet(boolean isCompleteResultSet) {
		this.isCompleteResultSet = isCompleteResultSet;
	}

	protected int getDefaultPageSize() {
		return configuration.getPagingBlockSize();
	}

	protected void applyCommonConfiguration(SearchRequest req) {
		String referralStrategy = configuration.getReferralStrategy();
		if (referralStrategy == null) {
			req.followReferrals();
		} else if (LdapConfiguration.REFERRAL_STRATEGY_FOLLOW.equals(referralStrategy)) {
			req.followReferrals();
		} else if (LdapConfiguration.REFERRAL_STRATEGY_IGNORE.equals(referralStrategy)) {
			req.ignoreReferrals();
		} else if (LdapConfiguration.REFERRAL_STRATEGY_THROW.equals(referralStrategy)) {
			// nothing to do
		} else {
			throw new ConfigurationException("Unknown value of referralStrategy configuration property: "+referralStrategy);
		}
	}
	
	protected SearchCursor executeSearch(SearchRequest req) throws LdapException {
		if (req.getFilter() == null) {
			req.setFilter(LdapConfiguration.SEARCH_FILTER_ALL);
		}
		logSearchRequest(req);
		SearchCursor searchCursor;
		try {
			searchCursor = connection.search(req);
		} catch (LdapReferralException e) {
			logSearchError(e);
			String referralStrategy = configuration.getReferralStrategy();
			if (referralStrategy == null) {
				// This should not happen!
				throw new IllegalStateException("Got referral exception while not expecting it: "+e.getMessage(),e);
			} else if (LdapConfiguration.REFERRAL_STRATEGY_FOLLOW.equals(referralStrategy)) {
				// This should not happen!
				throw new IllegalStateException("Got referral exception while not expecting it: "+e.getMessage(),e);
			} else if (LdapConfiguration.REFERRAL_STRATEGY_IGNORE.equals(referralStrategy)) {
				LOG.ok("Ignoring referral");
				return null;
			} else if (LdapConfiguration.REFERRAL_STRATEGY_THROW.equals(referralStrategy)) {
				throw e;
			} else {
				throw new ConfigurationException("Unknown value of referralStrategy configuration property: "+referralStrategy);
			}
		} catch (LdapException e) {
			logSearchError(e);
			throw e;
		}
		return searchCursor;
	}
	
	protected void logSearchRequest(SearchRequest req) {
		if (LOG.isOk()) {
			String controls = null;
			Map<String, Control> controlsMap = req.getControls();
			if (controlsMap != null && !controlsMap.isEmpty()) {
				StringBuilder sb = new StringBuilder();
				// We want just a short list here. toString methods of control implementations are too long. Avoid them.
				for (java.util.Map.Entry<String, Control> entry: controlsMap.entrySet()) {
					Control control = entry.getValue();
					if (control instanceof PagedResults) {
						sb.append("PagedResults(size=");
						sb.append(((PagedResults)control).getSize());
						sb.append(", cookie=");
						byte[] cookie = ((PagedResults)control).getCookie();
						if (cookie == null) {
							sb.append("null");
						} else {
							sb.append(Base64.encode(cookie));
						}
						sb.append("),");
					} else if (control instanceof VirtualListViewRequest) {
						sb.append("VLV(beforeCount=");
						sb.append(((VirtualListViewRequest)control).getBeforeCount());
						sb.append(", afterCount=");
						sb.append(((VirtualListViewRequest)control).getAfterCount());
						sb.append(", offset=");
						sb.append(((VirtualListViewRequest)control).getOffset());
						sb.append(", contentCount=");
						sb.append(((VirtualListViewRequest)control).getContentCount());
						sb.append(", contextID=");
						byte[] contextId = ((VirtualListViewRequest)control).getContextId();
						if (contextId == null) {
							sb.append("null");
						} else {
							sb.append(Base64.encode(contextId));
						}
						sb.append("),");
					} else if (control instanceof SortRequest) {
						sb.append("Sort(");
						for (org.apache.directory.api.ldap.model.message.controls.SortKey sortKey: ((SortRequest)control).getSortKeys()) {
							sb.append(sortKey.getAttributeTypeDesc());
							sb.append(":");
							sb.append(sortKey.getMatchingRuleId());
							sb.append(":");
							if (sortKey.isReverseOrder()) {
								sb.append("D");
							} else {
								sb.append("A");
							}
							sb.append("),");
						}
					} else {
						sb.append(control.getClass().getName());
						sb.append(",");
					}
				}
				controls = sb.toString();
			}
			LOG.ok("Search REQ base={0}, filter={1}, scope={2}, attributes={3}, controls={4}",
					req.getBase(), req.getFilter(), req.getScope(), req.getAttributes(), controls);
		}
	}

	protected void logSearchRequest(SearchRequest req, String extra) {
		if (LOG.isOk()) {
			LOG.ok("Search REQ base={0}, filter={1}, scope={2}, attributes={3}, {4}",
					req.getBase(), req.getFilter(), req.getScope(), req.getAttributes(), extra);
		}
	}

	protected void logSearchResult(Entry entry) {
		if (LOG.isOk()) {
			LOG.ok("Search RES {0}", entry);
		}
	}
	
	protected void logSearchResult(String type, LdapResult ldapResult) {
		if (LOG.isOk()) {
			LOG.ok("Search RES {0}:\n{1}", type, ldapResult);
		}
	}

	protected void logSearchResult(String type, LdapResult ldapResult, String extra) {
		if (LOG.isOk()) {
			LOG.ok("Search RES {0}: {1}\n{2}", type, extra, ldapResult);
		}
	}

	protected void logSearchError(LdapException e) {
		LOG.error("Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
	}
	
	protected boolean handleResult(Entry entry) {
		return handler.handle(schemaTranslator.toIcfObject(objectClass, entry));
	}

	protected SortRequest createSortControl(String defaultSortLdapAttribute, String defaultSortOrderingRule) {
		SortRequest sortReqControl = null;
		if (getOptions() != null && getOptions().getSortKeys() != null && getOptions().getSortKeys().length > 0) {
			sortReqControl = new SortRequestControlImpl();
			sortReqControl.setCritical(true);
			for (SortKey icfSortKey: getOptions().getSortKeys()) {
				AttributeType attributeType = getSchemaTranslator().toLdapAttribute(getLdapObjectClass(), icfSortKey.getField());
				String attributeTypeDesc = attributeType.getName();
				String matchingRuleId = attributeType.getOrderingOid();
				if (matchingRuleId == null) {
					matchingRuleId = defaultSortOrderingRule;
				}
				boolean reverseOrder = !icfSortKey.isAscendingOrder();
				org.apache.directory.api.ldap.model.message.controls.SortKey ldapSortKey = 
						new org.apache.directory.api.ldap.model.message.controls.SortKey(attributeTypeDesc, matchingRuleId, reverseOrder);
				sortReqControl.addSortKey(ldapSortKey);
			}
		} else if (defaultSortLdapAttribute != null) {
			sortReqControl = new SortRequestControlImpl();
			AttributeType attributeType = getSchemaTranslator().toLdapAttribute(getLdapObjectClass(), defaultSortLdapAttribute);
			String matchingRuleId = attributeType.getOrderingOid();
			if (matchingRuleId == null) {
				matchingRuleId = defaultSortOrderingRule;
			}
			org.apache.directory.api.ldap.model.message.controls.SortKey ldapSortKey = 
					new org.apache.directory.api.ldap.model.message.controls.SortKey(defaultSortLdapAttribute, matchingRuleId, false); 
			sortReqControl.addSortKey(ldapSortKey);
		}
		return sortReqControl;
	}	
}
