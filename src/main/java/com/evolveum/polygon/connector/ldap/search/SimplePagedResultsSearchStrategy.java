/**
 * Copyright (c) 2014 Evolveum
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

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PagedResultsImpl;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortRequestControlImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SortKey;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.SchemaTranslator;

/**
 * @author semancik
 *
 */
public class SimplePagedResultsSearchStrategy extends SearchStrategy {
	
	private static final Log LOG = Log.getLog(SimplePagedResultsSearchStrategy.class);
	
	private int lastListSize = -1;
	private byte[] cookie = null;

	public SimplePagedResultsSearchStrategy(LdapNetworkConnection connection,
			LdapConfiguration configuration, SchemaTranslator schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		super(connection, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
		if (options != null && options.getPagedResultsCookie() != null) {
        	cookie = Base64.decode(options.getPagedResultsCookie());
        }
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.apache.directory.api.ldap.model.message.SearchScope, java.lang.String[])
	 */
	@Override
	public void search(String baseDn, ExprNode filterNode, SearchScope scope, String[] attributes)
			throws LdapException {
		
		SortRequest sortReqControl = createSortControl(null, null);
		
		int pageSize = getDefaultPageSize();
		int offset = 0;
		if (getOptions() != null && getOptions().getPagedResultsOffset() != null) {
        	offset = getOptions().getPagedResultsOffset();
        	if (offset != 0) {
        		LOG.info("Inefficient search using SimplePaged control and offset {0}",offset);
        	}
        }
		
		
		boolean proceed = true;
		int numberOfResutlsHandled = 0;
        int numberOfResultsSkipped = 0;
        
        do {
        	SearchRequest req = new SearchRequestImpl();
    		req.setBase(new Dn(baseDn));
    		req.setFilter(filterNode);
    		req.setScope(scope);
    		applyCommonConfiguration(req);
    		if (attributes != null) {
    			req.addAttributes(attributes);
    		};
    		
    		if (sortReqControl != null) {
    			req.addControl(sortReqControl);
    		}
        	
    		// Simple Paged Results control
        	if (getOptions() != null && getOptions().getPageSize() != null && 
        			((numberOfResutlsHandled + numberOfResultsSkipped + pageSize) > offset + getOptions().getPageSize())) {
        		pageSize = offset + getOptions().getPageSize() - (numberOfResutlsHandled + numberOfResultsSkipped);
            }
        	PagedResults pagedResultsControl = new PagedResultsImpl();
        	pagedResultsControl.setCookie(cookie);
        	pagedResultsControl.setCritical(true);
        	pagedResultsControl.setSize(pageSize);
        	if (LOG.isOk()) {
            	LOG.ok("LDAP search request: PagedResults( pageSize = {0}, cookie = {1} )", 
            			pageSize, Base64.encode(cookie));
            }
        	req.addControl(pagedResultsControl);
        	
        	int responseResultCount = 0;
        	SearchCursor searchCursor = executeSearch(req);
        	LOG.ok("Cursor: {0}", searchCursor);
    		try {
    			while (proceed && searchCursor.next()) {
    				Response response = searchCursor.get();
    				LOG.ok("Response: {0}", response);
    				if (response instanceof SearchResultEntry) {
    					responseResultCount++;
    					if (offset > numberOfResultsSkipped) {
                    		numberOfResultsSkipped++;
                    		// skip processing
                    	} else {
                        	numberOfResutlsHandled++;
        			        Entry entry = ((SearchResultEntry)response).getEntry();
        			        logSearchResult(entry);
        			        proceed = handleResult(entry);
        			        if (!proceed) {
                            	LOG.ok("Ending search because handler returned false");
                            }
                    	}
    			        
    			    } else {
    			    	LOG.warn("Got unexpected response: {0}", response);
    			    }
    			}
    			
    			SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
    			LOG.ok("DONE: {0}", searchResultDone);
    			if (searchResultDone != null) {
    				LdapResult ldapResult = searchResultDone.getLdapResult();
			    	LOG.ok("result: {0}", ldapResult);
			    	PagedResults pagedResultsResponseControl = (PagedResults)searchResultDone.getControl(PagedResults.OID);
			    	String extra = "no paged response control";
			    	if (pagedResultsResponseControl != null) {
			    		StringBuilder sb = new StringBuilder();
			    		sb.append("paged control size=");
			    		sb.append(pagedResultsResponseControl.getSize());
			    		if (pagedResultsResponseControl.getCookie() != null) {
			    			sb.append(" cookie=");
			    			sb.append(Base64.encode(pagedResultsResponseControl.getCookie()));
			    		}
			    		extra = sb.toString();
			    		cookie = pagedResultsResponseControl.getCookie();
			    		lastListSize = pagedResultsResponseControl.getSize();
			    	} else {
			    		LOG.ok("no paged result control in the response");
			    		cookie = null;
			    		lastListSize = -1;
			    	}
			    	logSearchResult(ldapResult, extra);
    			}
    			
    			searchCursor.close();
    		} catch (CursorException e) {
    			// TODO: better error handling
    			LOG.error("Error:", e);
    			throw new ConnectorIOException(e.getMessage(), e);
    		}
    		
    		if (responseResultCount == 0) {
            	// Zero results returned. This is either a hidded error or end of search.
            	LOG.warn("Zero results returned from paged search");
            	break;
            }
    		if (!proceed) {
            	break;
            }
    		if (getOptions() != null && getOptions().getPageSize() != null && 
        			((numberOfResutlsHandled + numberOfResultsSkipped) >= offset + getOptions().getPageSize())) {
            	break;
            }
        } while (cookie != null);

        LOG.ok("Search done");
	}

	@Override
	public int getRemainingPagedResults() {
		return lastListSize;
	}
        
    @Override
	public String getPagedResultsCookie() {
		if (cookie == null) {
			return null;
		}
		return Base64.encode(cookie);
	}

}
