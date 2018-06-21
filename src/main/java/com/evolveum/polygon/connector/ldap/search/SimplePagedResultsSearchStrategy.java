/**
 * Copyright (c) 2014-2018 Evolveum
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

import java.util.Base64;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PagedResultsImpl;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class SimplePagedResultsSearchStrategy<C extends AbstractLdapConfiguration> extends SearchStrategy<C> {
	
	private static final Log LOG = Log.getLog(SimplePagedResultsSearchStrategy.class);
	
	private int lastListSize = -1;
	private byte[] cookie = null;

	public SimplePagedResultsSearchStrategy(ConnectionManager<C> connectionManager,
			AbstractLdapConfiguration configuration, AbstractSchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		super(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
		if (options != null && options.getPagedResultsCookie() != null) {
        	cookie = Base64.getDecoder().decode(options.getPagedResultsCookie());
        }
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.apache.directory.api.ldap.model.message.SearchScope, java.lang.String[])
	 */
	@Override
	public void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes)
			throws LdapException {
		
		SortRequest sortReqControl = createSortControl(null, null);
		
		int pageSize = getDefaultPageSize();
		int offset = 0;
		if (getOptions() != null && getOptions().getPagedResultsOffset() != null) {
        	offset = getOptions().getPagedResultsOffset() - 1;
        	if (offset != 0) {
        		LOG.info("Inefficient search using SimplePaged control and offset {0}",offset);
        	}
        }
		
		
		boolean proceed = true;
		int numberOfResutlsHandled = 0;
        int numberOfResultsSkipped = 0;
        int retryAttempts = 0;
        
        LdapNetworkConnection connection = getConnection(baseDn);
        Referral referral = null; // remember this in case we need a reconnect
        
        OUTER: do {
        	SearchRequest req = new SearchRequestImpl();
    		req.setBase(baseDn);
    		req.setFilter(preProcessSearchFilter(filterNode));
    		req.setScope(scope);
    		applyCommonConfiguration(req);
    		if (attributes != null) {
    			req.addAttributes(attributes);
    		}
    		
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
            			pageSize, cookie==null?null:Base64.getEncoder().encodeToString(cookie));
            }
        	req.addControl(pagedResultsControl);
        	
        	int responseResultCount = 0;
        	SearchCursor searchCursor = executeSearch(connection, req);
    		try {
    			while (proceed) {
    				try {
						boolean hasNext = searchCursor.next();
						if (!hasNext) {
							break;
						}
					} catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
						logSearchError(connection, e);
						// Server disconnected. And by some miracle this was not caught by
						// checkAlive or connection manager.
						retryAttempts++;
		    			if (retryAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
		    				// TODO: better exception. Maybe re-throw exception from the last error?
		    				throw new ConnectorIOException("Maximum number of reconnect attemps exceeded");
		    			}
						LOG.ok("Connection error ({0}), reconnecting", e.getMessage(), e);
						LdapUtil.closeCursor(searchCursor);
						connection = getConnectionReconnect(baseDn, referral);
						continue OUTER;
					}
    				Response response = searchCursor.get();
    				if (response instanceof SearchResultEntry) {
    					responseResultCount++;
    					if (offset > numberOfResultsSkipped) {
                    		numberOfResultsSkipped++;
                    		// skip processing
                    	} else {
                        	numberOfResutlsHandled++;
        			        Entry entry = ((SearchResultEntry)response).getEntry();
        			        logSearchResult(connection, entry);
        			        proceed = handleResult(connection, entry);
        			        if (!proceed) {
                            	LOG.ok("Ending search because handler returned false");
                            }
                    	}
    			        
    			    } else {
    			    	LOG.warn("Got unexpected response: {0}", response);
    			    }
    			}
    			
    			SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
    			LdapUtil.closeCursor(searchCursor);
    			
				if (searchResultDone != null) {
    				LdapResult ldapResult = searchResultDone.getLdapResult();
			    	PagedResults pagedResultsResponseControl = (PagedResults)searchResultDone.getControl(PagedResults.OID);
			    	String extra = "no paged response control";
			    	if (pagedResultsResponseControl != null) {
			    		StringBuilder sb = new StringBuilder();
			    		sb.append("paged control size=");
			    		sb.append(pagedResultsResponseControl.getSize());
			    		if (pagedResultsResponseControl.getCookie() != null) {
			    			sb.append(" cookie=");
			    			byte[] cookie = pagedResultsResponseControl.getCookie();
			    			if (cookie == null) {
			    				sb.append("null");
			    			} else {
			    				sb.append(Base64.getEncoder().encodeToString(cookie));
			    			}
			    		}
			    		extra = sb.toString();
			    		cookie = pagedResultsResponseControl.getCookie();
			    		lastListSize = pagedResultsResponseControl.getSize();
			    		if (lastListSize == 0) {
			    			// RFC2696 specifies zero as "I do not know". We use -1 for that.
			    			lastListSize = -1;
			    		}
			    	} else {
			    		LOG.ok("no paged result control in the response");
			    		cookie = null;
			    		lastListSize = -1;
			    	}
			    	logSearchResult(connection, "Done", ldapResult, extra);
			    	
			    	if (ldapResult.getResultCode() == ResultCodeEnum.REFERRAL && !getConfiguration().isReferralStrategyThrow()) {
			    		referral = ldapResult.getReferral();
			    		if (getConfiguration().isReferralStrategyIgnore()) {
			    			LOG.ok("Ignoring referral {0}", referral);
			    		} else {
			    			LOG.ok("Following referral {0}", referral);
			    			retryAttempts++;
			    			if (retryAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
			    				// TODO: better exception. Maybe re-throw exception from the last error?
			    				throw new ConnectorIOException("Maximum number of attemps exceeded");
			    			}
			    			connection = getConnection(baseDn, referral);
			    			if (connection == null) {
			    				throw new ConnectorIOException("Cannot get connection based on referral "+referral);
			    			}
			    			lastListSize = -1;
			    	        cookie = null;
			    			continue;
			    		}
			    		
			    	} else if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
			    		// continue the loop
			    		
			    	} else {
    					String msg = "LDAP error during search: "+LdapUtil.formatLdapMessage(ldapResult);
    					if (ldapResult.getResultCode() == ResultCodeEnum.SIZE_LIMIT_EXCEEDED && getOptions() != null && getOptions().getAllowPartialResults() != null && getOptions().getAllowPartialResults()) {
    						LOG.ok("{0} (allowed error)", msg);
    						setCompleteResultSet(false);
    					} else {
    						LOG.error("{0}", msg);
    						throw LdapUtil.processLdapResult("LDAP error during search", ldapResult);
    					}
    					break;
    				}
    			}
    			
    		} catch (CursorException e) {
    			// TODO: better error handling
    			LOG.error("Error:", e);
    			throw new ConnectorIOException(e.getMessage(), e);
    		}
    		
    		if (responseResultCount == 0) {
            	// Zero results returned. This is either a hidden error or end of search.
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
        
        // TODO: properly abandon the paged search by sending request with size=0 and cookie=lastCookie
	}

	@Override
	public int getRemainingPagedResults() {
		if (lastListSize < 0) {
			return lastListSize;
		} else {
			return lastListSize - getNumberOfEntriesFound();
		}
	}
        
    @Override
	public String getPagedResultsCookie() {
		if (cookie == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(cookie);
	}
    
    

}
