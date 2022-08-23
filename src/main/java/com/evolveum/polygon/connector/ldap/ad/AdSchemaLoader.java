/**
 * Copyright (c) 2019 Evolveum
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PagedResultsImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.ldap.client.api.DefaultSchemaLoader;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.common.logging.Log;

import com.evolveum.polygon.connector.ldap.LdapConstants;
import com.evolveum.polygon.connector.ldap.LdapUtil;

/**
 * @author semancik
 *
 */
public class AdSchemaLoader extends DefaultSchemaLoader {

    private static final Log LOG = Log.getLog(AdSchemaLoader.class);

    private Map<String,Entry> classEntryMap;
    private Map<String,Entry> attributeEntryMap;
    private Dn schemaNamingContextDn;

    public AdSchemaLoader(LdapConnection connection) throws LdapException {
        if ( connection == null ) {
            throw new InvalidConnectionException( I18n.err( I18n.ERR_04104_NULL_CONNECTION_CANNOT_CONNECT ) );
        }
        setConnection(connection);
        setRelaxed(true);
        setQuirksMode(true);

        setUpHardwiredAdSchemas();

        boolean wasConnected = connection.isConnected();
        try {
            if ( !wasConnected ) {
                connection.connect();
            }
            Entry rootDse = connection.lookup( Dn.ROOT_DSE, SchemaConstants.SUBSCHEMA_SUBENTRY_AT,
                    SchemaConstants.VENDOR_NAME_AT, AdConstants.ATTRIBUTE_SCHEMA_NAMING_CONTEXT_NAME );
            if ( rootDse == null ) {
                // TODO
            }

            Dn subschemaSubentryDn;
            Attribute subschemaSubentryAttribute = rootDse.get( SchemaConstants.SUBSCHEMA_SUBENTRY_AT );
            if ( ( subschemaSubentryAttribute != null ) && ( subschemaSubentryAttribute.size() > 0 ) ) {
                subschemaSubentryDn = new Dn( connection.getSchemaManager(), subschemaSubentryAttribute.getString() );
            }

            Attribute schemaNamingContext = rootDse.get( AdConstants.ATTRIBUTE_SCHEMA_NAMING_CONTEXT_NAME );
            if ( ( schemaNamingContext != null ) && ( schemaNamingContext.size() > 0 ) ) {
                schemaNamingContextDn = new Dn( connection.getSchemaManager(), schemaNamingContext.getString() );
            }

            loadAdSchemas();

        } catch (CursorException e) {
            throw new LdapException("Cursor error while searching AD schema: "+e.getMessage(), e);

        } finally {
            if ( ( !wasConnected ) && ( connection.isConnected() ) ) {
                try {
                    connection.close();
                } catch ( IOException e ) {
                    throw new LdapException( e );
                }
            }
        }
    }

    private void setUpHardwiredAdSchemas() {
        addSyntax(LdapConstants.SYNTAX_AD_OBJECT_DS_DN, "Object(DS-DN)", true);                            // 2.5.5.1
        addSyntax(LdapConstants.SYNTAX_AD_STRING_OBJECT_IDENTIFIER, "String(Object-Identifier)", true);    // 2.5.5.2
        addSyntax(LdapConstants.SYNTAX_AD_STRING_CASE, "String(Case)", true);                            // 2.5.5.3
        addSyntax(LdapConstants.SYNTAX_AD_STRING_TELETEX, "String(Teletex)", true);                        // 2.5.5.4
        addSyntax(LdapConstants.SYNTAX_AD_STRING_IA5, "String(IA5)", true);                                // 2.5.5.5
        addSyntax(LdapConstants.SYNTAX_AD_STRING_NUMERIC, "String(Numeric)", true);                        // 2.5.5.6
        addSyntax(LdapConstants.SYNTAX_AD_OBJECT_DN_BINARY, "Object(DN-Binary)", true);                    // 2.5.5.7
        addSyntax(LdapConstants.SYNTAX_AD_ADSTYPE_BOOLEAN, "ADSTYPE_BOOLEAN", true);                    // 2.5.5.8
        addSyntax(LdapConstants.SYNTAX_AD_ADSTYPE_INTEGER, "ADSTYPE_INTEGER", true);                     // 2.5.5.9
        addSyntax(LdapConstants.SYNTAX_AD_ADSTYPE_OCTET_STRING, "ADSTYPE_OCTET_STRING", false);            // 2.5.5.10
        addSyntax(LdapConstants.SYNTAX_AD_UTC_TIME, "UTC Time", true);                                    // 2.5.5.11
        addSyntax(LdapConstants.SYNTAX_AD_STRING_UNICODE, "String(Unicode)", true);                        // 2.5.5.12
        addSyntax(LdapConstants.SYNTAX_AD_OBJECT_PRESENTATION_ADDRESS, "Object(Presentation-Address)", true); // 2.5.5.13
        addSyntax(LdapConstants.SYNTAX_AD_OBJECT_ACCESS_POINT, "Object(Access-Point)", true);            // 2.5.5.14
        addSyntax(LdapConstants.SYNTAX_AD_ADSTYPE_NT_SECURITY_DESCRIPTOR, "ADSTYPE_NT_SECURITY_DESCRIPTOR", false); // 2.5.5.15
        addSyntax(LdapConstants.SYNTAX_AD_LARGE_INTEGER, "LargeInteger", true);                            // 2.5.5.16
        // Even though this is "String(Sid)", it is not really string. It is binary.
        addSyntax(LdapConstants.SYNTAX_AD_STRING_SID, "String(Sid)", false);                            // 2.5.5.17
    }

    private LdapSyntax addSyntax(String syntaxOid, String description, boolean isHumanReadable) {
        LdapSyntax syntax = new LdapSyntax(syntaxOid, description, isHumanReadable);
        syntax.setEnabled(true);
        syntax.setSchemaName(AdConstants.AD_SCHEMA_NAME);
        updateSchemas(syntax);
        return syntax;
    }

    private void loadAdSchemas() throws LdapException, CursorException {

        classEntryMap = new HashMap<>();
        attributeEntryMap = new HashMap<>();

        byte[] cookie = null;
        int pageSize = 200;

        do {
            SearchRequest req = new SearchRequestImpl();
            req.setBase(schemaNamingContextDn);
            req.setFilter(LdapUtil.createAllSearchFilter());
            req.setScope(SearchScope.SUBTREE);

            PagedResults pagedResultsControl = new PagedResultsImpl();
            pagedResultsControl.setCookie(cookie);
            pagedResultsControl.setCritical(true);
            pagedResultsControl.setSize(pageSize);
            req.addControl(pagedResultsControl);

            if (LOG.isOk()) {
                LOG.ok("Schema search request: baseDn={0} PagedResults( pageSize = {1}, cookie = {2} )",
                        schemaNamingContextDn, pageSize, cookie==null?null:Base64.getEncoder().encodeToString(cookie));
            }

            SearchCursor schemaCursor = getConnection().search(req);
            while (true) {
                boolean hasNext = schemaCursor.next();
                if (!hasNext) {
                    break;
                }
                Response response = schemaCursor.get();
                if (response instanceof SearchResultEntry) {
                    Entry schemaEntry = ((SearchResultEntry)response).getEntry();
//                    LOG.ok("AD schema entry: {0}", schemaEntry);
                    switch (getSchemaObjectClass(schemaEntry)) {
                        case AdConstants.OBJECT_CLASS_CLASS_SCHEMA:
                            addToEntryMap(classEntryMap, schemaEntry);
                            break;
                        case AdConstants.OBJECT_CLASS_ATTRIBUTE_SCHEMA:
                            addToEntryMap(attributeEntryMap, schemaEntry);
                            parseAttribute(schemaEntry);
                            break;
                        case AdConstants.OBJECT_CLASS_DMD:
                            // Ignore. Root schema object itself.
                            break;
                        case AdConstants.OBJECT_CLASS_SUB_SCHEMA:
                            // Ignore. This is regular LDAP-like schema.
                            break;
                        default:
                                throw new LdapSchemaException("Unknown schema object class "+getSchemaObjectClass(schemaEntry));
                    }
                }
            }
            SearchResultDone searchResultDone = schemaCursor.getSearchResultDone();
            LOG.ok("Search results done: {0}", searchResultDone);
            if (searchResultDone != null) {
                LdapResult ldapResult = searchResultDone.getLdapResult();
                if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
                    throw new LdapSchemaException("Error searching schema: " + ldapResult.getResultCode());
                }
                PagedResults pagedResultsResponseControl = (PagedResults)searchResultDone.getControl(PagedResults.OID);
                if (pagedResultsResponseControl != null) {
                    if (pagedResultsResponseControl.getCookie() != null) {
                        cookie = pagedResultsResponseControl.getCookie();
                        if (cookie.length == 0) {
                            cookie = null;
                        }
                    }
                } else {
                    LOG.warn("No paged results control in schema search response");
                }
            }
            LdapUtil.closeDoneCursor(schemaCursor);
        } while (cookie != null);

        LOG.ok("Loaded AD schema, {0} classes, {1} attributes", classEntryMap.size(), attributeEntryMap.size());

        for( java.util.Map.Entry<String, Entry> mapEntry : attributeEntryMap.entrySet()) {
            parseAttribute(mapEntry);
        }

        for( java.util.Map.Entry<String, Entry> mapEntry : classEntryMap.entrySet()) {
            parseClass(mapEntry);
        }

        // Allow GC to free the memory
        classEntryMap = null;
        attributeEntryMap = null;
    }

    private String addToEntryMap(Map<String, Entry> entryMap, Entry schemaEntry) throws LdapSchemaException {
        String ldapName = LdapUtil.getStringAttribute(schemaEntry, AdConstants.ATTRIBUTE_LDAP_DISPLAY_NAME_NAME);
        Entry existingEntry = entryMap.get(ldapName);
        if (existingEntry != null) {
            LOG.warn("Conflicting schema entries:\n{0}\n{1}", existingEntry, schemaEntry);
            throw new LdapSchemaException("Conflicting schema entries "+schemaEntry);
        }
        entryMap.put(ldapName, schemaEntry);
        return ldapName;
    }

    private void parseAttribute(java.util.Map.Entry<String, Entry> mapEntry) {
        Entry schemaEntry = mapEntry.getValue();
        String oid = LdapUtil.getStringAttribute(schemaEntry, AdConstants.ATTRIBUTE_ATTRIBUTE_ID_NAME);
        AdAttributeType attributeType = new AdAttributeType(oid);
        attributeType.setNames(mapEntry.getKey());
        attributeType.setDescription(LdapUtil.getStringAttribute(schemaEntry, SchemaConstants.CN_AT));
        attributeType.setEnabled(true);
        attributeType.setRelaxed(true);
        attributeType.setSingleValued(LdapUtil.getBooleanAttribute(schemaEntry, AdConstants.ATTRIBUTE_IS_SINGLE_VALUED_NAME, false));
        String syntaxOid = LdapUtil.getStringAttribute(schemaEntry, AdConstants.ATTRIBUTE_ATTRIBUTE_SYNTAX_NAME);
        attributeType.setSyntaxOid(syntaxOid);

//        attributeType.setUsage(usage);
        attributeType.setUserModifiable(!LdapUtil.getBooleanAttribute(schemaEntry, AdConstants.ATTRIBUTE_SYSTEM_ONLY_NAME, false));

//        attributeType.setEquality(equality);
//        attributeType.setOrdering(ordering);
//        attributeType.setSubstring(substring);

        attributeType.setSchemaName(AdConstants.AD_SCHEMA_NAME);
        updateSchemas(attributeType);
    }


    private void parseClass(java.util.Map.Entry<String, Entry> mapEntry) throws LdapSchemaException {
        Entry schemaEntry = mapEntry.getValue();
        String className = mapEntry.getKey();
        String oid = LdapUtil.getStringAttribute(schemaEntry, AdConstants.ATTRIBUTE_GOVERNS_ID_NAME);
        AdObjectClass objectClass = new AdObjectClass(oid);
        objectClass.setNames(className);
        // TODO
        objectClass.setDescription(LdapUtil.getStringAttribute(schemaEntry, SchemaConstants.CN_AT));
        objectClass.setEnabled(true);

        if (!className.equals(SchemaConstants.TOP_OC)) {
            // AD declared object class top as its own superclass. Which is insane and it leads to infinite loops in schema processing.
            String superClassName = LdapUtil.getStringAttribute(schemaEntry, AdConstants.ATTRIBUTE_SUB_CLASS_OF_NAME);
            if (superClassName != null) {
                if (superClassName.equals(className)) {
                    throw new LdapSchemaException("Class "+className+" is its own superclass ("+superClassName+")");
                }
                // Name of this method says "oid" but what it really mean is "name"
                objectClass.setSuperiorOids(Arrays.asList(superClassName));
            }
        }

        List<String> mustAttributeNames = new ArrayList();
        addToAttributesList(mustAttributeNames, schemaEntry, AdConstants.ATTRIBUTE_MUST_CONTAIN_NAME);
        addToAttributesList(mustAttributeNames, schemaEntry, AdConstants.ATTRIBUTE_SYSTEM_MUST_CONTAIN_NAME);
        // Name of this method says "oid" but what it really mean is "name"
        objectClass.setMustAttributeTypeOids(mustAttributeNames);

        List<String> mayAttributeNames = new ArrayList();
        addToAttributesList(mayAttributeNames, schemaEntry, AdConstants.ATTRIBUTE_MAY_CONTAIN_NAME);
        addToAttributesList(mayAttributeNames, schemaEntry, AdConstants.ATTRIBUTE_SYSTEM_MAY_CONTAIN_NAME);
        // Name of this method says "oid" but what it really mean is "name"
        objectClass.setMayAttributeTypeOids(mayAttributeNames);

        objectClass.setDefaultObjectCategory(LdapUtil.getStringAttribute(schemaEntry, AdConstants.ATTRIBUTE_DEFAULT_OBJECT_CATEGORY_NAME));

        objectClass.setSchemaName(AdConstants.AD_SCHEMA_NAME);
//        LOG.ok("Registering object class {0} ({1}):\n{2}", className, oid, objectClass);
        updateSchemas(objectClass);
    }

    private void addToAttributesList(List<String> attributeNames, Entry schemaEntry, String attributeName) throws LdapSchemaException {
        Attribute attribute = schemaEntry.get(attributeName);
        if (attribute == null) {
            return;
        }
        for (Value value : attribute) {
            attributeNames.add(value.getString());
        }
    }

    private void parseAttribute(Entry schemaEntry) {
        // TODO Auto-generated method stub

    }

    private String getSchemaObjectClass(Entry schemaEntry) throws LdapException {
        Attribute objectClassAttr = schemaEntry.get( SchemaConstants.OBJECT_CLASS_AT );
        if (objectClassAttr == null) {
            throw new LdapException("No objectClass in "+schemaEntry.getDn());
        }
        String schemaObjectClass = null;
        for (Value value : objectClassAttr) {
            if (SchemaConstants.TOP_OC.equals(value.getString())) {
                continue;
            }
            schemaObjectClass = value.getString();
        }
        if (schemaObjectClass == null) {
            throw new LdapException("Cannot determine schema objectClass in "+schemaEntry.getDn());
        }
        return schemaObjectClass;
    }

}
