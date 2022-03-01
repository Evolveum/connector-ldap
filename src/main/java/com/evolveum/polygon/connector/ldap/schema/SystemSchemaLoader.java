/*
 * Copyright (c) 2022 Evolveum
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

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.registries.AbstractSchemaLoader;
import org.apache.directory.api.ldap.model.schema.registries.DefaultSchema;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.ResourceMap;
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.api.util.Strings;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Loads some parts from "system" schema, taken from Directory API JARs.
 * This includes normalizers and matching rules, that are needed for DN comparison
 * (and other things) to work correctly.
 *
 * Also, this loader renames the schema from "system" to "internal" to avoid conflicts.
 */
public class SystemSchemaLoader extends AbstractSchemaLoader {

    private static final String SEPARATOR_PATTERN = "[/\\Q\\\\E]";

    private static final String LDIF_EXT = "ldif";

    /** a map of all the schema resources in Directory API */
    private static final Map<String, Boolean> RESOURCE_MAP = ResourceMap.getResources( Pattern
            .compile( "schema" + SEPARATOR_PATTERN + "ou=schema.*" ) );

    private static final String SCHEMA_NAME_SYSTEM = "system";
    private static final String SCHEMA_NAME_INTERNAL = "internal";

    private static final String SCHEMA_SYSTEM_ROOT_DIR_PATH = "schema/ou=schema/cn=" + SCHEMA_NAME_SYSTEM + "/";

    private DefaultSchema schema;

    public SystemSchemaLoader() {
        initializeSchemas();
    }

    private void initializeSchemas() {
        Pattern pat = Pattern.compile( "schema" + SEPARATOR_PATTERN + "ou=schema"
                + SEPARATOR_PATTERN + "cn=[a-z0-9-_]*\\." + LDIF_EXT );

        for ( String file : RESOURCE_MAP.keySet() ) {
            if ( pat.matcher( file ).matches() ) {
                try {
                    URL resource = getResource( file, "schema LDIF file" );
                    try ( InputStream in = resource.openStream() ) {
                        try (LdifReader reader = new LdifReader(in)) {
                            LdifEntry ldifEntry = reader.next();
                            Entry ldapEntry = ldifEntry.getEntry();
                            String cn = ldapEntry.get(SchemaConstants.CN_AT).getString();
                            if (SCHEMA_NAME_SYSTEM.equals(cn)) {

                                String owner = null;
                                Attribute creatorsName = ldapEntry.get( SchemaConstants.CREATORS_NAME_AT );
                                if ( creatorsName != null ) {
                                    owner = creatorsName.getString();
                                }
                                schema = new DefaultSchema( this, SCHEMA_NAME_INTERNAL, owner, StringConstants.EMPTY_STRINGS, false );

                            }
                        }
                    }
                } catch ( Exception e ) {
                    throw new RuntimeException("Error loading schema resource "+ file + ": " + e.getMessage(), e);
                }
            }
        }
    }

    private URL getResource( String resource, String msg ) throws IOException {
        if ( RESOURCE_MAP.get( resource ) ) {
            // We to allow loading of multiple resources, mostly for testability
            // E.g. midPoint integration tests are using the API both directly (asserting state of LDAP server)
            // and indirectly (in the connector). Therefore from the point of view of the connector the resources
            // are loaded twice. They are the same, therefore loading any of them is OK.
            return DefaultSchemaLdifExtractor.getAnyResource( resource, msg );
        } else {
            return new File( resource ).toURI().toURL();
        }
    }

    private List<Entry> loadEntries(String pathSegment, Schema[] schemas) throws LdapException, IOException {
        List<Entry> output = new ArrayList<>();
        if ( schemas == null ) {
            return output;
        }
        for ( Schema schema : schemas ) {
            if (!schema.getSchemaName().equals(SCHEMA_NAME_INTERNAL)) {
                throw new IllegalArgumentException(SystemSchemaLoader.class.getName() + " cannot load schema "+schema.getSchemaName());
            }
            String start = SCHEMA_SYSTEM_ROOT_DIR_PATH + pathSegment + "/m-oid=";
            String end = "." + LDIF_EXT;
            for ( String resourcePath : RESOURCE_MAP.keySet() ) {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) ) {
                    URL resource = getResource( resourcePath, pathSegment + " LDIF file" );
                    try ( InputStream in = resource.openStream();
                          LdifReader reader = new LdifReader( in ) ) {
                        LdifEntry entry = reader.next();
                        output.add( entry.getEntry() );
                    }
                }
            }
        }

        return output;
    }

    @Override
    public List<Entry> loadAttributeTypes(Schema... schemas) throws LdapException, IOException {
        // Do NOT load attribute types. If we load them now, the definitions from the server will be ignored.
        // Those are standard attribute types, and in theory they should be the same.
        // However, there are servers that ignore the standards, such as AD.
        // We have to respect their ignorance.
//        return loadEntries(SchemaConstants.ATTRIBUTE_TYPES_PATH, schemas);
        return new ArrayList<>();
    }

    @Override
    public List<Entry> loadComparators(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.COMPARATORS_PATH, schemas);
    }

    @Override
    public List<Entry> loadDitContentRules(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.DIT_CONTENT_RULES_PATH, schemas);
    }

    @Override
    public List<Entry> loadDitStructureRules(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.DIT_STRUCTURE_RULES_PATH, schemas);
    }

    @Override
    public List<Entry> loadMatchingRules(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.MATCHING_RULES_PATH, schemas);
    }

    @Override
    public List<Entry> loadMatchingRuleUses(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.MATCHING_RULE_USE_PATH, schemas);
    }

    @Override
    public List<Entry> loadNameForms(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.NAME_FORMS_PATH, schemas);
    }

    @Override
    public List<Entry> loadNormalizers(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.NORMALIZERS_PATH, schemas);
    }

    @Override
    public List<Entry> loadObjectClasses(Schema... schemas) throws LdapException, IOException {
        // Do NOT load object classes. If we load them now, the definitions from the server will be ignored.
        // Those are standard object classes, and in theory they should be the same.
        // However, there are servers that ignore the standards, such as AD.
        // We have to respect their ignorance.
//        return loadEntries(SchemaConstants.OBJECT_CLASSES_PATH, schemas);
        return new ArrayList<>();
    }

    @Override
    public List<Entry> loadSyntaxes(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.SYNTAXES_PATH, schemas);
    }

    @Override
    public List<Entry> loadSyntaxCheckers(Schema... schemas) throws LdapException, IOException {
        return loadEntries(SchemaConstants.SYNTAX_CHECKERS_PATH, schemas);
    }

    public Schema getInternalSchema() {
        return schema;
    }
}
