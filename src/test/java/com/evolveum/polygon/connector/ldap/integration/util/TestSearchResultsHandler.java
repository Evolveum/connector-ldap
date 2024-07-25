/*
 * Copyright (c) 2010-2023 Evolveum
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

package com.evolveum.polygon.connector.ldap.integration.util;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.spi.SearchResultsHandler;

import java.util.ArrayList;

public class TestSearchResultsHandler implements SearchResultsHandler {

    private static final ArrayList<ConnectorObject> result = new ArrayList<>();

    private static final Log LOG = Log.getLog(TestSearchResultsHandler.class);

    public TestSearchResultsHandler() {

        result.clear();
    }

    @Override
    public boolean handle(ConnectorObject connectorObject) {
        LOG.ok("Test handler handling object : {0}", connectorObject);
        result.add(connectorObject);
        return true;
    }

    @Override
    public void handleResult(SearchResult result) {
    }

    public ArrayList<ConnectorObject> getResult() {

        return TestSearchResultsHandler.result;
    }
}