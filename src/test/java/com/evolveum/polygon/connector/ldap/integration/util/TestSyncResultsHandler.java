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
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;

import java.util.ArrayList;

public class TestSyncResultsHandler implements SyncResultsHandler {
    private ArrayList<SyncDelta> uidResult = new ArrayList<>();
    private static final Log LOG = Log.getLog(TestSyncResultsHandler.class);

    public TestSyncResultsHandler() {
        uidResult.clear();
    }

    @Override
    public boolean handle(SyncDelta syncDelta) {

        if (syncDelta != null) {
            return uidResult.add(syncDelta);
        }

        return false;
    }

    public ArrayList<SyncDelta> getResult() {

        return uidResult;
    }

//    public boolean clear() {
//
//        uidResult.clear();
//
//        return uidResult.isEmpty();
//    }
}