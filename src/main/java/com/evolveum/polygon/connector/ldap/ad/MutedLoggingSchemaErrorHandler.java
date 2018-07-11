/**
 * Copyright (c) 2018 Evolveum
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

import java.util.List;

import org.apache.directory.api.ldap.model.schema.LoggingSchemaErrorHandler;
import org.slf4j.Logger;

/**
 * @author semancik
 *
 */
public class MutedLoggingSchemaErrorHandler extends LoggingSchemaErrorHandler {

	@Override
	protected void log( Logger log, String message ) {
		// Push logging messages down to trace level. There are too many schema errors in AD.
        log.trace( message );
    }

}
