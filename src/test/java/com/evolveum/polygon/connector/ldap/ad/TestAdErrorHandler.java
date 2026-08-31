/*
 * Copyright (c) 2026 Evolveum
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

import com.evolveum.polygon.connector.ldap.ReconnectException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.LdapResultImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestAdErrorHandler {

    private final AdErrorHandler errorHandler = new AdErrorHandler();

    @DataProvider
    public Object[][] bindRequiredDiagnostics() {
        return new Object[][] {
                { "000004DC: LdapErr: DSID-0C0907E9, comment: Bind required" },
                { "000004DC: LdapErr: DSID-0C090A71, comment: Bind required" },
                { "000004DC: LdapErr: DSID-0C090C88, comment: Bind required" },
                { "000004DC: LdapErr: DSID-0C090D5A, comment: In order to perform this operation a successful bind "
                        + "must be completed on the connection., data 0, v4563" },
                { "000004DC: LdapErr: DSID-1234ABCD, comment: Bind required" },
                { "000004DC: Bind required" }
        };
    }

    @Test(dataProvider = "bindRequiredDiagnostics")
    public void testBindRequiredResultRequestsReconnect(String diagnostic) {
        Assert.assertTrue(errorHandler.processLdapResult("Searching accounts",
                result(ResultCodeEnum.OPERATIONS_ERROR, diagnostic)) instanceof ReconnectException);
    }

    @Test(dataProvider = "bindRequiredDiagnostics")
    public void testBindRequiredExceptionRequestsReconnect(String diagnostic) {
        Assert.assertTrue(errorHandler.processLdapException("Reading account",
                new LdapException(diagnostic)) instanceof ReconnectException);
    }

    @Test
    public void testInvalidCredentialsRemainSecurityError() {
        Assert.assertTrue(errorHandler.processLdapResult("Binding",
                result(ResultCodeEnum.INVALID_CREDENTIALS, "80090308: Logon failed, data 52e"))
                instanceof ConnectorSecurityException);
    }

    @Test
    public void testUnrelatedOperationsErrorDoesNotRequestReconnect() {
        Assert.assertFalse(errorHandler.processLdapResult("Searching accounts",
                result(ResultCodeEnum.OPERATIONS_ERROR, "00000001: Other operations error"))
                instanceof ReconnectException);
    }

    @Test
    public void testReturnsReconnectExceptionForKnownBindRequiredDsid() {
        // Without an AD subcode, only the DSID fallback can classify this exception.
        RuntimeException exception = errorHandler.processLdapException("Reading account",
                new LdapException("LdapErr: DSID-0C0907E9, comment: Bind required"));

        Assert.assertTrue(exception instanceof ReconnectException,
                "The caller must receive the exception as a return value to perform reconnection");
    }

    @Test
    public void testReturnsReconnectExceptionForDsidResult() {
        // Isolate the DSID fallback from the separate AD subcode classification.
        RuntimeException exception = errorHandler.processLdapResult("Searching accounts",
                result(ResultCodeEnum.OPERATIONS_ERROR,
                        "LdapErr: DSID-0C0907E9, comment: Bind required"));

        Assert.assertTrue(exception instanceof ReconnectException);
    }

    @Test
    public void testReturnsExceptionForAdSubcode() {
        RuntimeException exception = errorHandler.processLdapResult("Updating account",
                result(ResultCodeEnum.UNWILLING_TO_PERFORM, "0000051C: Invalid primary group"));

        Assert.assertTrue(exception instanceof InvalidAttributeValueException);
    }

    private LdapResult result(ResultCodeEnum resultCode, String diagnosticMessage) {
        LdapResult result = new LdapResultImpl();
        result.setResultCode(resultCode);
        result.setDiagnosticMessage(diagnosticMessage);
        return result;
    }
}
