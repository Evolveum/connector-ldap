/**
 * Copyright (c) 2017 Evolveum
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
import java.io.StringWriter;
import java.nio.charset.Charset;

import javax.net.ssl.HostnameVerifier;
import javax.xml.bind.DatatypeConverter;

import org.apache.cxf.interceptor.Fault;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;

import io.cloudsoft.winrm4j.client.Command;
import io.cloudsoft.winrm4j.client.WinRmClient;

/**
 * <p>
 * Simplistic shell emulation written in PowerShell and executed remotely
 * using WinRM (WS-MAN). PowerHell has ability to initialize PowerShell
 * environment once and then execute any number of commands in an interactive
 * fashion. This is needed especially for Exchange. For some strange reasons
 * the Exchange PowerShell snap-in takes extremely long time to initialize
 * (10-20sec). It is not possible to suffer this for every Exchange command
 * that we execute. Therefore we need to initialize PowerShell once, keep
 * the session running and run several commands as needed.
 * </p>
 * <p>
 * For reasons that are perhaps only known to Microsoft the PowerShell does
 * not process commands from stdin. It may not really be a shell, after all.
 * There is a PowerShell Remoting Protocol [MS-PSRP] that might be able to do
 * what we need. But it looks completely nuts. The PSRP seems to be using 
 * rogue element in the WS-MAN messages that contain base64-encoded mix of 
 * binary data and stand-alone XML snippets that contain other base-64 encoded
 * data which we have no idea what they are because we were too scared to have
 * a deeper look. Therefore we have made no attempt to implement PSRP. We value
 * our sanity.
 * </p>
 * <p>
 * Instead, we have to implement a shell inside PowerShell. So we can shell
 * while we shell. The PowerHell is a simple loop that takes string from stdin
 * and executes it. The executions are separated by prompt, so that the client
 * side can determine when a command execution ends and next command can be
 * sent.
 * </p> 
 * 
 * @author semancik
 */
public class PowerHell {
	
	private static final Log LOG = Log.getLog(PowerHell.class);
	public static final String PROMPT = ":::P0w3Rh3llPr0mPt:::";
	
	// Configuration
	private String endpointUrl;
	private String authenticationScheme;
	private String domainName;
	private String userName;
	private String password;
	private HostnameVerifier hostnameVerifier;
	private boolean disableCertificateChecks;
	private String initScriptlet;
	private String prompt = PROMPT;
	
	// State
	private WinRmClient client;
	private Command command;
	
	public String getEndpointUrl() {
		return endpointUrl;
	}

	public void setEndpointUrl(String endpointUrl) {
		this.endpointUrl = endpointUrl;
	}

	public String getAuthenticationScheme() {
		return authenticationScheme;
	}

	public void setAuthenticationScheme(String authenticationScheme) {
		this.authenticationScheme = authenticationScheme;
	}

	public String getDomainName() {
		return domainName;
	}

	public void setDomainName(String domainName) {
		this.domainName = domainName;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public HostnameVerifier getHostnameVerifier() {
		return hostnameVerifier;
	}

	public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
		this.hostnameVerifier = hostnameVerifier;
	}

	public boolean isDisableCertificateChecks() {
		return disableCertificateChecks;
	}

	public void setDisableCertificateChecks(boolean disableCertificateChecks) {
		this.disableCertificateChecks = disableCertificateChecks;
	}

	public String getInitScriptlet() {
		return initScriptlet;
	}

	public void setInitScriptlet(String initScriptlet) {
		this.initScriptlet = initScriptlet;
	}

	public String getPrompt() {
		return prompt;
	}

	public void setPrompt(String prompt) {
		this.prompt = prompt;
	}

	public void connect() throws PowerHellExecutionException {
		WinRmClient.Builder builder = WinRmClient.builder(endpointUrl, authenticationScheme);
		builder.credentials(domainName, userName, password);
		builder.disableCertificateChecks(disableCertificateChecks);
		builder.hostnameVerifier(hostnameVerifier);
		
		LOG.ok("Connecting WinRM for PowerHell. Endpoint: {0}", endpointUrl);
		client = builder.build();
		
		String psScript = createScript(initScriptlet);
		LOG.ok("Executing powershell. Script: {0}", psScript);
		
		long tsStart = System.currentTimeMillis();
		
		try {
			
			command = client.commandAsync("powershell -EncodedCommand "+encodeCommand(psScript));
			
		} catch (Fault e) {
			processFault("Executing command failed", e);
		}
		
		long tsAfterInit = System.currentTimeMillis();
		LOG.ok("Powershell running. init time: {0} ms", tsAfterInit-tsStart);
		
		while (true) {
			Integer exitCode = command.receive();
			
			String out = command.getLastOut();
    		String err = command.getLastErr();
    		logData("O<", out);
    		logData("E<", err);
    		
    		if (out != null && out.contains(prompt)) {
    			LOG.ok("First prompt detected");
    			break;
    		}
    		
    		if (exitCode != null) {
    			LOG.error("Exit code received before first prompt: {}", exitCode);
    			client.disconnect();
    			PowerHellExecutionException e = new PowerHellExecutionException("Exit code received before first prompt", exitCode);
    			e.setStdout(out);
    			e.setStderr(err);
    			throw e;
    		}
    	}
		
	}

	private void processFault(String message, Fault e) {
		// Fault does not have useful information on its own. Try to mine out something useful.
		Throwable cause = e.getCause();
		if (cause instanceof IOException) {
			if (cause.getMessage() != null && cause.getMessage().contains("Authorization loop detected")) {
				throw new ConnectorSecurityException(cause.getMessage(), e);
			}
			throw new ConnectorIOException(cause.getMessage(), e);
		}
		throw new ConnectorException(message + ": " + e.getMessage(), e);
	}

	public String runCommand(String outCommandLine) throws PowerHellExecutionException {
		
		long tsCommStart = System.currentTimeMillis();
		
		StringWriter writerStdOut = new StringWriter();
		StringWriter writerStdErr = new StringWriter();
		String promptMessage = null;
		
		String tx = outCommandLine + "\r\n";
		logData("I>", tx);
		
		command.send(tx);
		
		while (true) {
			Integer exitCode = command.receive();
			
			String out = command.getLastOut();
    		String err = command.getLastErr();
    		logData("O<", out);
    		logData("E<", err);

    		if (err != null) {
    			writerStdErr.write(err);
    		}
    		
    		if (out != null) {
    			int indexOfPrompt = out.indexOf(prompt);
    			if (indexOfPrompt >=0 ) {
    				writerStdOut.write(out.substring(0,indexOfPrompt));
    				int indexOfEol = out.indexOf("\n", indexOfPrompt);
    				promptMessage = out.substring(indexOfPrompt+prompt.length(), indexOfEol);
    				LOG.ok("Prompt detected, msg: {0}", promptMessage);
    				if (promptMessage != null && !promptMessage.matches("\\s*")) {
    					PowerHellExecutionException e = new PowerHellExecutionException(promptMessage, exitCode);
    	    			e.setStdout(writerStdOut.toString());
    	    			e.setStderr(writerStdErr.toString());
    	    			e.setPromptMessage(promptMessage);
    	    			throw e;
    				}
    				break;
    			} else {
    				writerStdOut.write(out);
    			}
    		}
    		
    		if (exitCode != null) {
    			LOG.error("Exit code received during command execution: {}", exitCode);
    			client.disconnect();
    			PowerHellExecutionException e = new PowerHellExecutionException("Exit code received during command execution", exitCode);
    			e.setStdout(writerStdOut.toString());
    			e.setStderr(writerStdErr.toString());
    			e.setPromptMessage(promptMessage);
    			throw e;
    		}
		}		
		
		long tsCommStop = System.currentTimeMillis();
		
		LOG.ok("Command {0} run time: {1} ms", outCommandLine, tsCommStop-tsCommStart);
		
		return writerStdOut.toString();
	}
	
	public int disconnect() {
		LOG.ok("Disconnecting, sending exit command");
		
		String tx = "exit\r\n";
		logData("I>", tx);
		
		command.send(tx);
	
		Integer exitCode = null;
		while (true) {
			exitCode = command.receive();
			
			String out = command.getLastOut();
    		String err = command.getLastErr();
    		logData("O<", out);
    		logData("E<", err);

    		if (exitCode != null) {    			
    			LOG.ok("Powershell exit code: {0}", exitCode);
    			break;
    		}
		}
		
		command.release();
		client.disconnect();
		
		return exitCode;
	}
	
	private String createScript(String initScriptlet) {
		StringBuilder sb = new StringBuilder();
		if (initScriptlet != null) {
			sb.append(initScriptlet);
			sb.append(";");
		}
		sb.append("write-host '").append(prompt).append("';"
			+ " while($s = [Console]::In.ReadLine()) { "
					+ "if($s -eq \"exit\") { exit } "
					+ "Invoke-Expression -ErrorVariable e $s; "
					+ "write-host '").append(prompt).append("'$e;"
					+ " $e = \"\" "
			+ "}");
		return sb.toString();
	}
	
	private String encodeCommand(String command) {
		byte[] bytes = command.getBytes(Charset.forName("UTF-16LE"));
        return DatatypeConverter.printBase64Binary(bytes);
	}
	
	private void logData(String prefix, String data) {
		if (LOG.isOk()) {
			if (data != null && !data.isEmpty()) {
				LOG.ok("{0} {1}", prefix, data);
			}
		}
	}

}
