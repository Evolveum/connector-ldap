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

/**
 * @author semancik
 *
 */
public class PowerHellExecutionException extends Exception {

	private Integer exitCode;
	private String stdout;
	private String stderr;
	private String promptMessage;
	
	public PowerHellExecutionException() {
		super();
	}

	public PowerHellExecutionException(String message, Throwable cause) {
		super(message, cause);
	}

	public PowerHellExecutionException(String message) {
		super(message);
	}

	public PowerHellExecutionException(Throwable cause) {
		super(cause);
	}
	
	public PowerHellExecutionException(String message, Throwable cause, Integer exitCode) {
		super(message, cause);
		this.exitCode = exitCode;
	}

	public PowerHellExecutionException(String message, Integer exitCode) {
		super(message);
		this.exitCode = exitCode;
	}

	public PowerHellExecutionException(Throwable cause, Integer exitCode) {
		super(cause);
		this.exitCode = exitCode;
	}

	public Integer getExitCode() {
		return exitCode;
	}

	public String getStdout() {
		return stdout;
	}

	public void setStdout(String stdout) {
		this.stdout = stdout;
	}

	public String getStderr() {
		return stderr;
	}

	public void setStderr(String stderr) {
		this.stderr = stderr;
	}

	public String getPromptMessage() {
		return promptMessage;
	}

	public void setPromptMessage(String promptMessage) {
		this.promptMessage = promptMessage;
	}
}
