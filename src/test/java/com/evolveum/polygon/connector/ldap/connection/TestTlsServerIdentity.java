/* SPDX-License-Identifier: Apache-2.0 */
package com.evolveum.polygon.connector.ldap.connection;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Exercise the pool's actual configuration and LDAP client's LDAPS/StartTLS paths on loopback.
 *
 * @author yunho-kim
 */
public class TestTlsServerIdentity {
    private static final char[] FIXTURE_PASSWORD = "synthetic-only".toCharArray();
    private final KeyStore[] certificates = new KeyStore[4];
    private String previousTrustStore;
    private String previousTrustPassword;
    private String previousTrustType;

    @BeforeClass
    public void certificates() throws Exception {
        previousTrustStore = System.getProperty("javax.net.ssl.trustStore");
        previousTrustPassword = System.getProperty("javax.net.ssl.trustStorePassword");
        previousTrustType = System.getProperty("javax.net.ssl.trustStoreType");
        Path directory = Files.createTempDirectory(Path.of("target"), "ldap-tls-");
        String[] names = {"dns:localhost,ip:127.0.0.1", "dns:localhost", "ip:127.0.0.1", "dns:localhost,ip:127.0.0.1"};
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        for (int n = 0; n < names.length; n++) {
            Path file = directory.resolve("server-" + n + ".p12");
            Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                    "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                    "-dname", "CN=unrelated.invalid", "-ext", "SAN=" + names[n], "-storetype", "PKCS12",
                    "-keystore", file.toString(), "-storepass", new String(FIXTURE_PASSWORD), "-noprompt")
                    .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            Assert.assertTrue(process.waitFor(30, TimeUnit.SECONDS));
            Assert.assertEquals(process.exitValue(), 0);
            certificates[n] = KeyStore.getInstance("PKCS12");
            try (InputStream stream = Files.newInputStream(file)) {
                certificates[n].load(stream, FIXTURE_PASSWORD);
            }
            if (n < 3) anchors.setCertificateEntry("server-" + n, certificates[n].getCertificate("server"));
        }
        Path file = directory.resolve("anchors.p12");
        try (OutputStream stream = Files.newOutputStream(file)) {
            anchors.store(stream, FIXTURE_PASSWORD);
        }
        System.setProperty("javax.net.ssl.trustStore", file.toAbsolutePath().toString());
        System.setProperty("javax.net.ssl.trustStorePassword", new String(FIXTURE_PASSWORD));
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    @AfterClass(alwaysRun = true)
    public void restoreProperties() {
        restore("javax.net.ssl.trustStore", previousTrustStore);
        restore("javax.net.ssl.trustStorePassword", previousTrustPassword);
        restore("javax.net.ssl.trustStoreType", previousTrustType);
    }

    private void restore(String key, String value) {
        if (value == null) System.clearProperty(key); else System.setProperty(key, value);
    }

    @DataProvider
    public Object[][] cases() {
        return new Object[][] {
                {"ssl", "127.0.0.1", 0, false, true}, {"starttls", "127.0.0.1", 0, false, true},
                {"ssl", "localhost", 0, false, true}, {"starttls", "localhost", 0, false, true},
                // A certificate for the reverse-resolved name must not authenticate a configured IP.
                {"ssl", "127.0.0.1", 1, false, false}, {"starttls", "127.0.0.1", 1, false, false},
                // Conversely, a matching IP SAN must work without a reverse-DNS-name SAN.
                {"ssl", "127.0.0.1", 2, false, true}, {"starttls", "127.0.0.1", 2, false, true},
                {"ssl", "localhost", 2, false, false}, {"starttls", "localhost", 2, false, false},
                // Preserve the existing explicit insecure opt-out; never use it for a secure resource.
                {"ssl", "127.0.0.1", 1, true, true}, {"starttls", "127.0.0.1", 1, true, true},
                {"ssl", "127.0.0.1", 3, false, false}, {"starttls", "127.0.0.1", 3, false, false},
                {"ssl", "127.0.0.1", 3, true, true}, {"starttls", "127.0.0.1", 3, true, true}
        };
    }

    private LdapConnectionConfig configuration(String security, String host, int port, boolean insecure) throws Exception {
        LdapConfiguration configuration = new LdapConfiguration();
        configuration.setHost("unused-primary.invalid");
        configuration.setPort(port);
        configuration.setBaseContext("dc=example,dc=test");
        configuration.setConnectionSecurity(security);
        configuration.setAllowUntrustedSsl(insecure);
        configuration.setTimeout(3000L);
        configuration.recompute();
        ServerDefinition selected = ServerDefinition.createDefaultDefinition(configuration);
        selected.setHost(host);
        // A selected secondary server must supply its own identity, not the global primary host.
        ServerConnectionPool<LdapConfiguration> pool = new ServerConnectionPool<>(configuration, null, null);
        Method method = ServerConnectionPool.class.getDeclaredMethod("createLdapConnectionConfig", ServerDefinition.class);
        method.setAccessible(true);
        return (LdapConnectionConfig) method.invoke(pool, selected);
    }

    @Test(dataProvider = "cases")
    public void authenticatesSelectedEndpointBeforeBind(String mode, String host, int certificate,
            boolean insecure, boolean permitted) throws Exception {
        AtomicInteger binds = new AtomicInteger();
        AtomicBoolean tlsStarted = new AtomicBoolean();
        AtomicBoolean tlsCompleted = new AtomicBoolean();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(certificates[certificate], FIXTURE_PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getByName(host))) {
            listener.setSoTimeout(5000);
            Future<?> server = executor.submit(() -> {
                try (Socket raw = listener.accept()) {
                    raw.setSoTimeout(5000);
                    if ("starttls".equals(mode)) {
                        byte[] request = message(raw.getInputStream());
                        Assert.assertTrue(new String(request, StandardCharsets.ISO_8859_1).contains("1.3.6.1.4.1.1466.20037"));
                        respond(raw.getOutputStream(), request, 0x78);
                    }
                    try (SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(raw, "localhost", raw.getPort(), false)) {
                        tls.setUseClientMode(false);
                        tls.setSoTimeout(5000);
                        tlsStarted.set(true);
                        tls.startHandshake();
                        tlsCompleted.set(true);
                        byte[] bind = message(tls.getInputStream());
                        Assert.assertEquals(bind[2 + (bind[1] & 0xff)] & 0xff, 0x60);
                        binds.incrementAndGet();
                        respond(tls.getOutputStream(), bind, 0x61);
                    }
                } catch (IOException failure) {
                    // A certificate rejection can abort TLS 1.3 with an alert, EOF or broken pipe.
                    // Accept this only during the handshake and require CertificateException on the client below.
                    if (permitted || !tlsStarted.get() || tlsCompleted.get()) throw new RuntimeException(failure);
                } catch (Exception failure) {
                    throw new RuntimeException(failure);
                }
            });
            try (LdapNetworkConnection connection = new LdapNetworkConnection(configuration(mode, host, listener.getLocalPort(), insecure))) {
                if (permitted) {
                    Assert.assertTrue(connection.connect());
                    connection.bind("cn=synthetic", "synthetic-only");
                } else {
                    Exception rejection = Assert.expectThrows(Exception.class, () -> {
                        connection.connect();
                        connection.bind("cn=synthetic", "synthetic-only");
                    });
                    Assert.assertTrue(hasCertificateFailure(rejection),
                            "Expected certificate validation to reject the endpoint: " + rejection);
                }
            }
            server.get(10, TimeUnit.SECONDS);
            Assert.assertTrue(tlsStarted.get(), "The test server must reach the TLS handshake");
            Assert.assertEquals(binds.get(), permitted ? 1 : 0, "No bind may reach a mismatched TLS endpoint");
        } finally {
            executor.shutdownNow();
        }
    }

    private static boolean hasCertificateFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof CertificateException) return true;
        }
        return false;
    }

    @Test
    public void retainsPlainLdapMode() throws Exception {
        LdapConnectionConfig configuration = configuration("none", "127.0.0.1", 389, false);
        Assert.assertFalse(configuration.isUseSsl());
        Assert.assertFalse(configuration.isUseTls());
    }

    @Test
    public void refusesStartTlsWithoutSendingPlaintextBind() throws Exception {
        AtomicInteger plaintextBinds = new AtomicInteger();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            listener.setSoTimeout(5000);
            Future<?> server = executor.submit(() -> {
                try (Socket raw = listener.accept()) {
                    raw.setSoTimeout(5000);
                    byte[] request = message(raw.getInputStream());
                    Assert.assertTrue(new String(request, StandardCharsets.ISO_8859_1).contains("1.3.6.1.4.1.1466.20037"));
                    respond(raw.getOutputStream(), request, 0x78, 52);
                    int first = raw.getInputStream().read();
                    if (first != -1) {
                        InputStream remaining = new java.io.SequenceInputStream(
                                new java.io.ByteArrayInputStream(new byte[] {(byte) first}), raw.getInputStream());
                        byte[] next = message(remaining);
                        if ((next[2 + (next[1] & 0xff)] & 0xff) == 0x60) plaintextBinds.incrementAndGet();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            try (LdapNetworkConnection connection = new LdapNetworkConnection(
                    configuration("starttls", "127.0.0.1", listener.getLocalPort(), false))) {
                Assert.expectThrows(Exception.class, () -> {
                    connection.connect();
                    connection.bind("cn=synthetic", "synthetic-only");
                });
            }
            server.get(10, TimeUnit.SECONDS);
            Assert.assertEquals(plaintextBinds.get(), 0);
        } finally {
            executor.shutdownNow();
        }
    }

    private static byte[] message(InputStream input) throws Exception {
        Assert.assertEquals(input.read(), 0x30);
        int length = input.read();
        if ((length & 0x80) != 0) {
            int count = length & 0x7f;
            Assert.assertTrue(count > 0 && count <= 2);
            length = 0;
            for (int n = 0; n < count; n++) length = (length << 8) | input.read();
        }
        Assert.assertTrue(length > 0 && length < 2048);
        byte[] body = input.readNBytes(length);
        Assert.assertEquals(body.length, length);
        Assert.assertEquals(body[0], 0x02);
        return body;
    }

    private static void respond(OutputStream stream, byte[] request, int operation) throws Exception {
        respond(stream, request, operation, 0);
    }

    private static void respond(OutputStream stream, byte[] request, int operation, int result) throws Exception {
        int idSize = request[1] & 0xff;
        Assert.assertTrue(idSize > 0 && idSize <= 4);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(Arrays.copyOf(request, 2 + idSize));
        body.write(new byte[] {(byte) operation, 7, 10, 1, (byte) result, 4, 0, 4, 0});
        stream.write(0x30);
        stream.write(body.size());
        body.writeTo(stream);
        stream.flush();
    }
}
