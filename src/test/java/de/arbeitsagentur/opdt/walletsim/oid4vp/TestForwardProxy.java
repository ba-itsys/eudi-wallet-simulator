package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal in-JVM HTTP forward proxy. It reads the absolute request URI a proxied client sends,
 * forwards the request to that origin and relays the answer back, recording every request line so
 * a test can tell which calls took this route.
 */
public final class TestForwardProxy implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final ExecutorService connections = Executors.newVirtualThreadPerTaskExecutor();
    private final List<String> requestLines = new CopyOnWriteArrayList<>();

    public TestForwardProxy() throws IOException {
        this.serverSocket = new ServerSocket();
        serverSocket.bind(new InetSocketAddress("localhost", 0));
        connections.submit(this::acceptConnections);
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    // the request lines as a proxied client sends them, so in absolute form: GET http://host/x HTTP/1.1
    public List<String> requestLines() {
        return List.copyOf(requestLines);
    }

    private void acceptConnections() {
        while (!serverSocket.isClosed()) {
            try {
                Socket client = serverSocket.accept();
                connections.submit(() -> relay(client));
            } catch (IOException e) {
                return;
            }
        }
    }

    private void relay(Socket client) {
        try (client;
                InputStream fromClient = new BufferedInputStream(client.getInputStream())) {
            String requestLine = readLine(fromClient);
            if (requestLine == null) {
                return;
            }
            requestLines.add(requestLine);
            String[] parts = requestLine.split(" ");
            if ("CONNECT".equals(parts[0])) {
                throw new IllegalStateException("This proxy relays plain HTTP only");
            }
            URI target = URI.create(parts[1]);
            List<String> headers = readHeaders(fromClient);
            byte[] body = readBody(fromClient, headers);
            try (Socket origin = new Socket(target.getHost(), target.getPort() == -1 ? 80 : target.getPort())) {
                forwardRequest(origin.getOutputStream(), parts[0], target, headers, body);
                origin.getInputStream().transferTo(client.getOutputStream());
                client.getOutputStream().flush();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // the origin server gets the request in origin form, and closes the connection so that the
    // proxied client opens a new one for its next request instead of reusing this relay
    private void forwardRequest(OutputStream toOrigin, String method, URI target, List<String> headers, byte[] body)
            throws IOException {
        StringBuilder request = new StringBuilder(method + " " + originForm(target) + " HTTP/1.1\r\n");
        headers.stream().filter(header -> !isConnectionHeader(header)).forEach(header -> request.append(header)
                .append("\r\n"));
        request.append("Connection: close\r\n\r\n");
        toOrigin.write(request.toString().getBytes(StandardCharsets.UTF_8));
        toOrigin.write(body);
        toOrigin.flush();
    }

    private static String originForm(URI target) {
        String path = target.getRawPath() == null || target.getRawPath().isEmpty() ? "/" : target.getRawPath();
        return target.getRawQuery() == null ? path : path + "?" + target.getRawQuery();
    }

    private static boolean isConnectionHeader(String header) {
        String name = header.toLowerCase(Locale.ROOT);
        return name.startsWith("connection:") || name.startsWith("proxy-connection:");
    }

    private static List<String> readHeaders(InputStream in) throws IOException {
        List<String> headers = new ArrayList<>();
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            headers.add(line);
        }
        return headers;
    }

    private static byte[] readBody(InputStream in, List<String> headers) throws IOException {
        if (headers.stream().anyMatch(header -> header.toLowerCase(Locale.ROOT).startsWith("transfer-encoding:"))) {
            throw new IllegalStateException("This proxy relays requests with a content length only");
        }
        int length = headers.stream()
                .filter(header -> header.toLowerCase(Locale.ROOT).startsWith("content-length:"))
                .mapToInt(header -> Integer.parseInt(
                        header.substring(header.indexOf(':') + 1).trim()))
                .findFirst()
                .orElse(0);
        return in.readNBytes(length);
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int read;
        while ((read = in.read()) != -1) {
            if (read == '\n') {
                String text = line.toString(StandardCharsets.UTF_8);
                return text.endsWith("\r") ? text.substring(0, text.length() - 1) : text;
            }
            line.write(read);
        }
        return line.size() == 0 ? null : line.toString(StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        connections.shutdownNow();
    }
}
