package ua.nanit.limbo.proxy;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public class ProxyConfig {
    private final boolean enabled;
    private final String uuid;
    private final String domain;
    private final String wsPath;
    private final String subPath;
    private final String name;
    private final int port;

    public ProxyConfig(SocketAddress serverAddress) {
        this.enabled = Boolean.parseBoolean(env("WS_ENABLED", "true"));
        this.uuid = env("WS_UUID", "b64c9a01-3f09-4dea-a0f1-dc85e5a3ac19");
        this.domain = env("WS_DOMAIN", "www.abc123.com");
        String path = env("WS_PATH", "");
        this.wsPath = path.isEmpty() && !uuid.isEmpty() ?
            URLEncoder.encode("api/v1/user?token=" + uuid.substring(0, Math.min(8, uuid.length())) + "&lang=en", StandardCharsets.UTF_8) : path;
        this.subPath = env("WS_SUB_PATH", "dc85e5a3ac19/sub");
        this.name = env("WS_NAME", "limbo");
        this.port = resolvePort(serverAddress);
    }

    private static int resolvePort(SocketAddress serverAddress) {
        // 1. 优先从环境变量读取
        String envPort = System.getenv("PORT");
        if (envPort != null && !envPort.isEmpty()) {
            try {
                return Integer.parseInt(envPort);
            } catch (NumberFormatException ignored) {}
        }

        // 2. 从server.properties读取
        File serverProps = new File("server.properties");
        if (serverProps.exists()) {
            try (FileInputStream fis = new FileInputStream(serverProps)) {
                Properties props = new Properties();
                props.load(fis);
                String portStr = props.getProperty("server-port");
                if (portStr != null && !portStr.isEmpty()) {
                    return Integer.parseInt(portStr);
                }
            } catch (Exception ignored) {}
        }

        // 3. 从SocketAddress获取 (NanoLimbo settings.yml)
        if (serverAddress instanceof InetSocketAddress) {
            int port = ((InetSocketAddress) serverAddress).getPort();
            if (port > 0 && port <= 65535) {
                return port;
            }
        }

        return 25565;
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    public boolean isEnabled() { return enabled; }
    public String getUuid() { return uuid; }
    public String getUuidWithoutDash() { return uuid.replace("-", ""); }
    public String getDomain() { return domain; }
    public String getWsPath() { return wsPath; }
    public String getSubPath() { return subPath; }
    public String getName() { return name; }
    public int getPort() { return port; }
}
