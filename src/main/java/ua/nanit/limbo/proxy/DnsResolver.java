package ua.nanit.limbo.proxy;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

public class DnsResolver {
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );
    private static final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    public static CompletableFuture<String> resolve(String host) {
        if (IP_PATTERN.matcher(host).matches()) {
            return CompletableFuture.completedFuture(host);
        }

        return CompletableFuture.supplyAsync(() -> {
            try {
                String url = "https://dns.google/resolve?name=" +
                    URLEncoder.encode(host, StandardCharsets.UTF_8) + "&type=A";
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();

                if (json.has("Status") && json.get("Status").getAsInt() == 0 && json.has("Answer")) {
                    JsonArray answers = json.getAsJsonArray("Answer");
                    for (JsonElement elem : answers) {
                        JsonObject answer = elem.getAsJsonObject();
                        if (answer.get("type").getAsInt() == 1) {
                            return answer.get("data").getAsString();
                        }
                    }
                }
            } catch (Exception ignored) {}
            return host;
        });
    }
}
