package ua.nanit.limbo.proxy;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ua.nanit.limbo.server.Log;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class GeoIPService {
    private static volatile String isp = "Unknown";

    public static void fetchISP() {
        new Thread(() -> {
            try {
                HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.ip.sb/geoip"))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                String countryCode = json.has("country_code") ? json.get("country_code").getAsString() : "XX";
                String ispName = json.has("isp") ? json.get("isp").getAsString().replace(" ", "_") : "Unknown";
                isp = countryCode + "-" + ispName;
                Log.info("[WSProxy] ISP detected: %s", isp);
            } catch (Exception e) {
                Log.warning("[WSProxy] Failed to fetch ISP: %s", e.getMessage());
                isp = "Unknown";
            }
        }, "WSProxy-GeoIP").start();
    }

    public static String getISP() {
        return isp;
    }
}
