import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * FeatureExtractor
 * -----------------
 * Pulls out simple, well-known "phishing signals" from a raw URL string.
 * Each feature is exposed as a public field (0/1 or a raw count) so that
 * both the rule-based scorer (URLAnalyzer) and the ML model (via Prediction)
 * can use the exact same numbers.
 */
public class FeatureExtractor {

    // ---- Extracted features ----
    public int usesIP;              // 1 if host is a raw IP address
    public int hasAtSymbol;         // 1 if '@' present (redirect trick)
    public int urlLength;           // total character length
    public int numDots;             // count of '.' in the URL
    public int numHyphens;          // count of '-' in the URL
    public int numSubdomains;       // number of subdomain levels
    public int hasHttps;            // 1 if scheme is https
    public int hasSuspiciousWords;  // 1 if login/verify/bank/secure etc present
    public int hasShortener;        // 1 if a known URL-shortener domain is used
    public int numDigits;           // count of digits in the URL
    public int hasDoubleSlashRedirect; // 1 if "//" appears after position 7 (redirect trick)
    public int hasPort;             // 1 if a non-standard port is specified

    private static final List<String> SUSPICIOUS_WORDS = Arrays.asList(
            "login", "verify", "update", "secure", "account", "bank",
            "confirm", "signin", "webscr", "password", "ebayisapi", "paypal"
    );

    private static final List<String> SHORTENERS = Arrays.asList(
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
    );

    private static final Pattern IP_PATTERN =
            Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");

    public FeatureExtractor(String rawUrl) {
        String url = rawUrl.trim();
        String host = extractHost(url);

        urlLength = url.length();
        hasAtSymbol = url.contains("@") ? 1 : 0;
        numDots = countChar(url, '.');
        numHyphens = countChar(url, '-');
        hasHttps = url.toLowerCase().startsWith("https://") ? 1 : 0;
        numDigits = countDigits(url);

        Matcher ipMatcher = IP_PATTERN.matcher(host);
        usesIP = ipMatcher.matches() ? 1 : 0;

        numSubdomains = host.isEmpty() ? 0 : Math.max(0, host.split("\\.").length - 2);

        String lower = url.toLowerCase();
        hasSuspiciousWords = SUSPICIOUS_WORDS.stream().anyMatch(lower::contains) ? 1 : 0;
        hasShortener = SHORTENERS.stream().anyMatch(host::contains) ? 1 : 0;

        int schemeEnd = url.indexOf("://");
        String afterScheme = schemeEnd >= 0 ? url.substring(schemeEnd + 3) : url;
        hasDoubleSlashRedirect = afterScheme.contains("//") ? 1 : 0;

        hasPort = host.contains(":") ? 1 : 0;
    }

    private String extractHost(String url) {
        try {
            String withScheme = url.matches("^[a-zA-Z]+://.*") ? url : "http://" + url;
            URI u = URI.create(withScheme);
            String host = u.getHost();
            return host == null ? "" : host.toLowerCase();
        } catch (Exception e) {
            // Fallback naive parsing if URL is malformed
            String s = url.replaceFirst("^[a-zA-Z]+://", "");
            int slash = s.indexOf('/');
            return (slash >= 0 ? s.substring(0, slash) : s).toLowerCase();
        }
    }

    private int countChar(String s, char c) {
        int count = 0;
        for (char ch : s.toCharArray()) if (ch == c) count++;
        return count;
    }

    private int countDigits(String s) {
        int count = 0;
        for (char ch : s.toCharArray()) if (Character.isDigit(ch)) count++;
        return count;
    }

    /** Returns the features as an ordered double array (used for ML + CSV export). */
    public double[] toArray() {
        return new double[]{
                usesIP, hasAtSymbol, urlLength, numDots, numHyphens,
                numSubdomains, hasHttps, hasSuspiciousWords, hasShortener,
                numDigits, hasDoubleSlashRedirect, hasPort
        };
    }

    public static String[] featureNames() {
        return new String[]{
                "usesIP", "hasAtSymbol", "urlLength", "numDots", "numHyphens",
                "numSubdomains", "hasHttps", "hasSuspiciousWords", "hasShortener",
                "numDigits", "hasDoubleSlashRedirect", "hasPort"
        };
    }
}
