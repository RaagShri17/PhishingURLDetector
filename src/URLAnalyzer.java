/**
 * URLAnalyzer
 * -----------
 * Takes extracted features and computes a weighted "suspicious score".
 * This is the rule-based half of the detector (the ML half lives in
 * MLClassifier.java; both are combined together in Prediction.java).
 */
public class URLAnalyzer {

    public static final int THRESHOLD = 5; // score > THRESHOLD => phishing

    private final FeatureExtractor features;
    private int score;

    public URLAnalyzer(String url) {
        this.features = new FeatureExtractor(url);
        this.score = computeScore();
    }

    private int computeScore() {
        int s = 0;

        if (features.usesIP == 1) s += 3;              // raw IP instead of domain name
        if (features.hasAtSymbol == 1) s += 3;          // '@' redirect trick
        if (features.urlLength > 75) s += 2;            // unusually long URL
        if (features.numDots > 4) s += 1;               // excessive dots
        if (features.numHyphens > 2) s += 1;            // excessive hyphens
        if (features.numSubdomains > 2) s += 2;         // deep subdomain nesting
        if (features.hasHttps == 0) s += 2;             // no HTTPS
        if (features.hasSuspiciousWords == 1) s += 3;   // login/verify/bank etc.
        if (features.hasShortener == 1) s += 2;         // known shortener
        if (features.numDigits > 5) s += 1;             // lots of digits
        if (features.hasDoubleSlashRedirect == 1) s += 2; // "//" redirect trick
        if (features.hasPort == 1) s += 1;              // non-standard port

        return s;
    }

    public int getScore() {
        return score;
    }

    public boolean isPhishing() {
        return score > THRESHOLD;
    }

    public FeatureExtractor getFeatures() {
        return features;
    }
}
