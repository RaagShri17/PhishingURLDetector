/**
 * Prediction
 * ----------
 * Packages the full analysis result: the rule-based score, the ML
 * probability, and the final combined verdict. Can serialize to JSON
 * for easy printing/logging.
 */
public class Prediction {

    private final String url;
    private final int ruleScore;
    private final int threshold;
    private final double mlProbability; // -1 if ML model unavailable
    private final boolean phishing;
    private final FeatureExtractor features;

    public Prediction(String url, URLAnalyzer analyzer, double mlProbability) {
        this.url = url;
        this.ruleScore = analyzer.getScore();
        this.threshold = URLAnalyzer.THRESHOLD;
        this.mlProbability = mlProbability;
        this.features = analyzer.getFeatures();

        boolean ruleSaysPhishing = analyzer.isPhishing();
        boolean mlSaysPhishing = mlProbability >= 0 && mlProbability > 0.5;
        this.phishing = ruleSaysPhishing || mlSaysPhishing;
    }

    public boolean isPhishing() {
        return phishing;
    }

    public int getRuleScore() {
        return ruleScore;
    }

    public double getMlProbability() {
        return mlProbability;
    }

    public FeatureExtractor getFeatures() {
        return features;
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"url\":\"").append(escape(url)).append("\",");
        sb.append("\"ruleScore\":").append(ruleScore).append(",");
        sb.append("\"threshold\":").append(threshold).append(",");
        sb.append("\"mlProbability\":").append(mlProbability).append(",");
        sb.append("\"label\":\"").append(phishing ? "PHISHING" : "LEGITIMATE").append("\",");

        sb.append("\"features\":{");
        String[] names = FeatureExtractor.featureNames();
        double[] values = features.toArray();
        for (int i = 0; i < names.length; i++) {
            sb.append("\"").append(names[i]).append("\":").append(values[i]);
            if (i < names.length - 1) sb.append(",");
        }
        sb.append("}");
        sb.append("}");
        return sb.toString();
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}