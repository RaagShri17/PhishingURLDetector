public class Main {

    private static final String DATASET_PATH = "../dataset/phishing_urls.csv";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java Main <url>");
            System.exit(1);
        }

        String url = args[0];

        URLAnalyzer analyzer = new URLAnalyzer(url);

        MLClassifier classifier = new MLClassifier(DATASET_PATH);
        double mlProb = classifier.isTrained()
                ? classifier.predictProbability(analyzer.getFeatures().toArray())
                : -1;

        Prediction prediction = new Prediction(url, analyzer, mlProb);
        System.out.println(prediction.toJson());
    }
}