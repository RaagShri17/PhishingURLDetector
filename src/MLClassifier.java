import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * MLClassifier
 * ------------
 * A small, dependency-free Logistic Regression classifier written in plain
 * Java. It trains itself on dataset/phishing_urls.csv (using the SAME
 * features as FeatureExtractor.java) the moment it's constructed, then can
 * predict a phishing probability for any new URL's feature vector.
 *
 * This replaces the old Python/scikit-learn model - everything now runs in
 * one JVM process, no external files or languages needed.
 */
public class MLClassifier {

    private double[] weights;
    private double bias;
    private double[] featureMeans;
    private double[] featureStdDevs;
    private final int numFeatures;
    private boolean trained = false;

    private static final double LEARNING_RATE = 0.1;
    private static final int EPOCHS = 2000;

    public MLClassifier(String csvPath) {
        this.numFeatures = FeatureExtractor.featureNames().length;
        this.weights = new double[numFeatures];
        this.bias = 0.0;

        try {
            List<double[]> X = new ArrayList<>();
            List<Integer> y = new ArrayList<>();
            loadDataset(csvPath, X, y);

            if (X.isEmpty()) {
                System.err.println("MLClassifier: dataset empty or not found at " + csvPath
                        + " - ML scoring disabled.");
                return;
            }

            standardizeAndTrain(X, y);
            trained = true;
        } catch (IOException e) {
            System.err.println("MLClassifier: could not load dataset (" + e.getMessage()
                    + ") - ML scoring disabled.");
        }
    }

    private void loadDataset(String csvPath, List<double[]> X, List<Integer> y) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(csvPath))) {
            String line = br.readLine(); // skip header
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                int lastComma = line.lastIndexOf(',');
                String url = line.substring(0, lastComma).trim();
                int label = Integer.parseInt(line.substring(lastComma + 1).trim());

                FeatureExtractor fe = new FeatureExtractor(url);
                X.add(fe.toArray());
                y.add(label);
            }
        }
    }

    /** Standardizes features (mean 0, std 1) then trains logistic regression via gradient descent. */
    private void standardizeAndTrain(List<double[]> X, List<Integer> y) {
        int n = X.size();
        featureMeans = new double[numFeatures];
        featureStdDevs = new double[numFeatures];

        // Compute mean
        for (double[] row : X) {
            for (int j = 0; j < numFeatures; j++) featureMeans[j] += row[j];
        }
        for (int j = 0; j < numFeatures; j++) featureMeans[j] /= n;

        // Compute std dev
        for (double[] row : X) {
            for (int j = 0; j < numFeatures; j++) {
                double diff = row[j] - featureMeans[j];
                featureStdDevs[j] += diff * diff;
            }
        }
        for (int j = 0; j < numFeatures; j++) {
            featureStdDevs[j] = Math.sqrt(featureStdDevs[j] / n);
            if (featureStdDevs[j] == 0) featureStdDevs[j] = 1; // avoid divide-by-zero
        }

        // Standardize
        double[][] Xs = new double[n][numFeatures];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < numFeatures; j++) {
                Xs[i][j] = (X.get(i)[j] - featureMeans[j]) / featureStdDevs[j];
            }
        }

        // Gradient descent
        for (int epoch = 0; epoch < EPOCHS; epoch++) {
            double[] gradW = new double[numFeatures];
            double gradB = 0.0;

            for (int i = 0; i < n; i++) {
                double z = bias;
                for (int j = 0; j < numFeatures; j++) z += weights[j] * Xs[i][j];
                double pred = sigmoid(z);
                double error = pred - y.get(i);

                for (int j = 0; j < numFeatures; j++) gradW[j] += error * Xs[i][j];
                gradB += error;
            }

            for (int j = 0; j < numFeatures; j++) {
                weights[j] -= LEARNING_RATE * (gradW[j] / n);
            }
            bias -= LEARNING_RATE * (gradB / n);
        }
    }

    private double sigmoid(double z) {
        return 1.0 / (1.0 + Math.exp(-z));
    }

    /** Returns P(phishing) for a raw feature vector (same order as FeatureExtractor.toArray()). */
    public double predictProbability(double[] rawFeatures) {
        if (!trained) return -1; // signals "no model available"

        double z = bias;
        for (int j = 0; j < numFeatures; j++) {
            double standardized = (rawFeatures[j] - featureMeans[j]) / featureStdDevs[j];
            z += weights[j] * standardized;
        }
        return sigmoid(z);
    }

    public boolean isTrained() {
        return trained;
    }
}