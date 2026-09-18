import javax.swing.*;
import java.awt.*;

public class GUI extends JFrame {

    private static final String DATASET_PATH = "../dataset/phishing_urls.csv";

    private final JTextField urlField;
    private final JLabel verdictLabel;
    private final JLabel ruleScoreLabel;
    private final JLabel mlScoreLabel;
    private final JTextArea featuresArea;
    private final MLClassifier classifier;

    public GUI() {
        setTitle("Phishing URL Detector");
        setSize(560, 480);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        classifier = new MLClassifier(DATASET_PATH);

        // ---- Top: input ----
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        topPanel.add(new JLabel("Enter URL:"), BorderLayout.WEST);
        urlField = new JTextField();
        topPanel.add(urlField, BorderLayout.CENTER);
        JButton checkButton = new JButton("Check URL");
        topPanel.add(checkButton, BorderLayout.EAST);
        add(topPanel, BorderLayout.NORTH);

        // ---- Center: verdict + scores + features ----
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));

        verdictLabel = new JLabel("Enter a URL and click Check URL");
        verdictLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        verdictLabel.setHorizontalAlignment(JLabel.CENTER);
        verdictLabel.setOpaque(true);
        verdictLabel.setBorder(BorderFactory.createEmptyBorder(12, 0, 12, 0));

        ruleScoreLabel = new JLabel("Rule-based score: -");
        mlScoreLabel = new JLabel("ML probability (phishing): -"
                + (classifier.isTrained() ? "" : "  [ML model unavailable - check dataset path]"));

        JPanel scorePanel = new JPanel(new GridLayout(2, 1));
        scorePanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));
        scorePanel.add(ruleScoreLabel);
        scorePanel.add(mlScoreLabel);

        featuresArea = new JTextArea();
        featuresArea.setEditable(false);
        featuresArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(featuresArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Extracted Features"));

        centerPanel.add(verdictLabel);
        centerPanel.add(scorePanel);
        centerPanel.add(scrollPane);

        add(centerPanel, BorderLayout.CENTER);

        checkButton.addActionListener(e -> analyze());
        urlField.addActionListener(e -> analyze());
    }

    private void analyze() {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            verdictLabel.setText("Please enter a URL first.");
            return;
        }

        URLAnalyzer analyzer = new URLAnalyzer(url);
        double mlProb = classifier.isTrained()
                ? classifier.predictProbability(analyzer.getFeatures().toArray())
                : -1;

        Prediction prediction = new Prediction(url, analyzer, mlProb);

        boolean phishing = prediction.isPhishing();
        verdictLabel.setText(phishing ? "⚠ PHISHING" : "✅ LEGITIMATE");
        verdictLabel.setBackground(phishing ? new Color(220, 38, 38) : new Color(22, 163, 74));
        verdictLabel.setForeground(Color.WHITE);

        ruleScoreLabel.setText("Rule-based score: " + prediction.getRuleScore()
                + " (threshold = " + URLAnalyzer.THRESHOLD + ")");

        if (mlProb >= 0) {
            mlScoreLabel.setText(String.format("ML probability (phishing): %.1f%%", mlProb * 100));
        } else {
            mlScoreLabel.setText("ML probability (phishing): model unavailable");
        }

        StringBuilder sb = new StringBuilder();
        String[] names = FeatureExtractor.featureNames();
        double[] values = prediction.getFeatures().toArray();
        for (int i = 0; i < names.length; i++) {
            sb.append(String.format("%-24s %s%n", names[i], values[i]));
        }
        featuresArea.setText(sb.toString());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new GUI().setVisible(true));
    }
}