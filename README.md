# Phishing URL Detector (100% Java)

A hybrid phishing URL detector — rule-based scoring **and** a hand-rolled
Logistic Regression ML model — written entirely in Java. No Python, no
external ML libraries, no pickle files. The ML model trains itself in a
fraction of a second, in-process, every time you run the app, straight from
the CSV dataset.

## Workflow

```
Enter URL
   ↓
Check URL features          <- FeatureExtractor.java
   ↓
Calculate suspicious score  <- URLAnalyzer.java
   ↓
ML classification           <- MLClassifier.java (trained from dataset/phishing_urls.csv)
   ↓
If rule score > threshold OR ML probability > 50%
   ↓
PHISHING          else          LEGITIMATE
```

## Project structure

```
PhishingURLDetector/
│
├── src/
│   ├── Main.java              <- CLI entry point (prints JSON result)
│   ├── URLAnalyzer.java       <- rule-based scoring
│   ├── FeatureExtractor.java  <- feature extraction from a URL
│   ├── MLClassifier.java      <- pure-Java logistic regression (trains from CSV)
│   ├── Prediction.java        <- combines rule score + ML probability -> verdict
│   └── GUI.java                <- interactive Swing GUI
│
├── dataset/
│   └── phishing_urls.csv      <- training data (url,label) - expand this for accuracy
│
└── README.md
```

---

## Step-by-step setup in VS Code

### 0. Prerequisites
- **JDK 17+** (Java Development Kit, not just JRE). Check with:
  ```
  javac -version
  ```
  If missing, install from https://adoptium.net/ (Temurin JDK).
- VS Code extension: **"Extension Pack for Java"** (by Microsoft).

### 1. Open the project
`File → Open Folder…` → select the `PhishingURLDetector` folder in VS Code.

### 2. Compile
Open a terminal in VS Code (`` Ctrl+` ``):

```bash
cd src
javac *.java
```

This produces `.class` files for every class. No errors should appear.

### 3. Run the GUI

```bash
java -cp . GUI
```

A window opens. On startup it silently trains the ML model from
`../dataset/phishing_urls.csv` (this happens in well under a second). Then:

1. Type/paste a URL into the input box.
2. Click **Check URL** (or press Enter).
3. See:
   - A big **PHISHING** (red) or **LEGITIMATE** (green) verdict banner.
   - The rule-based score vs. threshold.
   - The ML model's phishing probability (%).
   - A full breakdown of every extracted feature.

### 4. (Optional) Run from the command line instead of the GUI

```bash
java -cp . Main "http://192.168.1.5/login/verify-account"
```

Output (single line of JSON):
```json
{"url":"...","ruleScore":9,"threshold":5,"mlProbability":0.94,"label":"PHISHING","features":{...}}
```

### 5. Running from VS Code's Run button
Open `src/GUI.java` and click the ▶ "Run" button the Java extension shows
above `public static void main(...)`. (For `Main.java` you'll need to supply
the URL as a program argument via `Run → Add Configuration` or just use the
terminal command above — it's simpler.)

---

## How the rule-based score works

`URLAnalyzer.java` adds points for each suspicious signal `FeatureExtractor.java` finds:

| Signal                              | Points |
|--------------------------------------|--------|
| Raw IP address instead of domain     | +3     |
| '@' symbol in URL                    | +3     |
| Contains login/verify/bank/etc.      | +3     |
| URL length > 75 chars                | +2     |
| More than 2 subdomains               | +2     |
| No HTTPS                             | +2     |
| Known URL shortener                  | +2     |
| "//" redirect trick                  | +2     |
| More than 4 dots                     | +1     |
| More than 2 hyphens                  | +1     |
| More than 5 digits                   | +1     |
| Non-standard port specified          | +1     |

**Threshold = 5.** Score > 5 → rule-based verdict is `PHISHING`. Tune this via
the `THRESHOLD` constant in `URLAnalyzer.java`.

## How the ML classification works

`MLClassifier.java`:
1. Reads every row of `dataset/phishing_urls.csv`.
2. Runs each URL through `FeatureExtractor` to get the same 12 numeric features
   used by the rule-based scorer.
3. Standardizes the features (mean 0, std 1).
4. Trains a Logistic Regression model with plain gradient descent
   (2000 epochs, learning rate 0.1 — both tunable constants in the class).
5. Exposes `predictProbability(double[] features)`, which returns P(phishing)
   for any new URL.

`Prediction.java` combines both signals: the final verdict is `PHISHING` if
**either** the rule-based score exceeds the threshold **or** the ML model is
more than 50% confident.

## Extending this project
- Add more rows to `dataset/phishing_urls.csv` (the sample set is only ~40
  rows — a real detector needs hundreds/thousands of labeled examples) and
  just re-run the program; it retrains automatically on every launch.
- Add more features to `FeatureExtractor.java` (e.g. TLD checks, path depth,
  presence of "https" in the path but not the scheme).
- Increase `EPOCHS` or tune `LEARNING_RATE` in `MLClassifier.java` if you add
  a much larger dataset and want to experiment with convergence.
- Package into a runnable `.jar`:
  ```bash
  cd src
  jar cfe PhishingDetector.jar GUI *.class
  java -jar PhishingDetector.jar
  ```
  (Note: if you jar it up, ship the `dataset/` folder alongside the jar, or
  adjust `DATASET_PATH` in `Main.java`/`GUI.java` to an absolute/relative
  path that matches where you'll run it from.)
