import re  # Regular-expression support; currently unused but kept if log parsing grows more complex.
import pandas as pd  # Pandas is used to build model input tables.
import joblib  # Joblib loads the saved scikit-learn model and scaler from disk.

# Path to the trained random-forest model file used by detect_threat().
MODEL_PATH = "threat_app/ml/rf_model.pkl"

# Exact feature order expected by the trained classifier.
FEATURE_COLUMNS = ["protocol", "packet_size"]

# Load the main model once when the module is imported.
model = joblib.load("threat_app/ml/rf_model.pkl")

# Load the scaler once so packet_size can be transformed before prediction.
scaler = joblib.load("threat_app/ml/scaler.pkl")


def parse_log(raw_log):
    """Parse one CSV-style log string into a dictionary with typed values."""
    parts = raw_log.strip().split(",")  # Remove outer spaces and split the log by commas.

    if len(parts) != 4:  # The code expects exactly 4 fields in the input string.
        raise ValueError("Expected 4 values: src_ip,dst_ip,protocol,packet_size")  # Stop early if the log format is wrong.

    return {  # Convert the string fields into a normalized dictionary.
        "source_ip": parts[0].strip(),  # Source IP remains a cleaned string.
        "destination_ip": parts[1].strip(),  # Destination IP remains a cleaned string.
        "protocol": int(parts[2].strip()),  # Protocol is converted to an integer.
        "packet_size": float(parts[3].strip())  # Packet size is converted to a float.
    }


def preprocess_log(parsed):
    """Convert parsed log data into the numeric DataFrame used by the model."""
    print("Preprocessing log...")  # Basic console trace to show preprocessing started.
    steps = []  # Collect human-readable preprocessing steps for debugging or UI display.

    df = pd.DataFrame([parsed])  # Wrap the single parsed record into a one-row DataFrame.

    steps.append("Converted input to DataFrame")  # Record the first preprocessing step.

    df = df.drop(columns=["source_ip", "destination_ip"], errors="ignore")  # Remove IP text fields because the model uses numeric features only.
    steps.append("Dropped IP address columns")  # Record that the non-numeric columns were removed.

    df = df.apply(pd.to_numeric, errors="coerce")  # Convert remaining columns to numeric and turn bad values into NaN.
    steps.append("Converted features to numeric")  # Record the numeric conversion step.

    df = df.fillna(0)  # Replace missing values so the model always gets valid numeric input.
    steps.append("Handled missing values")  # Record the missing-value cleanup step.

    return df, steps  # Return both the processed features and the trace of what happened.


def detect_threat(feature_df):
    """Predict whether the prepared feature row represents normal traffic or an attack."""
    model = joblib.load(MODEL_PATH)  # Load the saved model again using the configured model path.

    prediction = model.predict(feature_df)[0]  # Run inference and take the first prediction from the result array.

    if prediction == 1:  # In this model, label 1 means an attack was detected.
        return True, "Attack"  # Return both a boolean flag and a human-readable label.
    else:  # Any other label is treated as non-malicious traffic.
        return False, "Normal"  # Return the negative result in the same two-value format.


def predict_from_text(csv_text):
    """Predict directly from a raw CSV text row without calling parse_log()."""
    parts = csv_text.split(",")  # Split the incoming CSV text into individual values.

    df = pd.DataFrame([{  # Build a one-row DataFrame with only the model features.
        "protocol": int(parts[2]),  # Extract protocol from the third CSV value.
        "packet_size": float(parts[3])  # Extract packet size from the fourth CSV value.
    }])

    df["packet_size"] = scaler.transform(df[["packet_size"]])  # Apply the saved scaler so packet size matches training-time scaling.

    df = df.reindex(columns=FEATURE_COLUMNS)  # Force the feature columns into the exact order expected by the model.

    pred = model.predict(df)[0]  # Run prediction on the prepared DataFrame and take the single result.
    return "Attack" if pred == 1 else "Normal"  # Convert the numeric class into a readable label.


def predict_from_features(features):
    """Predict when the caller already has the numeric feature values prepared."""
    import numpy as np  # NumPy is used here to reshape the raw feature list into model input format.

    X = np.array(features).reshape(1, -1)  # Convert the feature list into a 2D array with one sample.
    prediction = model.predict(X)[0]  # Run the model and extract the first prediction.
    return "Attack" if prediction == 1 else "Normal"  # Return a readable classification label.
