from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
import shap

from risk.risk_engine import analyze_risk


# ============================================================
# PATHS
# ============================================================

MODEL_FILE = Path(
    "models/lightgbm/baseline_model.pkl"
)

FEATURE_NAMES_FILE = Path(
    "models/lightgbm/feature_names.json"
)

CLASS_NAMES_FILE = Path(
    "models/lightgbm/label_encoder.pkl"
)


# ============================================================
# THREAT PROFILER
# ============================================================

class ThreatProfiler:
    """
    Complete threat profiling pipeline.

    Combines:

    1. LightGBM behavior classification
    2. Observed behavior information
    3. SHAP explanations
    4. Existing deterministic risk engine

    The risk engine remains responsible for calculating:

        risk score
        risk state
        risk reasons
    """

    def __init__(
        self,
        model_file=MODEL_FILE,
        feature_names_file=FEATURE_NAMES_FILE,
        class_names_file=CLASS_NAMES_FILE,
    ):

        # ----------------------------------------------------
        # Load model
        # ----------------------------------------------------

        self.model = joblib.load(
            model_file
        )

        # ----------------------------------------------------
        # Load feature names
        # ----------------------------------------------------

        with open(
            feature_names_file,
            "r",
            encoding="utf-8",
        ) as f:

            self.feature_names = json.load(f)

        # ----------------------------------------------------
        # Load label encoder
        # ----------------------------------------------------

        self.label_encoder = joblib.load(
            class_names_file
        )

        # ----------------------------------------------------
        # SHAP explainer
        # ----------------------------------------------------

        self.explainer = shap.TreeExplainer(
            self.model
        )

        # ----------------------------------------------------
        # Class names
        # ----------------------------------------------------

        self.class_names = [
            str(name)
            for name in self.label_encoder.classes_
        ]

        print(
            f"ThreatProfiler loaded: "
            f"{len(self.feature_names)} features, "
            f"{len(self.class_names)} classes"
        )

    # ========================================================
    # FEATURE VECTOR
    # ========================================================

    def _build_feature_vector(
        self,
        features,
    ):
        """
        Build a pandas DataFrame using the exact feature
        ordering used during LightGBM training.
        """

        missing = [
            feature
            for feature in self.feature_names
            if feature not in features
        ]

        if missing:

            raise ValueError(
                "Missing required features: "
                + ", ".join(missing)
            )

        values = [
            features[feature]
            for feature in self.feature_names
        ]

        X = pd.DataFrame(
            [values],
            columns=self.feature_names,
        )

        if X.isnull().any().any():

            raise ValueError(
                "Feature vector contains NaN values."
            )

        if not np.isfinite(
            X.to_numpy(dtype=float)
        ).all():

            raise ValueError(
                "Feature vector contains "
                "infinite values."
            )

        return X

    # ========================================================
    # SHAP VALUES
    # ========================================================

    def _calculate_shap(
        self,
        X,
        predicted_index,
    ):
        """
        Calculate SHAP values for the predicted class.
        """

        shap_values = self.explainer.shap_values(
            X
        )

        # Older SHAP versions:
        #
        # list[class] -> samples x features
        #
        # Newer SHAP versions:
        #
        # samples x features x classes

        if isinstance(
            shap_values,
            list,
        ):

            class_values = np.asarray(
                shap_values[predicted_index]
            )[0]

        else:

            shap_array = np.asarray(
                shap_values
            )

            if shap_array.ndim == 3:

                class_values = shap_array[
                    0,
                    :,
                    predicted_index,
                ]

            elif shap_array.ndim == 2:

                class_values = shap_array[0]

            else:

                raise ValueError(
                    "Unexpected SHAP shape: "
                    f"{shap_array.shape}"
                )

        return class_values

    # ========================================================
    # PROFILE SESSION
    # ========================================================

    def profile_session(
        self,
        session_id,
        features,
        observed_behaviors=None,
        behavior_counts=None,
        authentication=None,
    ):
        """
        Generate a complete threat profile.

        Parameters
        ----------
        session_id:
            Cowrie/session identifier.

        features:
            Dictionary containing the 30 ML features.

        observed_behaviors:
            Behaviors independently detected by the
            behavior analyzer.

        behavior_counts:
            Counts produced by the behavior analyzer.

        authentication:
            Authentication information from the session.

        Returns
        -------
        dict
            Complete threat profile containing:

            - LightGBM prediction
            - prediction probabilities
            - SHAP explanations
            - observed behaviors
            - risk score
            - risk state
            - risk reasons
        """

        if observed_behaviors is None:
            observed_behaviors = []

        if behavior_counts is None:
            behavior_counts = {}

        if authentication is None:
            authentication = {}

        # ----------------------------------------------------
        # Build feature vector
        # ----------------------------------------------------

        X = self._build_feature_vector(
            features
        )

        # ----------------------------------------------------
        # LightGBM prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            X
        )

        predicted_raw = prediction[0]

        # ----------------------------------------------------
        # Convert prediction to class name
        # ----------------------------------------------------

        if isinstance(
            predicted_raw,
            (int, np.integer),
        ):

            predicted_index = int(
                predicted_raw
            )

            if (
                predicted_index < 0
                or predicted_index >= len(
                    self.class_names
                )
            ):

                raise ValueError(
                    f"Invalid predicted class index: "
                    f"{predicted_index}"
                )

            predicted_class = (
                self.class_names[
                    predicted_index
                ]
            )

        else:

            predicted_class = str(
                predicted_raw
            )

            if predicted_class in self.class_names:

                predicted_index = (
                    self.class_names.index(
                        predicted_class
                    )
                )

            else:

                raise ValueError(
                    f"Unknown predicted class: "
                    f"{predicted_class}"
                )

        # ----------------------------------------------------
        # Prediction probabilities
        # ----------------------------------------------------

        probabilities = self.model.predict_proba(
            X
        )[0]

        probability_map = {}

        for index, probability in enumerate(
            probabilities
        ):

            if index < len(
                self.class_names
            ):

                probability_map[
                    self.class_names[index]
                ] = float(probability)

        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        shap_values = self._calculate_shap(
            X,
            predicted_index,
        )

        shap_rows = []

        for feature, value in zip(
            self.feature_names,
            shap_values,
        ):

            shap_rows.append(
                {
                    "feature": feature,
                    "shap_value": float(value),
                    "absolute_shap": float(
                        abs(value)
                    ),
                }
            )

        shap_rows.sort(
            key=lambda row: row["absolute_shap"],
            reverse=True,
        )

        top_explanations = shap_rows[:10]

        # ----------------------------------------------------
        # EXISTING RISK ENGINE
        # ----------------------------------------------------

        risk_input = {
            "session_id": session_id,

            "behaviors": list(
                observed_behaviors
            ),

            "behavior_counts": dict(
                behavior_counts
            ),

            "authentication": dict(
                authentication
            ),
        }

        risk_result = analyze_risk(
            risk_input
        )

        risk = risk_result["risk"]

        # ----------------------------------------------------
        # Complete threat profile
        # ----------------------------------------------------

        profile = {

            "session_id": session_id,

            # ----------------------------------------------
            # ML classification
            # ----------------------------------------------

            "predicted_class": predicted_class,

            "prediction_confidence": float(
                probabilities[predicted_index]
            ),

            "class_probabilities": probability_map,

            # ----------------------------------------------
            # Observed behavior
            # ----------------------------------------------

            "observed_behaviors": list(
                observed_behaviors
            ),

            "behavior_counts": dict(
                behavior_counts
            ),

            # ----------------------------------------------
            # Explainability
            # ----------------------------------------------

            "top_shap_features": (
                top_explanations
            ),

            # ----------------------------------------------
            # Risk assessment
            # ----------------------------------------------

            "risk": {

                "score": risk["score"],

                "state": risk["state"],

                "behavior_score": (
                    risk["behavior_score"]
                ),

                "progression_score": (
                    risk["progression_score"]
                ),

                "authentication_score": (
                    risk["authentication_score"]
                ),

                "reasons": list(
                    risk["reasons"]
                ),
            },
        }

        return profile


# ============================================================
# TEST
# ============================================================

def main():

    print("=" * 70)
    print("THREAT PROFILER + RISK ENGINE TEST")
    print("=" * 70)

    profiler = ThreatProfiler()

    # --------------------------------------------------------
    # Load one analyzed/risk-compatible session
    # --------------------------------------------------------

    dataset_file = Path(
        "data/generated/ml_training_dataset.jsonl"
    )

    if not dataset_file.exists():

        raise FileNotFoundError(
            f"Dataset not found: {dataset_file}"
        )

    with dataset_file.open(
        "r",
        encoding="utf-8",
    ) as f:

        record = json.loads(
            f.readline()
        )

    # --------------------------------------------------------
    # Test data
    #
    # The ML training dataset contains the ML features.
    # Behavior information may not be present in the
    # training record, so use empty behavior data here.
    #
    # The integration itself accepts real analyzer output.
    # --------------------------------------------------------

    profile = profiler.profile_session(

        session_id=record[
            "session_id"
        ],

        features=record[
            "features"
        ],

        observed_behaviors=record.get(
            "expected_behaviors",
            [],
        ),

        behavior_counts={},

        authentication={},
    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print()
    print("SESSION PROFILE")
    print("-" * 70)

    print(
        f"Session ID          : "
        f"{profile['session_id']}"
    )

    print(
        f"Predicted class     : "
        f"{profile['predicted_class']}"
    )

    print(
        f"Confidence          : "
        f"{profile['prediction_confidence']:.4f}"
    )

    print()
    print("Observed behaviors:")

    for behavior in profile[
        "observed_behaviors"
    ]:

        print(
            f"  - {behavior}"
        )

    print()
    print("Risk assessment:")

    risk = profile["risk"]

    print(
        f"  Score              : "
        f"{risk['score']}"
    )

    print(
        f"  State              : "
        f"{risk['state']}"
    )

    print(
        f"  Behavior score     : "
        f"{risk['behavior_score']}"
    )

    print(
        f"  Progression score  : "
        f"{risk['progression_score']}"
    )

    print(
        f"  Authentication     : "
        f"{risk['authentication_score']}"
    )

    print()
    print("Risk reasons:")

    for reason in risk[
        "reasons"
    ]:

        print(
            f"  - {reason}"
        )

    print()
    print("Top SHAP explanations:")

    for item in profile[
        "top_shap_features"
    ]:

        print(
            f"  {item['feature']:<35} "
            f"{item['shap_value']:+.6f}"
        )

    print()
    print("=" * 70)
    print("THREAT PROFILER + RISK ENGINE TEST COMPLETE")
    print("=" * 70)

    print()
    print(
        json.dumps(
            profile,
            indent=2,
        )
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()