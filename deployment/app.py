import pickle
import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score

# ------------------ Load artifacts ------------------
@st.cache_resource
def load_artifacts():
    with open("artifacts/rf_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("artifacts/features.pkl", "rb") as f:
        FEATURES = pickle.load(f)
    return model, FEATURES

model, FEATURES = load_artifacts()

# ------------------ Page config ------------------
st.set_page_config(page_title="SNMP IDS", layout="wide")

# ------------------ Simple styling ------------------
st.markdown("""
<style>
.big-title {font-size: 34px; font-weight: 800; margin-bottom: 0.2rem;}
.subtle {color: #9aa0a6; margin-top: 0;}
.card {
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(255,255,255,0.12);
  background: rgba(255,255,255,0.03);
}
</style>
""", unsafe_allow_html=True)

# ------------------ Header ------------------
st.markdown('<div class="big-title">🛡️ SNMP Enumeration IDS Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="subtle">Random Forest • Flow-based detection • Streamlit deployment</div>', unsafe_allow_html=True)

# ------------------ Sidebar (Advanced options) ------------------
st.sidebar.header("⚙️ Advanced Options")

threshold = st.sidebar.slider(
    "Decision threshold for Attack (P(attack) ≥ threshold)",
    min_value=0.05, max_value=0.95, value=0.50, step=0.05
)

strict_mode = st.sidebar.toggle("Strict IDS mode (catch more attacks)", value=False)
if strict_mode:
    threshold = min(threshold, 0.35)  # stricter (more sensitive) default

show_debug = st.sidebar.toggle("Show debug info", value=False)

st.sidebar.markdown("---")
st.sidebar.subheader("📌 Model Info")
st.sidebar.write(f"Features: {FEATURES}")
st.sidebar.write("Label: 0 = Normal, 1 = Attack")

# ------------------ Tabs ------------------
tab_pred, tab_batch, tab_diag, tab_explain, tab_about = st.tabs(
    ["🔮 Predict", "📦 Batch CSV", "📈 Diagrams", "🧠 Explain", "ℹ️ About"]
)

# =========================================================
# TAB 1: SINGLE PREDICTION
# =========================================================
with tab_pred:
    st.subheader("Single Flow Prediction")

    # Presets
    c1, c2, c3 = st.columns([1,1,1])
    with c1:
        if st.button("✅ Load Normal Example"):
            st.session_state["preset"] = {"srcport": 52000, "dur": 0.05, "sbytes": 142, "sttl": 128.0, "dttl": 128.0}
    with c2:
        if st.button("🚨 Load Attack Example"):
            st.session_state["preset"] = {"srcport": 43000, "dur": 2.5, "sbytes": 180000, "sttl": 64.0, "dttl": 64.0}
    with c3:
        if st.button("🧹 Reset Inputs"):
            st.session_state["preset"] = {"srcport": 40000, "dur": 1.5, "sbytes": 500, "sttl": 64.0, "dttl": 128.0}

    preset = st.session_state.get("preset", {"srcport": 40000, "dur": 1.5, "sbytes": 500, "sttl": 64.0, "dttl": 128.0})

    colA, colB = st.columns([1.1, 1.4])

    with colA:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.write("### Enter Flow Features")

        srcport = st.number_input("srcport", 0, 65535, int(preset["srcport"]))
        dur = st.number_input("dur (seconds)", 0.0, float(preset["dur"]), step=0.01)
        sbytes = st.number_input("sbytes", 0, int(preset["sbytes"]), step=100)
        sttl = st.number_input("sttl", 0.0, 255.0, float(preset["sttl"]), step=1.0)
        dttl = st.number_input("dttl", 0.0, 255.0, float(preset["dttl"]), step=1.0)

        st.caption(f"Using features: {FEATURES}")
        st.markdown('</div>', unsafe_allow_html=True)

    # Build input DF in exact feature order
    input_row = {"srcport": srcport, "dur": dur, "sbytes": sbytes, "sttl": sttl, "dttl": dttl}
    X_in = pd.DataFrame([input_row], columns=FEATURES)

    with colB:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.write("### Result")

        proba = model.predict_proba(X_in)[0]
        p_normal, p_attack = float(proba[0]), float(proba[1])

        pred_by_threshold = 1 if p_attack >= threshold else 0

        # Metrics cards
        m1, m2, m3 = st.columns(3)
        m1.metric("P(Normal)", f"{p_normal:.2f}")
        m2.metric("P(Attack)", f"{p_attack:.2f}")
        m3.metric("Threshold", f"{threshold:.2f}")

        # Show decision
        if pred_by_threshold == 1:
            st.error("🚨 Final Decision: SNMP Attack (Label = 1)")
        else:
            st.success("✅ Final Decision: Normal (Label = 0)")

        # Probability diagram
        fig, ax = plt.subplots()
        ax.bar(["Normal", "Attack"], [p_normal, p_attack])
        ax.set_ylim(0, 1)
        ax.set_ylabel("Probability")
        ax.set_title("Prediction Confidence")
        st.pyplot(fig)

        if show_debug:
            st.write("Raw input:")
            st.dataframe(X_in)

        st.markdown('</div>', unsafe_allow_html=True)

    # Save history
    if "history" not in st.session_state:
        st.session_state["history"] = []

    if st.button("💾 Save this prediction to History"):
        st.session_state["history"].append({
            **input_row,
            "p_normal": p_normal,
            "p_attack": p_attack,
            "threshold": threshold,
            "prediction": pred_by_threshold
        })

    if st.session_state["history"]:
        st.write("### Prediction History")
        st.dataframe(pd.DataFrame(st.session_state["history"]))

# =========================================================
# TAB 2: BATCH CSV PREDICTION
# =========================================================
with tab_batch:
    st.subheader("Batch Prediction (Upload CSV)")

    st.write("Upload a CSV containing the same feature columns used by the model.")
    st.write(f"Required columns: **{FEATURES}**")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded is not None:
        df_up = pd.read_csv(uploaded)

        missing = [c for c in FEATURES if c not in df_up.columns]
        if missing:
            st.error(f"Missing columns: {missing}")
        else:
            Xb = df_up[FEATURES].copy()
            proba_b = model.predict_proba(Xb)
            df_up["p_normal"] = proba_b[:, 0]
            df_up["p_attack"] = proba_b[:, 1]
            df_up["prediction"] = (df_up["p_attack"] >= threshold).astype(int)

            st.success("Batch prediction completed.")
            st.dataframe(df_up.head(30))

            # Download
            out_csv = df_up.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Predictions CSV", data=out_csv, file_name="snmp_predictions.csv", mime="text/csv")

            # If labeled data exists, show evaluation
            if "Label" in df_up.columns:
                st.markdown("---")
                st.write("### Evaluation (because your CSV contains `Label`)")

                y_true = df_up["Label"].astype(int)
                y_pred = df_up["prediction"].astype(int)

                acc = accuracy_score(y_true, y_pred)
                prec = precision_score(y_true, y_pred, zero_division=0)
                rec = recall_score(y_true, y_pred, zero_division=0)
                f1 = f1_score(y_true, y_pred, zero_division=0)

                a1, a2, a3, a4 = st.columns(4)
                a1.metric("Accuracy", f"{acc:.3f}")
                a2.metric("Precision", f"{prec:.3f}")
                a3.metric("Recall", f"{rec:.3f}")
                a4.metric("F1-score", f"{f1:.3f}")

                cm = confusion_matrix(y_true, y_pred)
                st.write("Confusion Matrix (rows=true, cols=pred):")
                st.dataframe(pd.DataFrame(cm, index=["True Normal", "True Attack"], columns=["Pred Normal", "Pred Attack"]))

                st.text("Classification Report:")
                st.text(classification_report(y_true, y_pred, digits=4))

# =========================================================
# TAB 3: DIAGRAMS
# =========================================================
with tab_diag:
    st.subheader("Model & Feature Diagrams")

    # 1) Feature importance
    st.write("### 1) Feature Importance (Random Forest)")
    importances = model.feature_importances_
    fi = pd.DataFrame({"feature": FEATURES, "importance": importances}).sort_values("importance", ascending=False)

    fig1, ax1 = plt.subplots()
    ax1.barh(fi["feature"], fi["importance"])
    ax1.invert_yaxis()
    ax1.set_xlabel("Importance")
    ax1.set_title("Feature Importance")
    st.pyplot(fig1)

    # 2) “Attack-likeness” indicator (simple, explainable)
    st.write("### 2) Attack-Likeness Indicators (Explainable thresholds)")
    st.caption("These are not the ML model; they are interpretable reference checks to support your demo.")

    # reference thresholds (based on typical SNMP enumeration behavior)
    ref = {
        "sbytes_attack_min": 100000,
        "dur_attack_min": 2.0,
        "ttl_common": [64.0, 128.0]
    }

    st.write("- If **sbytes > 100,000** → very attack-like")
    st.write("- If **dur > 2.0s** → more attack-like")
    st.write("- If **sttl and dttl are stable (64/64 or 128/128)** → more attack-like")

    # 3) Optional: Visual probability gauge from last prediction
    st.write("### 3) Latest Prediction Probability (if available)")
    if "history" in st.session_state and st.session_state["history"]:
        last = st.session_state["history"][-1]
        pN, pA = last["p_normal"], last["p_attack"]
        fig3, ax3 = plt.subplots()
        ax3.bar(["Normal", "Attack"], [pN, pA])
        ax3.set_ylim(0, 1)
        ax3.set_ylabel("Probability")
        ax3.set_title("Latest Saved Prediction")
        st.pyplot(fig3)
    else:
        st.info("Save a prediction in the Predict tab to see this chart.")

# =========================================================
# TAB 4: EXPLAIN
# =========================================================
with tab_explain:
    st.subheader("How the IDS Makes Decisions (Report-friendly)")

    st.markdown("""
**What the model sees:** flow features extracted from captured traffic.

**Why SNMP enumeration is detectable:**
- Enumeration produces **large responses** (high `sbytes`)
- It is **repetitive** (often longer `dur`)
- TTL values capture OS/network consistency (`sttl`, `dttl`)

**Why we removed `service`:**
- It was derived directly from port 161 → would leak the label.
""")

    st.write("### Key features (from ANOVA/importance)")
    st.write("In your project, `sbytes` is usually the strongest indicator of SNMP enumeration.")

# =========================================================
# TAB 5: ABOUT
# =========================================================
with tab_about:
    st.subheader("About")
    st.write("""
This Streamlit app demonstrates a Machine Learning IDS for detecting SNMP enumeration.
- Model: Random Forest
- Deployment: Streamlit + Pickle
- Inputs: flow-level network features
""")
    st.write("Tip for demo day: use the preset buttons and show diagrams + batch mode.")
