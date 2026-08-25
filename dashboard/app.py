import json
from collections import Counter
from pathlib import Path

import requests
import streamlit as st


# ==================================================
# Configuration
# ==================================================

API_URL = "http://127.0.0.1:8000/api/v1/security/analyze"

LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "security_events.jsonl"
)


# ==================================================
# Page configuration
# ==================================================

st.set_page_config(
    page_title="LLM-Sentinel",
    page_icon="Shield",
    layout="wide",
)


# ==================================================
# Custom styling
# ==================================================

st.markdown(
    """
    <style>
        .main-title {
            font-size: 42px;
            font-weight: 700;
            margin-bottom: 0;
        }

        .subtitle {
            font-size: 20px;
            color: #777;
            margin-top: 0;
        }

        .section-title {
            font-size: 26px;
            font-weight: 600;
            margin-top: 20px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==================================================
# Helper functions
# ==================================================

def load_security_events():
    """Load security events from JSONL log."""

    if not LOG_FILE.exists():
        return []

    events = []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except OSError:
        return []

    return events


def get_risk_message(risk_level):
    """Return a readable risk description."""

    messages = {
        "LOW": "Low security risk detected.",
        "MEDIUM": "Suspicious activity requires review.",
        "HIGH": "High-risk activity detected.",
        "CRITICAL": "Critical security threat detected.",
    }

    return messages.get(
        risk_level,
        "Security assessment completed.",
    )


def get_detection_counts(events):
    """Count detection categories across all events."""

    categories = []

    for event in events:

        for detection in event.get("detections", []):

            category = detection.get(
                "category",
                "unknown",
            )

            categories.append(category)

    return Counter(categories)


# ==================================================
# Header
# ==================================================

st.markdown(
    '<div class="main-title">LLM-Sentinel</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    "LLM Application Security Gateway"
    "</div>",
    unsafe_allow_html=True,
)

st.write(
    "Analyze prompts for prompt injection "
    "and character-level obfuscation."
)


# ==================================================
# Prompt Analysis
# ==================================================

st.markdown(
    '<div class="section-title">Prompt Analysis</div>',
    unsafe_allow_html=True,
)

prompt = st.text_area(
    "Enter a prompt to analyze:",
    height=180,
    placeholder="Enter a user prompt here...",
)


if st.button("Analyze Prompt", type="primary"):

    if not prompt.strip():

        st.warning("Please enter a prompt.")
        st.stop()

    try:

        response = requests.post(
            API_URL,
            json={"prompt": prompt},
            timeout=10,
        )

        response.raise_for_status()

        result = response.json()

    except requests.exceptions.ConnectionError:

        st.error(
            "Could not connect to the LLM-Sentinel API. "
            "Make sure FastAPI is running on port 8000."
        )

        st.stop()

    except requests.exceptions.Timeout:

        st.error(
            "The API request timed out."
        )

        st.stop()

    except requests.exceptions.RequestException as error:

        st.error(
            f"API request failed: {error}"
        )

        st.stop()

    # ==================================================
    # Extract result
    # ==================================================

    risk_score = result.get(
        "risk_score",
        0,
    )

    risk_level = result.get(
        "risk_level",
        "LOW",
    )

    decision = result.get(
        "decision",
        "ALLOW",
    )

    detections = result.get(
        "detections",
        [],
    )


    # ==================================================
    # Security Analysis
    # ==================================================

    st.divider()

    st.markdown(
        '<div class="section-title">'
        "Security Analysis"
        "</div>",
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Risk Score",
            f"{risk_score}/100",
        )

    with col2:

        st.metric(
            "Risk Level",
            risk_level,
        )

    with col3:

        st.metric(
            "Decision",
            decision,
        )

    with col4:

        st.metric(
            "Detections",
            len(detections),
        )


    # ==================================================
    # Risk Assessment
    # ==================================================

    st.subheader("Risk Assessment")

    st.progress(
        min(
            max(
                risk_score,
                0,
            ),
            100,
        ) / 100
    )

    st.caption(
        f"Security risk score: {risk_score}/100"
    )

    st.write(
        get_risk_message(risk_level)
    )


    # ==================================================
    # Decision
    # ==================================================

    if decision == "BLOCK":

        st.error(
            "Prompt BLOCKED - suspicious activity detected."
        )

    elif decision == "REVIEW":

        st.warning(
            "Prompt requires REVIEW."
        )

    else:

        st.success(
            "Prompt ALLOWED - no significant threat detected."
        )


    # ==================================================
    # Detections
    # ==================================================

    st.subheader("Detections")

    if not detections:

        st.success(
            "No suspicious patterns detected."
        )

    else:

        for detection in detections:

            category = detection.get(
                "category",
                "unknown",
            )

            confidence = detection.get(
                "confidence",
                0,
            )

            reason = detection.get(
                "reason",
                "No reason provided.",
            )

            with st.container(border=True):

                st.markdown(
                    f"### {category}"
                )

                st.write(
                    f"**Confidence:** "
                    f"{confidence * 100:.0f}%"
                )

                st.progress(
                    min(
                        max(
                            confidence,
                            0,
                        ),
                        1,
                    )
                )

                st.write(
                    f"**Reason:** {reason}"
                )


# ==================================================
# Security Event History
# ==================================================

st.divider()

st.markdown(
    '<div class="section-title">'
    "Security Event History"
    "</div>",
    unsafe_allow_html=True,
)

events = load_security_events()


if not events:

    st.info(
        "No security events have been recorded yet."
    )

else:

    recent_events = list(
        reversed(
            events[-10:]
        )
    )

    history_data = []

    for event in recent_events:

        history_data.append(
            {
                "Timestamp": event.get(
                    "timestamp",
                    "Unknown",
                ),
                "Risk Score": event.get(
                    "risk_score",
                    0,
                ),
                "Risk Level": event.get(
                    "risk_level",
                    "UNKNOWN",
                ),
                "Decision": event.get(
                    "decision",
                    "UNKNOWN",
                ),
                "Detections": len(
                    event.get(
                        "detections",
                        [],
                    )
                ),
            }
        )

    st.dataframe(
        history_data,
        use_container_width=True,
        hide_index=True,
    )


# ==================================================
# Security Statistics
# ==================================================

st.markdown(
    '<div class="section-title">'
    "Security Statistics"
    "</div>",
    unsafe_allow_html=True,
)


if events:

    total_events = len(events)

    blocked_events = sum(
        1
        for event in events
        if event.get("decision") == "BLOCK"
    )

    review_events = sum(
        1
        for event in events
        if event.get("decision") == "REVIEW"
    )

    allowed_events = sum(
        1
        for event in events
        if event.get("decision") == "ALLOW"
    )


    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Total Events",
            total_events,
        )

    with col2:

        st.metric(
            "Blocked",
            blocked_events,
        )

    with col3:

        st.metric(
            "Review",
            review_events,
        )

    with col4:

        st.metric(
            "Allowed",
            allowed_events,
        )


else:

    st.info(
        "Statistics will appear after security events are recorded."
    )


# ==================================================
# Detection Statistics
# ==================================================

st.subheader("Detection Statistics")

detection_counts = get_detection_counts(events)


if not detection_counts:

    st.info(
        "No detections have been recorded yet."
    )

else:

    detection_data = []

    for category, count in detection_counts.most_common():

        detection_data.append(
            {
                "Detection Category": category,
                "Occurrences": count,
            }
        )

    st.dataframe(
        detection_data,
        use_container_width=True,
        hide_index=True,
    )


# ==================================================
# Footer
# ==================================================

st.divider()

st.caption(
    "LLM-Sentinel v1.0.0 - LLM Application Security Gateway"
)