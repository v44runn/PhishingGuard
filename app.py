from html import escape

import streamlit as st

from detector import detect_red_flags
from model import predict_email


st.set_page_config(
    page_title="PhishGuard | Email Security",
    page_icon="🛡️",
    layout="centered",
)


st.markdown(
    """
    <style>
    .stApp {
        background:
            radial-gradient(ellipse at 50% -15%, rgba(35, 93, 146, .28), transparent 55%),
            #08111f;
        color: #e8eef8;
    }
    .block-container { max-width: 820px; padding-top: 2.6rem; padding-bottom: 3rem; }
    [data-testid="stHeader"] { background: transparent; }
    .brand {
        display: flex; align-items: center; gap: 12px;
        color: #f4f7fc; font-size: 1.1rem; font-weight: 700;
        letter-spacing: .02em; margin-bottom: 2.4rem;
    }
    .brand-mark {
        width: 38px; height: 38px; display: grid; place-items: center;
        border: 1px solid rgba(91, 174, 255, .4); border-radius: 12px;
        background: rgba(46, 128, 204, .16); font-size: 1.15rem;
    }
    .eyebrow {
        color: #71b8ff; font-size: .76rem; font-weight: 700;
        letter-spacing: .16em; text-transform: uppercase; margin-bottom: .55rem;
    }
    h1 { color: #f4f7fc !important; letter-spacing: -.04em !important; }
    .intro { color: #9eacc0; font-size: 1.05rem; line-height: 1.65; margin-bottom: 1.7rem; }
    .panel {
        background: rgba(16, 29, 47, .82); border: 1px solid #233751;
        border-radius: 16px; padding: 1.25rem 1.4rem;
        margin: .4rem 0 1rem;
    }
    .result-top { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
    .risk-label { color: #9eacc0; font-size: .86rem; margin-bottom: .35rem; }
    .risk-value { color: #f4f7fc; font-size: 2.5rem; font-weight: 750; line-height: 1.1; }
    .badge {
        border-radius: 999px; padding: .42rem .8rem; font-size: .82rem;
        font-weight: 700; white-space: nowrap;
    }
    .section-title { color: #e8eef8; font-size: 1rem; font-weight: 700; margin: 1.3rem 0 .65rem; }
    .signal {
        background: rgba(255, 255, 255, .035); border: 1px solid #233751;
        border-radius: 10px; color: #c4cfde; margin: .5rem 0;
        padding: .8rem .95rem; line-height: 1.5;
    }
    .note { color: #8e9db2; font-size: .84rem; line-height: 1.55; }
    div[data-testid="stTextArea"] textarea {
        background: #0b1727; color: #e8eef8; border-color: #2a405c;
        border-radius: 10px; line-height: 1.55;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: #58aaff; box-shadow: 0 0 0 1px #58aaff;
    }
    div.stButton > button {
        width: 100%; border: 0; border-radius: 10px; min-height: 3rem;
        background: linear-gradient(100deg, #2878d0, #3a9bff);
        color: white; font-weight: 700;
    }
    div.stButton > button:hover { border: 0; background: #51a7ff; color: white; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="brand"><span class="brand-mark">🛡️</span> PHISHGUARD</div>',
    unsafe_allow_html=True,
)
st.markdown('<div class="eyebrow">Email threat analysis</div>', unsafe_allow_html=True)
st.title("Spot suspicious emails before they reach you.")
st.markdown(
    '<div class="intro">Paste an email below to get a machine-learning risk estimate '
    "and an explanation of suspicious patterns found in the message.</div>",
    unsafe_allow_html=True,
)

email_text = st.text_area(
    "Email content",
    placeholder="Paste the email text here. Include the From and Reply-To headers if available.",
    height=230,
    label_visibility="collapsed",
)
analyze_clicked = st.button("Analyze email", type="primary")

if analyze_clicked:
    if not email_text.strip():
        st.warning("Paste an email message first, then select Analyze email.")
        st.session_state.pop("analysis", None)
        st.session_state.pop("analyzed_text", None)
    else:
        with st.spinner("Analyzing the email..."):
            try:
                phishing_probability = predict_email(email_text)
            except FileNotFoundError as error:
                st.error(
                    "The phishing model has not been trained yet. Download the Kaggle "
                    "Phishing Email Dataset CSV and run "
                    "`python model.py --train path/to/Phishing_Email.csv`, then select "
                    "Analyze email again."
                )
                st.caption(str(error))
                st.session_state.pop("analysis", None)
                st.session_state.pop("analyzed_text", None)
            else:
                if phishing_probability < 35:
                    level = "Low"
                    color = "#39d98a"
                elif phishing_probability < 70:
                    level = "Medium"
                    color = "#ffbd4a"
                else:
                    level = "High"
                    color = "#ff647c"
                st.session_state.analysis = {
                    "score": phishing_probability,
                    "level": level,
                    "color": color,
                    "explanations": detect_red_flags(email_text),
                }
                st.session_state.analyzed_text = email_text

analysis = st.session_state.get("analysis")
if analysis and st.session_state.get("analyzed_text") == email_text:
    score = analysis["score"]
    color = analysis["color"]
    st.markdown(
        f"""
        <div class="panel">
          <div class="result-top">
            <div>
              <div class="risk-label">Phishing risk score</div>
              <div class="risk-value">{score}<span style="font-size:1rem;color:#8e9db2;font-weight:500"> / 100</span></div>
            </div>
            <span class="badge" style="color:{color};background:{color}1c;border:1px solid {color}55">
              {analysis["level"]} Risk
            </span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(score / 100)

    st.markdown('<div class="section-title">What we noticed</div>', unsafe_allow_html=True)
    if analysis["explanations"]:
        for explanation in analysis["explanations"]:
            st.markdown(
                '<div class="signal">• '
                + escape(explanation)
                + "</div>",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="signal">No common phishing signals were detected in this message.</div>',
            unsafe_allow_html=True,
        )

st.markdown(
    '<div class="note">The score is a machine-learning probability estimate, not a guarantee '
    "that a message is safe or malicious. Explanations are rule-based indicators and may not "
    "identify every threat. Verify unexpected requests through a trusted, separate channel.</div>",
    unsafe_allow_html=True,
)