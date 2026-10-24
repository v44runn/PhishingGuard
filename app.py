from html import escape

import streamlit as st

from detector import detect_red_flags
from model import predict_email
from url_checker import analyze_url


def _highlight_email(text: str, findings: list[dict[str, int | str]]) -> str:
    ranges = sorted(
        (int(finding["start"]), int(finding["end"])) for finding in findings
    )
    merged_ranges = []
    for start, end in ranges:
        if merged_ranges and start <= merged_ranges[-1][1]:
            merged_ranges[-1] = (merged_ranges[-1][0], max(end, merged_ranges[-1][1]))
        else:
            merged_ranges.append((start, end))

    parts = []
    offset = 0
    for start, end in merged_ranges:
        parts.append(escape(text[offset:start]))
        parts.append("<mark>" + escape(text[start:end]) + "</mark>")
        offset = end
    parts.append(escape(text[offset:]))
    return "".join(parts)


def _render_email_checker() -> None:
    st.markdown('<div class="eyebrow">Email threat analysis</div>', unsafe_allow_html=True)
    st.subheader("Check an email")
    st.markdown(
        '<div class="intro">Get a machine-learning risk estimate and an explanation '
        "of suspicious patterns found in the message.</div>",
        unsafe_allow_html=True,
    )

    email_text = st.text_area(
        "Email content",
        placeholder="Paste the email text here. Include the From and Reply-To headers if available.",
        height=230,
        label_visibility="collapsed",
        key="email_text",
    )
    analyze_clicked = st.button("Analyze email", type="primary", key="analyze_email")

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
                        "The phishing model has not been trained yet. Put the prepared "
                        "dataset at `data/dataset.csv` and run `python model.py`, then "
                        "select Analyze email again."
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
                        "findings": detect_red_flags(email_text),
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

        st.markdown('<div class="section-title">Highlighted email</div>', unsafe_allow_html=True)
        if analysis["findings"]:
            st.markdown(
                '<pre class="email-highlight">'
                + _highlight_email(email_text, analysis["findings"])
                + "</pre>",
                unsafe_allow_html=True,
            )
            st.markdown('<div class="section-title">Detected red flags</div>', unsafe_allow_html=True)
            for finding in analysis["findings"]:
                st.markdown(
                    '<div class="signal"><strong>Line '
                    + str(finding["line_number"])
                    + ":</strong> "
                    + escape(str(finding["explanation"]))
                    + '<br><code>'
                    + escape(str(finding["text"]))
                    + "</code><br><span class=\"note\">"
                    + escape(str(finding["line"]))
                    + "</span></div>",
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                '<div class="signal">No suspicious patterns were detected to highlight.</div>',
                unsafe_allow_html=True,
            )

    st.markdown(
        '<div class="note">The score is a machine-learning probability estimate, not a guarantee '
        "that a message is safe or malicious. Explanations are rule-based indicators and may not "
        "identify every threat. Verify unexpected requests through a trusted, separate channel.</div>",
        unsafe_allow_html=True,
    )


def _render_url_checker() -> None:
    st.markdown('<div class="eyebrow">Link threat analysis</div>', unsafe_allow_html=True)
    st.subheader("Check a URL")
    st.markdown(
        '<div class="intro">Review a link for common warning signs before opening it. '
        "PhishGuard checks the URL locally and does not visit the destination.</div>",
        unsafe_allow_html=True,
    )
    url = st.text_input(
        "URL to check",
        placeholder="example.com or https://example.com/login",
        key="url_to_check",
    )
    if st.button("Check URL", type="primary", key="check_url"):
        st.session_state.url_analysis = analyze_url(url)
        st.session_state.url_analyzed_input = url

    result = st.session_state.get("url_analysis")
    if result and st.session_state.get("url_analyzed_input") == url:
        score = result["score"]
        if score < 35:
            level = "Low"
            status_color = "#39d98a"
        elif score < 70:
            level = "Medium"
            status_color = "#ffbd4a"
        else:
            level = "High"
            status_color = "#ff647c"
        st.markdown(
            f"""
            <div class="panel">
              <div class="risk-label">URL risk score</div>
              <div class="risk-value" style="font-size:2rem">{score}<span style="font-size:1rem;color:#8e9db2;font-weight:500"> / 100</span></div>
              <div class="risk-value" style="font-size:1.3rem;color:{status_color}">
                {level} Risk
              </div>
              <div class="note" style="margin-top:.6rem;overflow-wrap:anywhere">
                {escape(str(result["domain"] or result["url"]))}
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.progress(score / 100)
        if result["reasons"]:
            st.markdown('<div class="section-title">What to review</div>', unsafe_allow_html=True)
            for reason in result["reasons"]:
                st.markdown(
                    '<div class="signal">• ' + escape(str(reason)) + "</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success(
                "No obvious URL warning signs were found. This does not guarantee the site is safe."
            )

    st.markdown(
        '<div class="note">Checks are based on URL structure and common domain patterns. '
        "PhishGuard does not open the link or verify the live website.</div>",
        unsafe_allow_html=True,
    )


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
    .email-highlight {
        white-space: pre-wrap; overflow-wrap: anywhere; margin: .5rem 0;
        padding: 1rem; border: 1px solid #233751; border-radius: 10px;
        background: #0b1727; color: #d6e0ef; line-height: 1.65;
        font: .9rem/1.65 ui-monospace, SFMono-Regular, Consolas, monospace;
    }
    .email-highlight mark {
        color: #fff4d4; background: rgba(222, 157, 36, .42);
        border-bottom: 2px solid #ffbd4a; border-radius: 3px;
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
st.title("Spot suspicious emails before they reach you.")
email_tab, url_tab = st.tabs(["Email checker", "URL checker"])
with email_tab:
    _render_email_checker()
with url_tab:
    _render_url_checker()