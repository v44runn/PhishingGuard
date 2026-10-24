import streamlit as st  # Import the UI library
from detector import analyze_email  # Import email warning checks
from url_checker import check_url  # Import URL checks

st.title("🛡️ PhishGuard")  # Display the app title

mode = st.radio("Analyze:", ["Email", "URL"])  # Let users choose input type

text = st.text_area("Paste your email or URL")  # Create the input box

if st.button("Analyze"):  # Run when the button is clicked
    if not text.strip():  # Check for empty input
        st.error("Please enter something.")  # Show error
    elif mode == "Email":  # Handle email analysis
        warnings = analyze_email(text)  # Get email warning messages
        st.write("Email red flags:", warnings)  # Display explanations
        st.info("ML prediction will appear when the model is ready.")  # Placeholder
    else:  # Handle URL analysis
        result = check_url(text)  # Analyze the URL
        st.write("URL risk score:", result["score"])  # Display URL score
        st.write("Reasons:", result["reasons"])  # Display URL warnings