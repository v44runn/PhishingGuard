def analyze_email(text):  # Accept the email text
    warnings = []  # Create an empty list of warnings

    if "urgent" in text.lower():  # Check for urgent language
        warnings.append("Contains urgent language")  # Add a warning

    if "verify your account" in text.lower():  # Check for account verification requests
        warnings.append("Requests account verification")  # Add a warning

    return warnings  # Return all detected warnings