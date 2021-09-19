def format_align_digits(text, reference_text):
    if len(text) != len(reference_text):
        for idx, t in enumerate(reference_text):
            if not t.isdigit():
                text = text[:idx] + reference_text[idx] + text[idx:]
    return text
