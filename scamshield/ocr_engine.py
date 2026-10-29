"""Gemini Visual Extractor with Thinking DISABLED (Ultra-Fast)."""

import os
from io import BytesIO
from PIL import Image
from google import genai
from google.genai import types

def extract_text_with_gemini(image_file, api_key: str = None) -> tuple[str, str | None]:
    """
    Extracts text from screenshots with Gemini thinking mode disabled
    for near-instant OCR speeds (~1s).
    """
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return "", "Gemini API Key missing. Please provide your API Key."

    try:
        client = genai.Client(api_key=key)

        # 1. Reset pointer and open image
        image_file.seek(0)
        img = Image.open(image_file)

        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        # 2. Downscale huge screenshots to speed up transmission
        max_dim = 1200
        if max(img.size) > max_dim:
            img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=85)
        buffer.seek(0)
        optimized_img = Image.open(buffer)

        prompt = (
            "Extract all readable text, URLs, numbers, and brand names verbatim "
            "from this screenshot. Do not explain or summarize. Just output the extracted text."
        )

        # 3. DISABLE THINKING: Set thinking_budget=0
        fast_config = types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_budget=0),
            temperature=0.0  # Zero temperature for deterministic, fast extraction
        )

        # Fast direct extraction without thinking delays
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[optimized_img, prompt],
            config=fast_config
        )

        extracted_text = response.text.strip() if response.text else ""
        if not extracted_text:
            return "", "No text detected in image."

        return extracted_text, None

    except Exception as e:
        return "", f"Gemini extraction error: {str(e)}"