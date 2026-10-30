"""Ultra-Fast Gemini 3.5 Flash-Lite Extractor (Tile-Optimized for Speed)."""

import os
from io import BytesIO
from PIL import Image
from google import genai
from google.genai import types

def extract_text_from_image(image_file, api_key: str = None) -> tuple[str, str | None]:
    """
    Extracts text using Gemini 3.5 Flash-Lite without exposing credentials in UI.
    """
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return "", "GEMINI_API_KEY is not set in your .env file. Please check your configuration."

    try:
        client = genai.Client(api_key=key)

        image_file.seek(0)
        img = Image.open(image_file)

        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        # Downscale to 600px for minimal token consumption and fast extraction
        max_dim = 600
        if max(img.size) > max_dim:
            img.thumbnail((max_dim, max_dim), Image.Resampling.BILINEAR)

        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=75)
        buffer.seek(0)
        optimized_img = Image.open(buffer)

        prompt = "OCR: Extract all text, numbers, URLs, and headers verbatim. No commentary."

        config = types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="low"),
            max_output_tokens=400,
            temperature=0.0
        )

        response = client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=[optimized_img, prompt],
            config=config
        )

        extracted_text = response.text.strip() if response.text else ""
        if not extracted_text:
            return "", "No text detected in screenshot."

        return extracted_text, None

    except Exception as e:
        return "", f"Extraction error: {str(e)}"