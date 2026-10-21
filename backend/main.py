import os
from datetime import datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google import genai

try:
    from openai import OpenAI
    import openai as openai_sdk
except ImportError:
    OpenAI = None
    openai_sdk = None


# Load environment variables from the project root .env file.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

app = FastAPI(title="EAGLE JARVIS")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
openai_api_key = os.getenv("OPENAI_API_KEY", "").strip()
primary_provider = os.getenv("AI_PRIMARY_PROVIDER", "gemini").strip().lower()
if primary_provider not in {"gemini", "openai"}:
    primary_provider = "gemini"

client = genai.Client(
    api_key=gemini_api_key,
    http_options={"timeout": 10000},
) if gemini_api_key else None
openai_client = OpenAI(api_key=openai_api_key, timeout=10.0, max_retries=0) if openai_api_key and OpenAI else None


@app.get("/")
def home():
    return {
        "assistant": "EAGLE JARVIS",
        "status": "ONLINE",
        "message": "Your backend is working!",
        "time": datetime.now().isoformat(),
    }


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "backend": "connected",
        "gemini_configured": client is not None,
        "openai_configured": openai_client is not None,
        "primary_provider": primary_provider,
    }


def _is_retryable_gemini_error(error):
    if isinstance(error, genai.errors.APIError):
        code = getattr(error, "code", None)
        status = str(getattr(error, "status", "")).upper()
        try:
            code = int(code)
        except (TypeError, ValueError):
            code = None
        return code == 429 or (code is not None and code >= 500) or status in {
            "RESOURCE_EXHAUSTED", "INTERNAL", "UNAVAILABLE", "DEADLINE_EXCEEDED",
        }
    return isinstance(error, (httpx.TransportError, TimeoutError, ConnectionError))


def _is_retryable_openai_error(error):
    if openai_sdk is None:
        return False
    retryable_types = tuple(
        error_type
        for error_type in (
            getattr(openai_sdk, "APIConnectionError", None),
            getattr(openai_sdk, "APITimeoutError", None),
            getattr(openai_sdk, "RateLimitError", None),
            getattr(openai_sdk, "InternalServerError", None),
        )
        if isinstance(error_type, type)
    )
    return bool(retryable_types) and isinstance(error, retryable_types)


def _generate_gemini(text):
    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents=text,
    )
    return response.text or "I couldn't generate a response. Try again."


def _generate_openai(text):
    response = openai_client.responses.create(
        model="gpt-6-astra",
        input=text,
        max_output_tokens=300,
    )
    return response.output_text or "I couldn't generate a response. Try again."


@app.get("/api/command")
def command(text: str):
    clean_text = text.strip()
    lower_text = clean_text.lower()

    if not clean_text:
        return {
            "assistant": "EAGLE JARVIS",
            "reply": "Please enter a message.",
        }

    greetings = {
        "hi", "hello", "hey", "hi eagle", "hello eagle", "hey eagle",
        "good morning", "good morning eagle", "good afternoon",
        "good afternoon eagle", "good evening", "good evening eagle",
    }
    if lower_text in greetings:
        return {
            "assistant": "EAGLE JARVIS",
            "your_command": clean_text,
            "reply": "Hello! EAGLE JARVIS is online. How can I help?",
        }

    if lower_text in {"bye", "goodbye", "exit"}:
        return {
            "assistant": "EAGLE JARVIS",
            "your_command": clean_text,
            "reply": "Goodbye! EAGLE JARVIS signing off. See you soon!",
        }

    providers = {
        "gemini": (client is not None, _generate_gemini, _is_retryable_gemini_error),
        "openai": (openai_client is not None, _generate_openai, _is_retryable_openai_error),
    }
    fallback_provider = "openai" if primary_provider == "gemini" else "gemini"
    primary_ready, primary_generate, primary_retryable = providers[primary_provider]

    if not primary_ready:
        if primary_provider == "openai" and openai_api_key and OpenAI is None:
            message = "The OpenAI SDK is not installed. Install the project requirements."
        else:
            message = f"{primary_provider.title()} API key is missing. Check your local .env file."
        return {"assistant": "EAGLE JARVIS", "reply": message}

    try:
        answer = primary_generate(clean_text)
        used_provider = primary_provider
    except Exception as error:
        if not primary_retryable(error):
            print(f"{primary_provider.title()} request failed: {type(error).__name__}")
            return {
                "assistant": "EAGLE JARVIS",
                "reply": f"{primary_provider.title()} could not process the request. Check its API configuration and try again.",
            }

        fallback_ready, fallback_generate, fallback_retryable = providers[fallback_provider]
        if not fallback_ready:
            print(f"{primary_provider.title()} transient failure: {type(error).__name__}; {fallback_provider.title()} is not configured")
            return {
                "assistant": "EAGLE JARVIS",
                "reply": f"{primary_provider.title()} is temporarily unavailable and {fallback_provider.title()} is not configured. Check your connection or retry later.",
            }

        print(f"{primary_provider.title()} transient failure: {type(error).__name__}; trying {fallback_provider.title()}.")
        try:
            answer = fallback_generate(clean_text)
            used_provider = fallback_provider
        except Exception as fallback_error:
            print(f"{fallback_provider.title()} fallback failed: {type(fallback_error).__name__}")
            if not fallback_retryable(fallback_error):
                return {
                    "assistant": "EAGLE JARVIS",
                    "reply": f"{fallback_provider.title()} could not process the request. Check its API configuration and try again.",
                }
            return {
                "assistant": "EAGLE JARVIS",
                "reply": "Both AI providers are temporarily unavailable. Check your connection or retry later.",
            }

    return {
        "assistant": "EAGLE JARVIS",
        "your_command": clean_text,
        "reply": answer,
        "provider": used_provider,
    }
