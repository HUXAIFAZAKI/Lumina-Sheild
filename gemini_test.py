import os
from google import genai
from google.genai import types

def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = input("Enter your Gemini API key: ").strip()
        if not api_key:
            print("Error: API key is required.")
            return

    client = genai.Client(api_key=api_key)

    model_id = "gemini-2.5-flash-lite"

    # Enable Google Search grounding tool
    google_search_tool = types.Tool(google_search=types.GoogleSearch())

    config = types.GenerateContentConfig(
        tools=[google_search_tool],
    )

    chat = client.chats.create(model=model_id, config=config)

    print("Gemini 2.5 Flash Lite Chatbot with Web Search")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print("Goodbye!")
            break

        try:
            response = chat.send_message(user_input)
            print(f"\nGemini: {response.text}\n")
        except Exception as e:
            print(f"\nError: {e}\n")

if __name__ == "__main__":
    main()
