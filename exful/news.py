import requests
import uuid
import json

def get_news_data(access_key, keywords, language):
    base_url = "https://api.mediastack.com/v1/news"
    params = {
        "access_key": access_key,
        "categories": "general",
        "languages": language,
        "keywords": keywords
    }
    response = requests.get(base_url, params=params)
    json_response = response.json()
    news_data = []
    for article in json_response["data"]:
        news_id = str(uuid.uuid4())  # Generate a unique news ID
        title = article["title"]
        link = article["url"]
        description = article["description"]
        image_url = article["image"]
        news_data.append({
            "news_id": news_id,  # Add the news ID to the dictionary
            "title": title,
            "link": link,
            "description": description,
            "image_url": image_url
        })
    return news_data