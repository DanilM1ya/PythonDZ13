import os
import requests
import json

#API ключ
API_KEY = os.getenv("VT_API_KEY")

#Заголовки для авторизации
headers = {
    "x-apikey": API_KEY
}

#Базовый URL
BASE_URL = "https://www.virustotal.com/api/v3"

#Хеш файла для проверки
FILE_HASH = "44d88612fea8a8f36de82e1278abb02f"

#Запрос к API
url = f"{BASE_URL}/files/{FILE_HASH}"
print(f"Отправка запроса к {url}...")

#Выполняем запрос
response = requests.get(url, headers=headers)

#Вывод результатов
if response.status_code == 200:
    data = response.json()
    
    #Сохраняем JSON в файл
    with open("virustotal_result.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("Результат сохранен в файл virustotal_result.json")
    
    print("\nСтатистика сканирования:")
    
    stats = data["data"]["attributes"]["last_analysis_stats"]
    print(f"Вредоносных:     {stats['malicious']}")
    print(f"Подозрительных:   {stats['suspicious']}")
    print(f"Безопасных:       {stats['harmless']}")
    print(f"Неопределенных:   {stats['undetected']}")
else:
    print(f"Ошибка: {response.status_code}")
    print(response.text)
