import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu, simpledialog
from tkinterdnd2 import TkinterDnD, DND_FILES
import requests
import hashlib
import json
import os
import webbrowser
import urllib.parse
from threading import Thread
from datetime import datetime
from PIL import ImageTk, Image

# Константи за API ключовете
VIRUSTOTAL_API_KEY = '6aefbe39b917ac183706945c6226de5ff74f6e2830b97ecb2d9dac8d5db856d9'
HYBRIDANALYSIS_API_KEY = 'nm3req5j7be910c9kwq23w4g59863acffwgr86rwa4aead178bmo9bdt25b33548'

# Функции за хеширане на файла
def calculate_hashes(file_path):
    hashes = {"md5": None, "sha1": None, "sha256": None}
    with open(file_path, "rb") as f:
        file_data = f.read()
        hashes["md5"] = hashlib.md5(file_data).hexdigest()
        hashes["sha1"] = hashlib.sha1(file_data).hexdigest()
        hashes["sha256"] = hashlib.sha256(file_data).hexdigest()
    return hashes

# Функции за качване и получаване на анализ от VirusTotal
def upload_to_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()
    else:
        print("Грешка при качване във VirusTotal:", response.status_code)
        return {"error": response.json().get("error", "Unknown error")}

def get_virustotal_analysis(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Грешка при извличане на резултата от VirusTotal: {response.status_code}")
        return {"error": response.json().get("error", "Unknown error")}

def scan_url_virustotal(url_to_scan):
    url = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = f'url={urllib.parse.quote(url_to_scan)}'
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        print("Грешка при сканиране на URL във VirusTotal:", response.status_code)
        return {"error": response.json().get("error", "Unknown error")}

def get_virustotal_file_info(identifier):
    url = f'https://www.virustotal.com/api/v3/files/{identifier}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Грешка при извличане на информацията от VirusTotal: {response.status_code}")
        return {"error": response.json().get("error", "Unknown error")}

# Функции за качване и проверка в Hybrid Analysis
def upload_to_hybrid_analysis(file_path, email=None):
    url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': HYBRIDANALYSIS_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'environment_id': '120',  # Задаване на ID на средата (например: Windows 10)
    }
    if email:
        params['email'] = email  # Добавяне на email за уведомление

    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, headers=headers, files=files, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Грешка при качване в Hybrid Analysis: {response.status_code}")
        return {"error": response.json().get("error", "Unknown error")}

def scan_hash_hybrid_analysis(file_hash):
    url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': HYBRIDANALYSIS_API_KEY,
        'Accept': 'application/json'
    }
    data = {'hash': file_hash}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Грешка при търсене на хеш в Hybrid Analysis: {response.status_code}")
        return {"error": response.json().get("error", "Unknown error")}

# Функция за генериране на репорт в текстов файл
def generate_report(data, filename="report.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Threat Analysis Report\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(json.dumps(data, indent=4, ensure_ascii=False))
    messagebox.showinfo("Информация", f"Репортът е генериран: {filename}")

# Графичен интерфейс
def create_gui():
    root = TkinterDnD.Tk()
    root.title("Threat Analysis Tool")
    root.geometry("900x700")

    # Основен фрейм
    main_frame = ttk.Frame(root)
    main_frame.pack(fill='both', expand=True)

    # Notebook за раздели
    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill='both', expand=True, padx=10, pady=10)

    # Фрейм за сканиране на файлове
    scan_files_frame = ttk.Frame(notebook)
    notebook.add(scan_files_frame, text="Сканиране на файлове")

    # Фрейм за обща информация
    general_frame = ttk.Frame(scan_files_frame)
    general_frame.pack(fill='both', expand=True, padx=10, pady=10)

    # Поле за въвеждане на хеш или URL
    tk.Label(general_frame, text="Въведете хеш или URL:", font=("Arial", 12)).pack(pady=10)
    input_entry = tk.Entry(general_frame, width=50, font=("Arial", 12))
    input_entry.pack()

    # Добавяне на десен бутон за поставяне и избор на всичко в полето за въвеждане
    def input_entry_popup(event):
        menu = Menu(root, tearoff=0)
        menu.add_command(label="Постави", command=lambda: input_entry.event_generate("<<Paste>>"))
        menu.add_command(label="Избери всичко", command=lambda: input_entry.select_range(0, 'end'))
        menu.post(event.x_root, event.y_root)

    input_entry.bind("<Button-3>", input_entry_popup)

    # Добавяне на клавишни комбинации за полето за въвеждане
    def select_all(event):
        input_entry.select_range(0, 'end')
        return 'break'

    input_entry.bind("<Control-a>", select_all)
    input_entry.bind("<Control-A>", select_all)
    input_entry.bind("<Control-v>", lambda e: input_entry.event_generate('<<Paste>>'))
    input_entry.bind("<Control-V>", lambda e: input_entry.event_generate('<<Paste>>'))

    # Поле за показване на резултати
    details_frame = ttk.Frame(scan_files_frame)
    details_frame.pack(fill='both', expand=True, padx=10, pady=10)
    result_text = tk.Text(details_frame, wrap="word", font=("Arial", 10), state="disabled")
    result_text.pack(fill="both", expand=True, padx=10, pady=10)

    # Добавяне на десен бутон за копиране и избор на текст
    def popup(event):
        menu = Menu(root, tearoff=0)
        menu.add_command(label="Избери всичко", command=lambda: result_text.tag_add("sel", "1.0", "end"))
        menu.add_command(label="Копирай", command=lambda: root.clipboard_append(result_text.get("1.0", "end-1c")))
        menu.post(event.x_root, event.y_root)

    result_text.bind("<Button-3>", popup)

    # Драг и дроп поддръжка
    def on_drop(event):
        global file_path
        file_path = event.data.strip("{}")
        file_label.config(text=f"Избран файл: {os.path.basename(file_path)}", fg="blue")

    root.drop_target_register(DND_FILES)
    root.dnd_bind('<<Drop>>', on_drop)

    # Избраният файл
    global file_path
    file_path = None
    file_label = tk.Label(general_frame, text="Файл не е избран.", font=("Arial", 10), fg="gray")
    file_label.pack(pady=5)

    # Бутон за избор на файл
    def open_file():
        global file_path
        file_path = filedialog.askopenfilename(title="Изберете файл за анализ")
        if file_path:
            file_label.config(text=f"Избран файл: {os.path.basename(file_path)}", fg="blue")

    tk.Button(general_frame, text="Избери файл", command=open_file).pack(pady=10)

    # Бутон за проверка във VirusTotal (асинхронно)
    def check_virustotal():
        if not file_path:
            messagebox.showwarning("Грешка", "Изберете файл за анализ.")
            return

        def thread_function():
            # Качване на файла във VirusTotal
            vt_response = upload_to_virustotal(file_path)
            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)

            if "error" in vt_response:
                result_text.insert(tk.END, f"Грешка при качване във VirusTotal: {vt_response['error']}\n")
            else:
                analysis_id = vt_response['data']['id']
                result_text.insert(tk.END, f"Успешно качване във VirusTotal. ID на анализа: {analysis_id}\n")

                # Вземане на резултата от анализа
                analysis_data = get_virustotal_analysis(analysis_id)
                if "error" in analysis_data:
                    result_text.insert(tk.END, f"Грешка при извличане на резултата: {analysis_data['error']}\n")
                else:
                    # Показване на хеш стойностите и статуса на заплахите
                    result_text.insert(tk.END, f"MD5: {analysis_data['meta']['file_info']['md5']}\n")
                    result_text.insert(tk.END, f"SHA-1: {analysis_data['meta']['file_info']['sha1']}\n")
                    result_text.insert(tk.END, f"SHA-256: {analysis_data['meta']['file_info']['sha256']}\n")
                    result_text.insert(tk.END, f"Malicious: {analysis_data['data']['attributes']['stats']['malicious']}\n")
                    result_text.insert(tk.END, f"Suspicious: {analysis_data['data']['attributes']['stats']['suspicious']}\n")
                    result_text.insert(tk.END, f"Undetected: {analysis_data['data']['attributes']['stats']['undetected']}\n")

                    # Връзка към анализа
                    analysis_link = f"https://www.virustotal.com/gui/file/{analysis_data['meta']['file_info']['sha256']}"
                    result_text.insert(tk.END, f"[Отвори анализа във VirusTotal]\n")
                    result_text.tag_config("link", foreground="blue", underline=1)
                    result_text.tag_bind("link", "<Button-1>", lambda e: webbrowser.open(analysis_link))
                    result_text.insert(tk.END, analysis_link, "link")

                # Генериране на репорт
                generate_report(analysis_data)
            
            result_text.config(state="disabled")

        Thread(target=thread_function).start()

    # Бутон за проверка в Hybrid Analysis (асинхронно)
    def check_hybrid_analysis():
        if not file_path:
            messagebox.showwarning("Грешка", "Изберете файл за анализ.")
            return

        email = simpledialog.askstring("Имейл адрес", "Въведете имейл за получаване на репорта (незадължително):")

        def thread_function():
            # Качване на файла в Hybrid Analysis
            ha_response = upload_to_hybrid_analysis(file_path, email)
            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)

            if "error" in ha_response:
                result_text.insert(tk.END, f"Грешка при качване в Hybrid Analysis: {ha_response['error']}\n")
            else:
                if 'verdict' in ha_response and ha_response['verdict'] == 'no specific threat':
                    result_text.insert(tk.END, "Файлът е чист - няма открити заплахи.\n")
                else:
                    result_text.insert(tk.END, "Резултати от анализа в Hybrid Analysis:\n")
                    result_text.insert(tk.END, json.dumps(ha_response, indent=4))

                # Генериране на репорт
                generate_report(ha_response, filename="hybrid_analysis_report.txt")

            result_text.config(state="disabled")

        Thread(target=thread_function).start()

    # Бутон за проверка на хеш или URL във VirusTotal (асинхронно)
    def check_url_or_hash():
        identifier = input_entry.get().strip()
        if not identifier:
            messagebox.showwarning("Грешка", "Въведете хеш или URL за анализ.")
            return

        def thread_function():
            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)

            if identifier.startswith("http"):
                # Сканиране на URL във VirusTotal
                vt_response = scan_url_virustotal(identifier)
                if "error" in vt_response:
                    result_text.insert(tk.END, f"Грешка при сканиране на URL във VirusTotal: {vt_response['error']}\n")
                else:
                    analysis_id = vt_response['data']['id']
                    result_text.insert(tk.END, f"URL успешно сканиран. ID на анализа: {analysis_id}\n")
                    analysis_data = get_virustotal_analysis(analysis_id)
                    if "error" in analysis_data:
                        result_text.insert(tk.END, f"Грешка при извличане на резултата: {analysis_data['error']}\n")
                    else:
                        result_text.insert(tk.END, "Резултати от анализа на URL във VirusTotal:\n")
                        result_text.insert(tk.END, json.dumps(analysis_data, indent=4))
                        generate_report(analysis_data, filename="url_analysis_report.txt")
            else:
                # Извличане на информация за хеш от VirusTotal
                vt_response = get_virustotal_file_info(identifier)
                if "error" in vt_response:
                    result_text.insert(tk.END, f"Грешка при извличане на информация от VirusTotal: {vt_response['error']}\n")
                else:
                    result_text.insert(tk.END, "Резултати от анализа във VirusTotal:\n")
                    result_text.insert(tk.END, json.dumps(vt_response, indent=4))
                    generate_report(vt_response, filename="file_analysis_report.txt")

            result_text.config(state="disabled")

        Thread(target=thread_function).start()

    # Бутон за проверка на хеш в Hybrid Analysis (асинхронно)
    def check_hash_hybrid_analysis():
        file_hash = input_entry.get().strip()
        if not file_hash:
            messagebox.showwarning("Грешка", "Въведете хеш за анализ.")
            return

        def thread_function():
            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)

            ha_response = scan_hash_hybrid_analysis(file_hash)
            if "error" in ha_response:
                result_text.insert(tk.END, f"Грешка при търсене на хеш в Hybrid Analysis: {ha_response['error']}\n")
            else:
                result_text.insert(tk.END, "Резултати от анализа в Hybrid Analysis:\n")
                result_text.insert(tk.END, json.dumps(ha_response, indent=4))
                generate_report(ha_response, filename="hybrid_hash_analysis_report.txt")

            result_text.config(state="disabled")

        Thread(target=thread_function).start()

    # Бутоните за проверка
    tk.Button(general_frame, text="Провери във VirusTotal", command=check_virustotal).pack(pady=5)
    tk.Button(general_frame, text="Провери в Hybrid Analysis", command=check_hybrid_analysis).pack(pady=5)
    tk.Button(general_frame, text="Провери URL или хеш във VirusTotal", command=check_url_or_hash).pack(pady=5)
    tk.Button(general_frame, text="Провери хеш в Hybrid Analysis", command=check_hash_hybrid_analysis).pack(pady=5)

    root.mainloop()

create_gui()
