import tkinter as tk 
from tkinter import filedialog, messagebox, ttk, Menu
import requests
import csv
import json
import hashlib
import time

# Function to fetch IP information from different APIs
def fetch_ip_info(ip_list, api_type):
    country_mapping = {
        'AF': 'Afghanistan', 'AL': 'Albania', 'DZ': 'Algeria', 'AS': 'American Samoa', 'AD': 'Andorra', 'AO': 'Angola',
        'AG': 'Antigua and Barbuda', 'AR': 'Argentina', 'AM': 'Armenia', 'AU': 'Australia', 'AT': 'Austria', 'AZ': 'Azerbaijan',
        # [Truncated country list for brevity]
        'YE': 'Yemen', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
    }
    unique_ips = list(set(ip_list))  # Keep only unique IPs
    results = []
    
    for ip in unique_ips:
        if api_type == "ipinfo":
            url = f"https://ipinfo.io/{ip}/json"
        elif api_type == "ipapi":
            url = "http://ip-api.com/batch"
        elif api_type == "ipapico":
            url = f"https://ipapi.co/{ip}/json/"
        elif api_type == "abstractapi":
            url = f"https://ipgeolocation.abstractapi.com/v1/?api_key=YOUR_ABSTRACT_API_KEY&ip_address={ip}"
        elif api_type == "abuseip":
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            headers = {'Key': 'YOUR_ABUSEIP_API_KEY', 'Accept': 'application/json'}
        else:
            continue
        
        try:
            if api_type == "ipapi":
                response = requests.post(url, json=unique_ips)
            elif api_type == "abuseip":
                response = requests.get(url, headers=headers)
            else:
                response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                if api_type == "ipapi":
                    for info in data:
                        ip = info.get("query", "Unknown")
                        country = info.get("country", "Unknown")
                        provider = info.get("isp", "Unknown")
                        if info.get("status", "fail") == "fail":
                            results.append([ip, 'Грешка', 'Грешка', 'Грешка'])
                        else:
                            results.append([ip, country, provider, 'N/A'])
                elif api_type == "abuseip":
                    country = data.get('data', {}).get('countryCode', 'Unknown')
                    provider = data.get('data', {}).get('isp', 'Unknown')
                    results.append([ip, country, provider, 'N/A'])
                else:
                    country_code = data.get('country', 'Unknown') if api_type == "ipinfo" else data.get('country_name', 'Unknown')
                    country = country_mapping.get(country_code, country_code)
                    provider = data.get('org', 'Unknown')
                    is_cellular = data.get('mobile', False) if api_type == "ipinfo" else 'N/A'
                    cellular = '✓' if is_cellular else '✗'
                    results.append([ip, country, provider, cellular])
            else:
                results.append([ip, 'Грешка', 'Грешка', 'Грешка'])
        except Exception as e:
            results.append([ip, 'Грешка', 'Грешка', 'Грешка'])
    
    return results

# Function to report IP to AbuseIPDB
def report_abuseip(ip):
    api_key = "YOUR_ABUSEIP_API_KEY"
    url = "https://api.abuseipdb.com/api/v2/report"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    data = {
        'ip': ip,
        'categories': '18,22',  # Categories of abuse (e.g., DDoS attack, hacking)
        'comment': 'Reported via custom tool'
    }
    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            messagebox.showinfo("Успешно", f"IP адресът {ip} беше успешно репортнат на AbuseIPDB.")
        else:
            messagebox.showwarning("Грешка при репортване", f"Неуспешно репортване на IP адрес {ip}.")
    except Exception as e:
        messagebox.showwarning("Грешка при репортване", f"Неуспешно репортване на IP адрес {ip}.")

# Function to write results to CSV
def write_to_csv(results):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV файлове", "*.csv")])
    if file_path:
        with open(file_path, mode='w', newline='', encoding='utf-8-sig') as file:
            writer = csv.writer(file)
            writer.writerow(['IP Адрес', 'Държава', 'Доставчик', 'Мобилна мрежа'])
            writer.writerows(results)
        messagebox.showinfo("Успешно", "CSV файлът беше успешно запазен.")

# Function to calculate file hash
def calculate_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to fetch file analysis from VirusTotal
def fetch_virustotal_analysis(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": 'YOUR_VIRUSTOTAL_API_KEY'
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:  # Rate limit exceeded
            time.sleep(60)  # Wait and retry
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
        return None
    except Exception as e:
        return None

# Function to fetch file analysis from Hybrid Analysis
def fetch_hybrid_analysis(file_path):
    url = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": "YOUR_HYBRID_ANALYSIS_API_KEY"
    }
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                job_id = response.json().get('id')
                # Wait for the scan result
                time.sleep(120)  # Adjust wait time as necessary
                result_url = f"https://www.hybrid-analysis.com/api/v2/quick-scan/{job_id}"
                result_response = requests.get(result_url, headers=headers)
                if result_response.status_code == 200:
                    return result_response.json()
        return None
    except Exception as e:
        return None

# Function to fetch domain and SMTP information from MxToolbox
def fetch_mxtoolbox_info(domain, command):
    url = f"https://api.mxtoolbox.com/api/v1/lookup/{command}/{domain}"
    headers = {
        "Authorization": "7d6b24a9-c599-4376-adeb-ac40222c0fc4"
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        return None

# GUI Setup
def create_gui():
    def process_ips(api_type):
        ip_text = ip_entry.get("1.0", tk.END).strip()
        ip_list = ip_text.split()
        if ip_list:
            results = fetch_ip_info(ip_list, api_type)
            for row in result_table.get_children():
                result_table.delete(row)
            for result in results:
                result_table.insert("", tk.END, values=(result[0], result[1], result[2], result[3]))
        else:
            messagebox.showwarning("Грешка при въвеждане", "Моля, въведете поне един IP адрес.")

    def report_ip():
        selected_items = result_table.selection()
        if selected_items:
            for item in selected_items:
                ip = result_table.item(item)['values'][0]
                report_abuseip(ip)
        else:
            messagebox.showwarning("Грешка при репортване", "Няма избран IP адрес за репортване.")

    def export_csv():
        results = []
        for row in result_table.get_children():
            results.append(result_table.item(row)['values'])
        if results:
            write_to_csv(results)
        else:
            messagebox.showwarning("Грешка при експортиране", "Няма данни за експортиране.")

    def clear_results():
        for row in result_table.get_children():
            result_table.delete(row)

    def copy_results():
        results = []
        for row in result_table.get_children():
            row_values = result_table.item(row)['values']
            results.append(f"{row_values[0]} - {row_values[1]} - {row_values[2]} - {row_values[3]}")
        if results:
            root.clipboard_clear()
            root.clipboard_append("\n".join(results))
            root.update()
            messagebox.showinfo("Успешно", "Резултатите бяха копирани в клипборда.")
        else:
            messagebox.showwarning("Грешка при копиране", "Няма данни за копиране.")

    def scan_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            hash_value = calculate_file_hash(file_path)
            messagebox.showinfo("Файлът беше сканиран", f"Хеш стойност на файла: {hash_value}")
            virustotal_results = fetch_virustotal_analysis(hash_value)
            hybrid_results = fetch_hybrid_analysis(file_path)
            display_file_analysis(virustotal_results, hybrid_results)
        else:
            messagebox.showwarning("Грешка", "Моля, изберете файл за сканиране.")

    def display_file_analysis(virustotal_results, hybrid_results):
        # Clear previous results
        for row in result_table.get_children():
            result_table.delete(row)

        # Display VirusTotal results
        if virustotal_results:
            vt_detections = virustotal_results.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            for vendor, result in vt_detections.items():
                status = result.get('result', 'Неоткрито')
                result_table.insert("", tk.END, values=(f"VirusTotal - {vendor}", status))

        # Display Hybrid Analysis results
        if hybrid_results:
            ha_detections = hybrid_results.get('scanners', {})
            for scanner, result in ha_detections.items():
                status = result.get('result', 'Неоткрито')
                result_table.insert("", tk.END, values=(f"Hybrid Analysis - {scanner}", status))

        # Display contact addresses and domains if present
        if virustotal_results:
            contact_domains = virustotal_results.get('data', {}).get('attributes', {}).get('contacted_domains', [])
            contact_ips = virustotal_results.get('data', {}).get('attributes', {}).get('contacted_ips', [])
            if contact_domains:
                result_table.insert("", tk.END, values=("Контактни домейни", ", ".join(contact_domains)))
            if contact_ips:
                result_table.insert("", tk.END, values=("Контактни IP адреси", ", ".join(contact_ips)))

        if not virustotal_results and not hybrid_results:
            messagebox.showinfo("Резултат", "Няма зловредно съдържание.")

    def process_mxtoolbox():
        domain_text = domain_entry.get().strip()
        if domain_text:
            command = command_var.get()
            results = fetch_mxtoolbox_info(domain_text, command)
            if results:
                for row in result_table.get_children():
                    result_table.delete(row)
                result_table.insert("", tk.END, values=(f"MxToolbox - {command}", json.dumps(results, ensure_ascii=False)))
            else:
                messagebox.showwarning("Грешка при заявка", "Няма намерени данни за въведения домейн.")
        else:
            messagebox.showwarning("Грешка при въвеждане", "Моля, въведете домейн за проверка.")

    root = tk.Tk()
    root.title("Инструмент за SOC")
    root.geometry("1400x900")
    root.configure(bg='#2c3e50')

    style = ttk.Style()
    style.configure("Treeview",
                    background="#2c3e50",  
                    foreground="white",
                    rowheight=30,          
                    fieldbackground="#2c3e50",
                    font=('Arial', 12))   
    style.configure("Treeview.Heading",
                    background="#1abc9c",  
                    foreground="black",
                    font=('Arial', 14, 'bold'))
    style.map('Treeview', background=[('selected', '#3498db')]) 

    # Notebook for different functions
    notebook = ttk.Notebook(root)
    notebook.pack(pady=10, fill=tk.BOTH, expand=True)

    # Frame for IP Check
    frame_ip_check = ttk.Frame(notebook)
    frame_ip_check.pack(fill=tk.BOTH, expand=True)
    notebook.add(frame_ip_check, text="Проверка на IP адреси")

    # IP Entry Text Box
    ip_label = tk.Label(frame_ip_check, text="Въведете IP адреси (разделени със интервал или нов ред):", bg='#2c3e50', fg='white', font=('Arial', 12))
    ip_label.pack(pady=10)
    ip_entry = tk.Text(frame_ip_check, height=5, width=100, bg='#34495e', fg='white', insertbackground='white', font=('Arial', 10))
    ip_entry.pack(pady=5)
    
    # Right-click menu for IP entry
    def on_entry_right_click(event):
        menu = Menu(root, tearoff=0)
        menu.add_command(label="Поставяне", command=lambda: ip_entry.event_generate('<<Paste>>'))
        menu.add_command(label="Копиране", command=lambda: ip_entry.event_generate('<<Copy>>'))
        menu.add_command(label="Избиране на всичко", command=lambda: ip_entry.event_generate('<<SelectAll>>'))
        menu.post(event.x_root, event.y_root)
    ip_entry.bind("<Button-3>", on_entry_right_click)
    
    # Buttons to Process IPs
    button_frame_top = tk.Frame(frame_ip_check, bg='#2c3e50')
    button_frame_top.pack(pady=5)

    process_button_ipinfo = tk.Button(button_frame_top, text="Проверка на IP адреси (IPInfo)", command=lambda: process_ips("ipinfo"), bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
    process_button_ipinfo.grid(row=0, column=0, padx=5)

    process_button_ipapi = tk.Button(button_frame_top, text="Проверка на IP адреси (ip-api.com)", command=lambda: process_ips("ipapi"), bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
    process_button_ipapi.grid(row=0, column=1, padx=5)

    process_button_ipapico = tk.Button(button_frame_top, text="Проверка на IP адреси (ipapi.co)", command=lambda: process_ips("ipapico"), bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
    process_button_ipapico.grid(row=0, column=2, padx=5)

    process_button_abstractapi = tk.Button(button_frame_top, text="Проверка на IP адреси (Abstract API)", command=lambda: process_ips("abstractapi"), bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
    process_button_abstractapi.grid(row=0, column=3, padx=5)

    process_button_abuseip = tk.Button(button_frame_top, text="Проверка на IP адреси (AbuseIPDB)", command=lambda: process_ips("abuseip"), bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
    process_button_abuseip.grid(row=0, column=4, padx=5)

    button_frame_bottom = tk.Frame(frame_ip_check, bg='#2c3e50')
    button_frame_bottom.pack(pady=5)

    export_button = tk.Button(button_frame_bottom, text="Експортиране в CSV", command=export_csv, bg='#e67e22', fg='white', font=('Arial', 10, 'bold'))
    export_button.grid(row=0, column=0, padx=5)

    clear_button = tk.Button(button_frame_bottom, text="Изчистване на резултатите", command=clear_results, bg='#e74c3c', fg='white', font=('Arial', 10, 'bold'))
    clear_button.grid(row=0, column=1, padx=5)

    copy_button = tk.Button(button_frame_bottom, text="Копиране на резултатите", command=copy_results, bg='#f1c40f', fg='black', font=('Arial', 10, 'bold'))
    copy_button.grid(row=0, column=2, padx=5)

    result_label = tk.Label(frame_ip_check, text="Резултати:", bg='#2c3e50', fg='white', font=('Arial', 12))
    result_label.pack(pady=10)
    columns = ("IP Адрес", "Държава", "Доставчик", "Мобилна мрежа")
    result_table = ttk.Treeview(frame_ip_check, columns=columns, show='headings')

    column_settings = {
        "IP Адрес": 150,
        "Държава": 150,
        "Доставчик": 200,
        "Мобилна мрежа": 100
    }
    for col, width in column_settings.items():
        result_table.heading(col, text=col)
        result_table.column(col, anchor='center', width=width)
    
    result_table.configure(style="Treeview")
    result_table.pack(pady=10, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(result_table, orient='vertical', command=result_table.yview)
    result_table.configure(yscroll=scrollbar.set)
    scrollbar.pack(side='right', fill='y')

    def on_right_click(event):
        menu = Menu(root, tearoff=0)
        menu.add_command(label="Копиране на избраните IP адреси", command=copy_selected_ips)
        menu.add_command(label="Изтриване на избраните IP адреси", command=delete_selected_ips)
        menu.add_command(label="Репорт на избраните IP адреси", command=report_ip)
        menu.post(event.x_root, event.y_root)

    def copy_selected_ips():
        selected_items = result_table.selection()
        if selected_items:
            selected_ips = []
            for item in selected_items:
                item_values = result_table.item(item)['values']
                selected_ips.append(f"{item_values[0]} - {item_values[1]} - {item_values[2]} - {item_values[3]}")
            root.clipboard_clear()
            root.clipboard_append("\n".join(selected_ips))
            root.update()
            messagebox.showinfo("Успешно", "Избраните IP адреси бяха копирани в клипборда.")
        else:
            messagebox.showwarning("Грешка при копиране", "Няма избран IP адрес за копиране.")

    def delete_selected_ips():
        selected_items = result_table.selection()
        if selected_items:
            for item in selected_items:
                result_table.delete(item)
        else:
            messagebox.showwarning("Грешка при изтриване", "Няма избран IP адрес за изтриване.")

    result_table.bind("<Button-3>", on_right_click)

    # Frame for File, IP, and Hash Scans
    frame_file_scan = ttk.Frame(notebook)
    frame_file_scan.pack(fill=tk.BOTH, expand=True)
    notebook.add(frame_file_scan, text="Сканиране на файлове, IP и хеш стойности")

    # File scan button
    file_scan_button = tk.Button(frame_file_scan, text="Сканиране на файл", command=scan_file, bg='#e67e22', fg='white', font=('Arial', 10, 'bold'))
    file_scan_button.pack(pady=10)

    # Result Table for file analysis
    result_label = tk.Label(frame_file_scan, text="Резултати от сканиране на файл:", bg='#2c3e50', fg='white', font=('Arial', 12))
    result_label.pack(pady=10)
    columns = ("Източник", "Статус")
    result_table = ttk.Treeview(frame_file_scan, columns=columns, show='headings')
    for col in columns:
        result_table.heading(col, text=col)
        result_table.column(col, anchor='center')

    result_table.pack(pady=10, fill=tk.BOTH, expand=True)

    # Frame for Domain and SMTP Checks
    frame_domain_check = ttk.Frame(notebook)
    frame_domain_check.pack(fill=tk.BOTH, expand=True)
    notebook.add(frame_domain_check, text="Проверка на домейни и SMTP")

    domain_label = tk.Label(frame_domain_check, text="Въведете домейн или SMTP адрес:", bg='#2c3e50', fg='white', font=('Arial', 12))
    domain_label.pack(pady=10)
    domain_entry = tk.Entry(frame_domain_check, width=80, bg='#34495e', fg='white', insertbackground='white', font=('Arial', 10))
    domain_entry.pack(pady=5)

    command_var = tk.StringVar()
    command_var.set("blacklist")  # Default command
    command_options = ["blacklist", "smtp", "mx", "a", "spf", "txt", "ptr", "cname", "whois", "arin", "soa", "tcp", "http", "https", "ping", "trace", "dns"]
    command_menu = ttk.OptionMenu(frame_domain_check, command_var, *command_options)
    command_menu.pack(pady=5)

    process_domain_button = tk.Button(frame_domain_check, text="Проверка на домейн", command=process_mxtoolbox, bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
    process_domain_button.pack(pady=10)

    created_by_label = tk.Label(root, text="Created by: DSK\B0058919", bg='#2c3e50', fg='white', font=('Arial', 10, 'italic'))
    created_by_label.pack(side=tk.BOTTOM, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
