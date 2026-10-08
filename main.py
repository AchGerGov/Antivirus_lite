import os
import hashlib
import pefile
import json
import socket
import threading
import time
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import warnings
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from PIL import Image, ImageTk
import requests
import zipfile
import io
import sys
import psutil
import tempfile

warnings.filterwarnings('ignore')

class GuardianShieldPro:
    def __init__(self, root):
        self.root = root
        self.root.title("GuardianShield Pro")
        self.root.geometry("1000x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Инициализация защиты
        self.malware_db = self.load_malware_db()
        self.model = self.train_ml_model()
        self.running = True
        self.suspicious_activities = []
        self.quarantine_dir = os.path.join(tempfile.gettempdir(), "GuardianShield_Quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Создание GUI
        self.create_gui()
        
        # Запуск фоновых процессов
        self.start_background_tasks()
        
        # Проверка обновлений
        self.check_for_updates()

    def create_gui(self):
        """Создание графического интерфейса"""
        # Стили
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TButton", padding=6, font=('Helvetica', 10))
        style.configure("TLabel", background="#f0f0f0", font=('Helvetica', 10))
        
        # Главный контейнер
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Панель управления
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Кнопки управления
        ttk.Button(control_frame, text="Сканировать файл", command=self.scan_file_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Сканировать папку", command=self.scan_folder_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Быстрое сканирование", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Полное сканирование", command=self.full_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Карантин", command=self.show_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Настройки", command=self.show_settings).pack(side=tk.LEFT, padx=5)
        
        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Вкладки
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Вкладка сканирования
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text="Сканирование")
        
        self.scan_results = ttk.Treeview(scan_frame, columns=("file", "status", "details"), show="headings")
        self.scan_results.heading("file", text="Файл")
        self.scan_results.heading("status", text="Статус")
        self.scan_results.heading("details", text="Детали")
        self.scan_results.column("file", width=400)
        self.scan_results.column("status", width=150)
        self.scan_results.column("details", width=300)
        
        scrollbar = ttk.Scrollbar(scan_frame, orient="vertical", command=self.scan_results.yview)
        self.scan_results.configure(yscrollcommand=scrollbar.set)
        
        self.scan_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Вкладка мониторинга
        monitor_frame = ttk.Frame(notebook)
        notebook.add(monitor_frame, text="Мониторинг")
        
        self.monitor_log = scrolledtext.ScrolledText(monitor_frame, wrap=tk.WORD, width=100, height=25)
        self.monitor_log.pack(fill=tk.BOTH, expand=True)
        
        # Вкладка статистики
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="Статистика")
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD, width=100, height=25)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Обновление интерфейса
        self.update_stats()

    def start_background_tasks(self):
        """Запуск фоновых задач"""
        self.realtime_thread = threading.Thread(target=self.realtime_monitor, daemon=True)
        self.realtime_thread.start()
        
        self.network_thread = threading.Thread(target=self.network_monitor, daemon=True)
        self.network_thread.start()
        
        self.update_thread = threading.Thread(target=self.update_checker, daemon=True)
        self.update_thread.start()

    def update_checker(self):
        """Проверка обновлений в фоне"""
        while self.running:
            time.sleep(3600)  # Проверка каждый час
            self.check_for_updates(silent=True)

    def check_for_updates(self, silent=False):
        """Проверка обновлений сигнатур"""
        try:
            if not silent:
                self.status_var.set("Проверка обновлений...")
            
            response = requests.get("https://example.com/malware_db.json", timeout=10)
            remote_db = response.json()
            
            if len(remote_db['hashes']) > len(self.malware_db['hashes']):
                self.malware_db = remote_db
                self.save_malware_db()
                if not silent:
                    messagebox.showinfo("Обновление", "База сигнатур успешно обновлена")
                    self.status_var.set("База сигнатур обновлена")
            elif not silent:
                self.status_var.set("Обновления не найдены")
        
        except Exception as e:
            if not silent:
                messagebox.showerror("Ошибка", f"Не удалось проверить обновления: {str(e)}")
                self.status_var.set("Ошибка проверки обновлений")

    def load_malware_db(self):
        """Загрузка базы сигнатур"""
        try:
            with open('malware_db.json') as f:
                return json.load(f)
        except:
            # База по умолчанию
            return {
                'hashes': ['a1b2c3d4e5f6...'],  # Пример хеша
                'rules': [{'name': 'Suspicious PE imports', 'pattern': 'CreateProcess'}],
                'trusted_extensions': ['.txt', '.pdf', '.doc', '.jpg', '.png']
            }

    def save_malware_db(self):
        """Сохранение базы сигнатур"""
        with open('malware_db.json', 'w') as f:
            json.dump(self.malware_db, f)

    def train_ml_model(self):
        """Обучение модели машинного обучения"""
        # В реальной системе здесь должна быть загрузка реальных данных
        X = np.random.rand(100, 10)
        model = IsolationForest(contamination=0.05, random_state=42)  # Уменьшили уровень contamination
        model.fit(X)
        return model

    def is_pe_file(self, file_path):
        """Проверка, является ли файл PE-файлом"""
        try:
            with open(file_path, 'rb') as f:
                return f.read(2) == b'MZ'
        except:
            return False

    def scan_file(self, file_path):
        """Улучшенная проверка файла с учетом типа файла"""
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # 1. Проверка по хешу (для всех файлов)
            file_hash = self.get_file_hash(file_path)
            if file_hash in self.malware_db['hashes']:
                return "MALWARE", "Known malicious hash"
            
            # 2. Для доверенных расширений только проверка хеша
            if file_ext in self.malware_db.get('trusted_extensions', []):
                return "CLEAN", "Trusted file type"
            
            # 3. Для PE-файлов полная проверка
            if self.is_pe_file(file_path):
                pe_result = self.analyze_pe(file_path)
                if pe_result:
                    return "MALWARE", pe_result
                
                # ML-анализ только для PE-файлов
                if self.ml_analysis(file_path):
                    return "SUSPICIOUS", "AI Detection (verify manually)"
            
            # 4. Для остальных файлов только проверка энтропии
            entropy = self.calculate_entropy(file_path)
            if entropy > 7.5:  # Высокая энтропия может указывать на шифрование
                return "SUSPICIOUS", f"High entropy ({entropy:.2f}) - possible packed/encrypted content"
            
            return "CLEAN", "No threats detected"
        
        except Exception as e:
            return "ERROR", str(e)

    def get_file_hash(self, file_path):
        """Вычисление хеша файла"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def analyze_pe(self, file_path):
        """Анализ PE-файлов"""
        try:
            pe = pefile.PE(file_path)
            results = []
            
            # Проверка подозрительных импортов
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode().lower()
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode().lower()
                            suspicious_imports = {'createprocess', 'winexec', 'virtualalloc', 'createthread'}
                            if any(susp in imp_name for susp in suspicious_imports):
                                results.append(f"Suspicious import: {dll}!{imp_name}")
            
            # Проверка подозрительных секций
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                if section.Characteristics & 0xE0000020:  # EXECUTE, READ, WRITE
                    results.append(f"Suspicious section: {section_name} (RWX)")
            
            # Проверка отсутствующих стандартных секций
            standard_sections = {'.text', '.data', '.rdata', '.rsrc'}
            present_sections = {s.Name.decode().rstrip('\x00').lower() for s in pe.sections}
            if not standard_sections.issubset(present_sections):
                results.append("Missing standard sections")
            
            return "; ".join(results) if results else False
        
        except pefile.PEFormatError:
            return False
        except Exception as e:
            return f"PE analysis error: {str(e)}"

    def ml_analysis(self, file_path):
        """Анализ с помощью ML только для PE-файлов"""
        try:
            features = self.extract_file_features(file_path)
            return self.model.predict([features])[0] == -1
        except:
            return False

    def extract_file_features(self, file_path):
        """Извлечение признаков файла для ML (ИСПРАВЛЕННАЯ ВЕРСИЯ)"""
        try:
            size = os.path.getsize(file_path)
            entropy = self.calculate_entropy(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            
            # Более осмысленные признаки для PE-файлов
            features = np.array([
                size,
                entropy,
                ext in ('.exe', '.dll', '.sys'),  # Исполняемые файлы
                ext in ('.pdf', '.doc', '.xls'),   # Документы
                ext in ('.txt', '.log', '.csv'),   # Текстовые файлы
                len(open(file_path, 'rb').read(1000)),  # Первые 1000 байт
                os.path.basename(file_path).count(' '),  # Подозрительные пробелы в имени
                sum(c < 32 or c > 126 for c in open(file_path, 'rb').read(1000)),  # Непечатаемые символы
                size % 100,
                self.is_pe_file(file_path)  # Является ли PE-файлом
            ])
            return features
        except:
            return np.zeros(10)

    def calculate_entropy(self, file_path):
        """Вычисление энтропии файла"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            entropy = 0.0
            counts = np.zeros(256)
            
            for byte in data:
                counts[byte] += 1
            
            counts = counts[counts > 0] / len(data)
            entropy = -np.sum(counts * np.log2(counts))
            
            return entropy
        except:
            return 0.0

    def realtime_monitor(self):
        """Улучшенный мониторинг файловой системы"""
        watch_dirs = ['C:\\Windows\\System32', os.path.expanduser('~')]
        known_good_files = set()
        
        while self.running:
            try:
                for directory in watch_dirs:
                    for root, _, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Пропускаем уже проверенные файлы
                            if file_path in known_good_files:
                                continue
                            
                            result, details = self.scan_file(file_path)
                            
                            if result == "CLEAN":
                                known_good_files.add(file_path)
                                continue
                            
                            if "MALWARE" in result:
                                self.log_activity(f"Обнаружен вредоносный файл: {file_path} - {details}")
                                self.add_to_scan_results(file_path, result, details)
                                
                                if messagebox.askyesno("Подтверждение", 
                                                    f"Обнаружен вредоносный файл:\n{file_path}\n\nПоместить в карантин?"):
                                    self.quarantine_file(file_path)
                            
                            elif "SUSPICIOUS" in result:
                                self.log_activity(f"Подозрительный файл: {file_path} - {details}")
                                self.add_to_scan_results(file_path, result, details)
                
                time.sleep(60)  # Проверка каждую минуту
            
            except Exception as e:
                self.log_activity(f"Ошибка мониторинга: {str(e)}")
                time.sleep(10)

    def network_monitor(self):
        """Мониторинг сетевой активности"""
        while self.running:
            try:
                # Мониторинг подозрительных соединений
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        ip, port = conn.raddr
                        if port in [6666, 6667, 7777, 31337]:  # Подозрительные порты
                            self.log_activity(f"Подозрительное соединение: {ip}:{port}")
                
                time.sleep(10)
            
            except Exception as e:
                self.log_activity(f"Ошибка сетевого мониторинга: {str(e)}")
                time.sleep(10)

    def quarantine_file(self, file_path):
        """Перемещение файла в карантин"""
        try:
            filename = os.path.basename(file_path)
            dest = os.path.join(self.quarantine_dir, filename)
            
            # Уникальное имя файла, если уже существует
            counter = 1
            while os.path.exists(dest):
                name, ext = os.path.splitext(filename)
                dest = os.path.join(self.quarantine_dir, f"{name}_{counter}{ext}")
                counter += 1
            
            os.rename(file_path, dest)
            self.log_activity(f"Файл помещен в карантин: {filename}")
        
        except Exception as e:
            self.log_activity(f"Ошибка карантина: {str(e)}")

    def log_activity(self, message):
        """Логирование событий"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.suspicious_activities.append(log_entry)
        
        # Запись в файл
        with open("guardianshield.log", "a", encoding='utf-8') as f:
            f.write(log_entry + "\n")
        
        # Обновление интерфейса
        self.root.after(0, self.update_monitor_log, log_entry)

    def update_monitor_log(self, message):
        """Обновление лога мониторинга"""
        self.monitor_log.insert(tk.END, message + "\n")
        self.monitor_log.see(tk.END)

    def update_stats(self):
        """Обновление статистики"""
        stats = [
            f"GuardianShield Pro - Статистика\n{'='*30}",
            f"Всего проверок: {len(self.suspicious_activities)}",
            f"Обнаружено угроз: {len([x for x in self.suspicious_activities if 'MALWARE' in x])}",
            f"Файлов в карантине: {len(os.listdir(self.quarantine_dir)) if os.path.exists(self.quarantine_dir) else 0}",
            f"\nПоследние события:"
        ]
        
        last_events = self.suspicious_activities[-5:] if len(self.suspicious_activities) > 5 else self.suspicious_activities
        stats.extend(last_events)
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, "\n".join(stats))
        
        # Обновление каждые 5 секунд
        self.root.after(5000, self.update_stats)
#--------------------------------------------------------------------------------------------------------
    def scan_file_dialog(self):
        """Диалог выбора файла для сканирования"""
        file_path = filedialog.askopenfilename(title="Выберите файл для сканирования")
        if file_path:
            self.status_var.set(f"Сканирование файла: {os.path.basename(file_path)}")
            self.scan_file_with_ui(file_path)

    def scan_folder_dialog(self):
        """Диалог выбора папки для сканирования"""
        folder_path = filedialog.askdirectory(title="Выберите папку для сканирования")
        if folder_path:
            self.status_var.set(f"Сканирование папки: {os.path.basename(folder_path)}")
            threading.Thread(target=self.scan_folder, args=(folder_path,)).start()

    def scan_file_with_ui(self, file_path):
        """Сканирование файла с обновлением интерфейса"""
        try:
            result, details = self.scan_file(file_path)
            self.add_to_scan_results(file_path, result, details)
            
            if "MALWARE" in result:
                if messagebox.askyesno("Обнаружена угроза", 
                                     f"Файл {os.path.basename(file_path)} содержит вредоносный код!\n\nПоместить в карантин?"):
                    self.quarantine_file(file_path)
            elif "SUSPICIOUS" in result:
                messagebox.showwarning("Подозрительный файл", 
                                     f"Файл {os.path.basename(file_path)} выглядит подозрительно.\n\nДетали: {details}")
            else:
                messagebox.showinfo("Сканирование завершено", "Угроз не обнаружено")
            
            self.status_var.set("Сканирование завершено")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось просканировать файл: {str(e)}")
            self.status_var.set("Ошибка сканирования")

    def add_to_scan_results(self, file_path, status, details):
        """Добавление результата в таблицу"""
        self.scan_results.insert("", tk.END, values=(os.path.basename(file_path), status, details))

    def scan_folder(self, folder_path):
        """Сканирование папки"""
        try:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    result, details = self.scan_file(file_path)
                    
                    self.root.after(0, self.add_to_scan_results, file_path, result, details)
                    
                    if "MALWARE" in result:
                        self.quarantine_file(file_path)
                        self.root.after(0, self.log_activity, f"Обнаружен вредоносный файл: {file_path} - {details}")
            
            self.root.after(0, lambda: self.status_var.set("Сканирование папки завершено"))
            self.root.after(0, lambda: messagebox.showinfo("Готово", "Сканирование папки завершено"))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Не удалось просканировать папку: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Ошибка сканирования папки"))

    def quick_scan(self):
        """Быстрое сканирование системных папок"""
        self.status_var.set("Выполняется быстрое сканирование...")
        threading.Thread(target=self._quick_scan).start()

    def _quick_scan(self):
        """Фоновая задача быстрого сканирования"""
        try:
            sys_folders = [
                os.environ['WINDIR'] + '\\System32',
                os.environ['APPDATA'],
                os.environ['PROGRAMFILES'],
                os.path.expanduser('~') + '\\Downloads'
            ]
            
            for folder in sys_folders:
                if os.path.exists(folder):
                    self.scan_folder(folder)
            
            self.root.after(0, lambda: self.status_var.set("Быстрое сканирование завершено"))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка быстрого сканирования: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Ошибка быстрого сканирования"))

    def full_scan(self):
        """Полное сканирование всех дисков"""
        if messagebox.askyesno("Подтверждение", "Полное сканирование может занять много времени. Продолжить?"):
            self.status_var.set("Выполняется полное сканирование...")
            threading.Thread(target=self._full_scan).start()

    def _full_scan(self):
        """Фоновая задача полного сканирования"""
        try:
            drives = ['%s:\\' % d for d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists('%s:' % d)]
            
            for drive in drives:
                self.root.after(0, lambda: self.status_var.set(f"Сканирование диска {drive}"))
                self.scan_folder(drive)
            
            self.root.after(0, lambda: self.status_var.set("Полное сканирование завершено"))
            self.root.after(0, lambda: messagebox.showinfo("Готово", "Полное сканирование завершено"))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка полного сканирования: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Ошибка полного сканирования"))
#------------------------------------------------------------------------------------------
    def show_quarantine(self):
        """Показать содержимое карантина"""
        quarantine_window = tk.Toplevel(self.root)
        quarantine_window.title("Карантин")
        quarantine_window.geometry("600x400")
        
        frame = ttk.Frame(quarantine_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        quarantine_list = tk.Listbox(frame, yscrollcommand=scrollbar.set)
        quarantine_list.pack(fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=quarantine_list.yview)
        
        try:
            files = os.listdir(self.quarantine_dir)
            for file in files:
                quarantine_list.insert(tk.END, file)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить карантин: {str(e)}")

    def show_settings(self):
        """Окно настроек"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Настройки")
        settings_window.geometry("400x300")
        
        ttk.Label(settings_window, text="Настройки GuardianShield Pro").pack(pady=10)
        
        # Пример настройки
        self.auto_update_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_window, text="Автоматически проверять обновления", 
                       variable=self.auto_update_var).pack(pady=5, anchor=tk.W)
        
        ttk.Button(settings_window, text="Проверить обновления сейчас", 
                  command=self.check_for_updates).pack(pady=10)
        
        ttk.Button(settings_window, text="Экспорт логов", 
                  command=self.export_logs).pack(pady=10)

    def export_logs(self):
        """Экспорт логов в файл"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")],
            title="Сохранить логи как"
        )
        
        if file_path:
            try:
                with open("guardianshield.log", "r", encoding='utf-8') as src, \
                     open(file_path, "w", encoding='utf-8') as dst:
                    dst.write(src.read())
                
                messagebox.showinfo("Успех", "Логи успешно экспортированы")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось экспортировать логи: {str(e)}")

    def on_close(self):
        """Обработчик закрытия окна"""
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите закрыть GuardianShield Pro?"):
            self.running = False
            self.root.destroy()
            sys.exit()

if __name__ == "__main__":
    root = tk.Tk()
    app = GuardianShieldPro(root)
    root.mainloop()
