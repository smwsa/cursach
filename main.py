import customtkinter as ctk
import sqlite3
from tkinter import messagebox, ttk
import re
import hashlib


# Инициализация базы данных
def initialize_db():
    conn = sqlite3.connect('security_app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            name TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            description TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


initialize_db()


class SecurityApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Информационная Безопасность")
        self.geometry("800x600")

        self.report_windows_opened = 0
        self.current_user = None

        # Вызов окна логина
        self.show_login_window()

    def show_login_window(self):
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(expand=True)

        self.login_label = ctk.CTkLabel(self.login_frame, text="Вход")
        self.login_label.pack(pady=10)

        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Имя пользователя")
        self.username_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Пароль", show="*")
        self.password_entry.pack(pady=10)

        self.login_button = ctk.CTkButton(self.login_frame, text="Войти", command=self.login)
        self.login_button.pack(pady=10)

        self.register_button = ctk.CTkButton(self.login_frame, text="Регистрация", command=self.show_register_window)
        self.register_button.pack(pady=10)

    def show_register_window(self):
        self.login_frame.pack_forget()
        self.register_frame = ctk.CTkFrame(self)
        self.register_frame.pack(expand=True)

        self.register_label = ctk.CTkLabel(self.register_frame, text="Регистрация")
        self.register_label.pack(pady=10)

        self.reg_username_entry = ctk.CTkEntry(self.register_frame, placeholder_text="Имя пользователя")
        self.reg_username_entry.pack(pady=10)

        self.reg_password_entry = ctk.CTkEntry(self.register_frame, placeholder_text="Пароль", show="*")
        self.reg_password_entry.pack(pady=10)

        self.reg_name_entry = ctk.CTkEntry(self.register_frame, placeholder_text="Имя")
        self.reg_name_entry.pack(pady=10)

        self.reg_email_entry = ctk.CTkEntry(self.register_frame, placeholder_text="Email")
        self.reg_email_entry.pack(pady=10)

        self.register_button = ctk.CTkButton(self.register_frame, text="Зарегистрироваться", command=self.register)
        self.register_button.pack(pady=10)

        self.back_button = ctk.CTkButton(self.register_frame, text="Назад", command=self.back_to_login)
        self.back_button.pack(pady=10)

    def back_to_login(self):
        self.register_frame.pack_forget()
        self.show_login_window()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = self.hash_password(password)

        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            self.log_action(f"Успешный вход: {username}")
            self.current_user = user[0]
            self.login_frame.pack_forget()
            self.show_main_window()
        else:
            self.log_action(f"Неудачная попытка входа: {username}")
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль")

    def register(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        name = self.reg_name_entry.get()
        email = self.reg_email_entry.get()
        hashed_password = self.hash_password(password)

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.log_action(f"Ошибка регистрации: некорректный email - {email}")
            messagebox.showerror("Ошибка", "Некорректный email")
            return

        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, name, email) VALUES (?, ?, ?, ?)",
                           (username, hashed_password, name, email))
            conn.commit()
            self.log_action(f"Регистрация нового пользователя: {username}")
            messagebox.showinfo("Успешно", "Регистрация прошла успешно")
            self.back_to_login()
        except sqlite3.IntegrityError:
            self.log_action(f"Ошибка регистрации: имя пользователя уже существует - {username}")
            messagebox.showerror("Ошибка", "Имя пользователя уже существует")
        finally:
            conn.close()

    def log_action(self, message):
        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (message) VALUES (?)", (message,))
        conn.commit()
        conn.close()

    def show_main_window(self):
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(expand=True, fill="both")

        self.logs_tab = self.tabview.add("Мониторинг логов")
        self.user_management_tab = self.tabview.add("Управление доступом")
        self.reports_tab = self.tabview.add("Отчёты по безопасности")

        self.create_logs_tab()
        self.create_user_management_tab()
        self.create_reports_tab()

    def create_logs_tab(self):
        self.log_tree = ttk.Treeview(self.logs_tab, columns=("Date", "Message"), show='headings')
        self.log_tree.heading("Date", text="Дата")
        self.log_tree.heading("Message", text="Сообщение")
        self.log_tree.pack(pady=10, fill='both', expand=True)

        self.load_logs_button = ctk.CTkButton(self.logs_tab, text="Загрузить логи", command=self.load_logs)
        self.load_logs_button.pack(pady=10)

    def load_logs(self):
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT date, message FROM logs ORDER BY date DESC")
        logs = cursor.fetchall()
        conn.close()
        for log in logs:
            self.log_tree.insert('', 'end', values=log)

    def create_user_management_tab(self):
        self.user_tree = ttk.Treeview(self.user_management_tab, columns=("ID", "Username", "Name", "Email"),
                                      show='headings')
        self.user_tree.heading("ID", text="ID")
        self.user_tree.heading("Username", text="Имя пользователя")
        self.user_tree.heading("Name", text="Имя")
        self.user_tree.heading("Email", text="Email")
        self.user_tree.pack(pady=10, fill='both', expand=True)

        self.add_user_button = ctk.CTkButton(self.user_management_tab, text="Добавить пользователя",
                                             command=self.show_add_user_window)
        self.add_user_button.pack(pady=10)

        self.remove_user_button = ctk.CTkButton(self.user_management_tab, text="Удалить пользователя",
                                                command=self.remove_user)
        self.remove_user_button.pack(pady=10)

        self.load_users()

    def load_users(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, name, email FROM users")
        users = cursor.fetchall()
        conn.close()
        for user in users:
            self.user_tree.insert('', 'end', values=user)

    def show_add_user_window(self):
        if hasattr(self, 'add_user_window') and self.add_user_window.winfo_exists():
            return

        self.add_user_window = ctk.CTkToplevel(self)
        self.add_user_window.title("Добавить пользователя")
        self.add_user_window.geometry("600x450")
        self.add_user_window.grab_set()

        self.add_username_entry = ctk.CTkEntry(self.add_user_window, placeholder_text="Имя пользователя")
        self.add_username_entry.pack(pady=10)

        self.add_password_entry = ctk.CTkEntry(self.add_user_window, placeholder_text="Пароль", show="*")
        self.add_password_entry.pack(pady=10)

        self.add_name_entry = ctk.CTkEntry(self.add_user_window, placeholder_text="Имя")
        self.add_name_entry.pack(pady=10)

        self.add_email_entry = ctk.CTkEntry(self.add_user_window, placeholder_text="Email")
        self.add_email_entry.pack(pady=10)

        self.save_user_button = ctk.CTkButton(self.add_user_window, text="Сохранить", command=self.add_user)
        self.save_user_button.pack(pady=10)

    def add_user(self):
        username = self.add_username_entry.get()
        password = self.add_password_entry.get()
        name = self.add_name_entry.get()
        email = self.add_email_entry.get()
        hashed_password = self.hash_password(password)

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Ошибка", "Некорректный email")
            return

        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, name, email) VALUES (?, ?, ?, ?)",
                           (username, hashed_password, name, email))
            conn.commit()
            self.log_action(f"Добавлен новый пользователь: {username}")
            self.load_users()
            messagebox.showinfo("Успешно", "Пользователь добавлен")
            self.add_user_window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Ошибка", "Имя пользователя уже существует")
        finally:
            conn.close()

    def remove_user(self):
        selected_item = self.user_tree.selection()
        if not selected_item:
            messagebox.showerror("Ошибка", "Выберите пользователя для удаления")
            return

        user_id = self.user_tree.item(selected_item)["values"][0]

        # Проверяем, не пытаемся ли удалить текущего пользователя
        if user_id == self.current_user:
            messagebox.showerror("Ошибка", "Вы не можете удалить пользователя, под которым зашли в программу")
            return

        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        self.log_action(f"Удалён пользователь ID: {user_id}")
        self.load_users()
        messagebox.showinfo("Успешно", "Пользователь удалён")

    def create_reports_tab(self):
        self.report_tree = ttk.Treeview(self.reports_tab, columns=("ID", "Category", "Date"), show='headings')
        self.report_tree.heading("ID", text="ID")
        self.report_tree.heading("Category", text="Категория")
        self.report_tree.heading("Date", text="Дата")
        self.report_tree.pack(pady=10, fill='both', expand=True)

        self.add_report_button = ctk.CTkButton(self.reports_tab, text="Добавить отчёт", command=self.show_add_report_window)
        self.add_report_button.pack(pady=10)

        self.remove_report_button = ctk.CTkButton(self.reports_tab, text="Удалить отчёт", command=self.remove_report)
        self.remove_report_button.pack(pady=10)

        self.view_report_button = ctk.CTkButton(self.reports_tab, text="Просмотреть отчёт", command=self.view_report)
        self.view_report_button.pack(pady=10)

        self.load_reports()

    def load_reports(self):
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)
        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, category, date FROM reports")
        reports = cursor.fetchall()
        conn.close()
        for report in reports:
            self.report_tree.insert('', 'end', values=report)

    def show_add_report_window(self):
        if hasattr(self, 'add_report_window') and self.add_report_window.winfo_exists():
            return

        self.add_report_window = ctk.CTkToplevel(self)
        self.add_report_window.title("Добавить отчёт")
        self.add_report_window.geometry("400x300")
        self.add_report_window.grab_set()

        self.add_category_entry = ctk.CTkEntry(self.add_report_window, placeholder_text="Категория")
        self.add_category_entry.pack(pady=10)

        self.add_description_text = ctk.CTkTextbox(self.add_report_window, width=300, height=150)
        self.add_description_text.pack(pady=10)

        self.save_report_button = ctk.CTkButton(self.add_report_window, text="Сохранить", command=self.add_report)
        self.save_report_button.pack(pady=10)

    def add_report(self):
        category = self.add_category_entry.get()
        description = self.add_description_text.get("1.0", ctk.END).strip()

        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO reports (category, description) VALUES (?, ?)", (category, description))
        conn.commit()
        conn.close()
        self.log_action(f"Добавлен новый отчёт: {category}")
        self.load_reports()
        messagebox.showinfo("Успешно", "Отчёт добавлен")
        self.add_report_window.destroy()

    def remove_report(self):
        selected_item = self.report_tree.selection()
        if not selected_item:
            messagebox.showerror("Ошибка", "Выберите отчёт для удаления")
            return
        report_id = self.report_tree.item(selected_item)["values"][0]
        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM reports WHERE id=?", (report_id,))
        conn.commit()
        conn.close()
        self.log_action(f"Удалён отчёт ID: {report_id}")
        self.load_reports()
        messagebox.showinfo("Успешно", "Отчёт удалён")

    def view_report(self):
        selected_item = self.report_tree.selection()
        if not selected_item:
            messagebox.showerror("Ошибка", "Выберите отчёт для просмотра")
            return
        report_id = self.report_tree.item(selected_item)["values"][0]
        conn = sqlite3.connect('security_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports WHERE id=?", (report_id,))
        report = cursor.fetchone()
        conn.close()

        if report:
            self.view_report_window = ctk.CTkToplevel(self)
            self.view_report_window.title("Просмотр отчёта")
            self.view_report_window.geometry("400x400")

            report_text = f"ID: {report[0]}\nКатегория: {report[1]}\nДата: {report[3]}\n\nОписание:\n{report[2]}"
            self.view_report_text = ctk.CTkTextbox(self.view_report_window, width=350, height=300)
            self.view_report_text.pack(pady=10)
            self.view_report_text.insert(ctk.END, report_text)
            self.view_report_text.configure(state='disabled')


if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()