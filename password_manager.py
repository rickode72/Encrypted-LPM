import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import sqlite3
import ctypes
import base64
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Abilita DPI awareness su Windows per rendering nitido a 1920x1080
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

def deriva_chiave_da_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def chiedi_master_password():
    """Mostra un dialog per la master password. Restituisce la Fernet key decifrata o chiude l'app."""
    if not os.path.exists("secret.key"):
        root_tmp = tk.Tk()
        root_tmp.withdraw()
        messagebox.showerror(
            "Errore",
            "File secret.key non trovato.\nEsegui prima genera_chiave.py per creare la chiave protetta."
        )
        root_tmp.destroy()
        sys.exit(1)

    with open("secret.key", "rb") as f:
        dati = f.read()

    salt = dati[:16]
    fernet_key_cifrata = dati[16:]

    # Finestra di login
    login = tk.Tk()
    login.title("Login - Password Manager")
    login.geometry("420x180")
    login.resizable(False, False)

    font_label = ("Segoe UI", 12)
    font_entry = ("Segoe UI", 12)
    font_button = ("Segoe UI", 11, "bold")

    tk.Label(login, text="Inserisci la Master Password:", font=font_label).pack(pady=(20, 5))
    entry_master = tk.Entry(login, font=font_entry, show="*", width=30)
    entry_master.pack(pady=5)
    entry_master.focus_set()

    risultato = {}

    def tentativo(event=None):
        master = entry_master.get()
        if not master:
            return
        try:
            chiave_derivata = deriva_chiave_da_password(master, salt)
            cipher_master = Fernet(chiave_derivata)
            fernet_key = cipher_master.decrypt(fernet_key_cifrata)
            risultato["key"] = fernet_key
            login.destroy()
        except (InvalidToken, Exception):
            messagebox.showerror("Errore", "Master password errata.", parent=login)
            entry_master.delete(0, tk.END)
            entry_master.focus_set()

    def on_chiudi():
        login.destroy()
        sys.exit(0)

    login.bind("<Return>", tentativo)
    login.protocol("WM_DELETE_WINDOW", on_chiudi)

    tk.Button(login, text="Sblocca", command=tentativo, bg="#2196F3", fg="white", font=font_button).pack(pady=10)

    login.mainloop()

    if "key" not in risultato:
        sys.exit(0)

    return risultato["key"]

KEY = chiedi_master_password()
cipher = Fernet(KEY)

def init_db():
    conn = sqlite3.connect("password.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credenziali(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sito TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def salva_password(sito, username, password):
    password_cifrata = cipher.encrypt(password.encode()).decode()
    conn = sqlite3.connect("password.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO credenziali (sito, username, password) VALUES (?, ?, ?)", 
        (sito, username, password_cifrata)
    )
    conn.commit()
    conn.close()

def leggi_passwords():
    conn = sqlite3.connect("password.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, sito, username, password FROM credenziali")
    righe = cursor.fetchall()
    conn.close()
    risultati = []
    for riga in righe:
        id_, sito, username, pwd_cifrata = riga
        pwd_decifrata = cipher.decrypt(pwd_cifrata.encode()).decode()
        risultati.append((id_, sito, username, pwd_decifrata))
    return risultati

def cancella_password(id_):
    conn = sqlite3.connect("password.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM credenziali WHERE id = ?", (id_,))
    conn.commit()
    # Rinumera gli ID in modo sequenziale partendo da 1
    cursor.execute("SELECT id FROM credenziali ORDER BY id")
    righe = cursor.fetchall()
    for nuovo_id, (vecchio_id,) in enumerate(righe, start=1):
        if vecchio_id != nuovo_id:
            cursor.execute("UPDATE credenziali SET id = ? WHERE id = ?", (nuovo_id, vecchio_id))
    # Resetta il contatore AUTOINCREMENT
    cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'credenziali'")
    if righe:
        cursor.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('credenziali', ?)", (len(righe),))
    conn.commit()
    conn.close()

def modifica_credenziale(id_, sito, username, password):
    password_cifrata = cipher.encrypt(password.encode()).decode()
    conn = sqlite3.connect("password.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE credenziali SET sito = ?, username = ?, password = ? WHERE id = ?",
        (sito, username, password_cifrata, id_)
    )
    conn.commit()
    conn.close()

def esporta_db_leggibile():
    conn = sqlite3.connect("password.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, sito, username, password FROM credenziali")
    righe = cursor.fetchall()
    conn.close()
    with open("password_leggibile.txt", "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("  PASSWORD MANAGER - DATABASE CREDENZIALI\n")
        f.write("=" * 80 + "\n\n")
        if not righe:
            f.write("  (nessuna credenziale salvata)\n")
        for riga in righe:
            id_, sito, username, pwd_cifrata = riga
            f.write(f"  ID:        {id_}\n")
            f.write(f"  Sito:      {sito}\n")
            f.write(f"  Username:  {username}\n")
            f.write(f"  Password:  {pwd_cifrata}\n")
            f.write("-" * 80 + "\n")

def avvia_app():
    root = tk.Tk()
    root.title("Password Manager Locale")
    root.geometry("1280x720")
    root.minsize(800, 500)

    # --- Stile e font scalati per rendering nitido ---
    font_label = ("Segoe UI", 11)
    font_entry = ("Segoe UI", 11)
    font_button = ("Segoe UI", 10, "bold")
    font_tabella = ("Segoe UI", 11)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", font=font_tabella, rowheight=30)
    style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"))

    # --- Layout principale con grid responsivo ---
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)  # la tabella si espande

    # --- Frame in alto: form per aggiungere ---
    frame_input = tk.Frame(root, pady=10)
    frame_input.grid(row=0, column=0, sticky="ew", padx=15, pady=(10, 0))
    # Le colonne delle Entry si espandono uniformemente
    frame_input.columnconfigure(1, weight=1)
    frame_input.columnconfigure(3, weight=1)
    frame_input.columnconfigure(5, weight=1)

    tk.Label(frame_input, text="Sito:", font=font_label).grid(row=0, column=0, padx=(5, 2), sticky="e")
    entry_sito = tk.Entry(frame_input, font=font_entry)
    entry_sito.grid(row=0, column=1, padx=5, sticky="ew")

    tk.Label(frame_input, text="Username:", font=font_label).grid(row=0, column=2, padx=(10, 2), sticky="e")
    entry_user = tk.Entry(frame_input, font=font_entry)
    entry_user.grid(row=0, column=3, padx=5, sticky="ew")

    tk.Label(frame_input, text="Password:", font=font_label).grid(row=0, column=4, padx=(10, 2), sticky="e")
    entry_pwd = tk.Entry(frame_input, font=font_entry, show="*")
    entry_pwd.grid(row=0, column=5, padx=5, sticky="ew")

    def toggle_password():
        if entry_pwd.cget("show") == "*":
            entry_pwd.config(show="")
            btn_mostra.config(text="Nascondi")
        else:
            entry_pwd.config(show="*")
            btn_mostra.config(text="Mostra")

    btn_mostra = tk.Button(frame_input, text="Mostra", command=toggle_password, font=font_button, width=8)
    btn_mostra.grid(row=0, column=6, padx=2)

    def on_salva(event=None):
        sito = entry_sito.get().strip()
        user = entry_user.get().strip()
        pwd = entry_pwd.get().strip()
        if not sito or not user or not pwd:
            messagebox.showwarning("Attenzione", "Compila tutti i campi!")
            return
        salva_password(sito, user, pwd)
        entry_sito.delete(0, tk.END)
        entry_user.delete(0, tk.END)
        entry_pwd.delete(0, tk.END)
        aggiorna_tabella()
        esporta_db_leggibile()

    btn_salva = tk.Button(frame_input, text="Salva", command=on_salva, bg="green", fg="white", font=font_button)
    btn_salva.grid(row=0, column=7, padx=10)

    # Binding tasto Enter solo sui campi del form di inserimento
    entry_sito.bind("<Return>", on_salva)
    entry_user.bind("<Return>", on_salva)
    entry_pwd.bind("<Return>", on_salva)

    # --- Tabella per visualizzare le voci ---
    frame_tabella = tk.Frame(root)
    frame_tabella.grid(row=1, column=0, sticky="nsew", padx=15, pady=10)
    frame_tabella.columnconfigure(0, weight=1)
    frame_tabella.rowconfigure(0, weight=1)

    colonne = ("ID", "Sito", "Username", "Password")
    tabella = ttk.Treeview(frame_tabella, columns=colonne, show="headings")
    tabella.column("ID", width=60, minwidth=40, stretch=False)
    tabella.column("Sito", width=250, minwidth=100)
    tabella.column("Username", width=250, minwidth=100)
    tabella.column("Password", width=300, minwidth=100)
    for col in colonne:
        tabella.heading(col, text=col)

    scrollbar = ttk.Scrollbar(frame_tabella, orient="vertical", command=tabella.yview)
    tabella.configure(yscrollcommand=scrollbar.set)
    tabella.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")

    # --- Bottone cancella in basso ---
    def on_cancella():
        selezione = tabella.selection()
        if not selezione:
            messagebox.showwarning("Attenzione", "Seleziona una voce da cancellare.")
            return
        item = tabella.item(selezione[0])
        id_ = item["values"][0]
        if messagebox.askyesno("Conferma", "Sei sicuro di voler cancellare questa voce?"):
            cancella_password(id_)
            nascondi_popup()
            aggiorna_tabella()
            esporta_db_leggibile()

    def on_modifica():
        selezione = tabella.selection()
        if not selezione:
            messagebox.showwarning("Attenzione", "Seleziona una voce da modificare.")
            return
        item = tabella.item(selezione[0])
        id_ = item["values"][0]
        vecchio_sito = str(item["values"][1])
        vecchio_user = str(item["values"][2])
        vecchia_pwd = str(item["values"][3])

        # Finestra di modifica
        win = tk.Toplevel(root)
        win.title("Modifica credenziale")
        win.geometry("450x220")
        win.resizable(False, False)
        win.grab_set()

        tk.Label(win, text="Sito:", font=font_label).grid(row=0, column=0, padx=10, pady=(15, 5), sticky="e")
        e_sito = tk.Entry(win, font=font_entry, width=30)
        e_sito.grid(row=0, column=1, padx=10, pady=(15, 5))
        e_sito.insert(0, vecchio_sito)

        tk.Label(win, text="Username:", font=font_label).grid(row=1, column=0, padx=10, pady=5, sticky="e")
        e_user = tk.Entry(win, font=font_entry, width=30)
        e_user.grid(row=1, column=1, padx=10, pady=5)
        e_user.insert(0, vecchio_user)

        tk.Label(win, text="Password:", font=font_label).grid(row=2, column=0, padx=10, pady=5, sticky="e")
        e_pwd = tk.Entry(win, font=font_entry, width=30)
        e_pwd.grid(row=2, column=1, padx=10, pady=5)
        e_pwd.insert(0, vecchia_pwd)

        def salva_modifica(event=None):
            nuovo_sito = e_sito.get().strip()
            nuovo_user = e_user.get().strip()
            nuova_pwd = e_pwd.get().strip()
            if not nuovo_sito or not nuovo_user or not nuova_pwd:
                messagebox.showwarning("Attenzione", "Compila tutti i campi!", parent=win)
                return
            modifica_credenziale(id_, nuovo_sito, nuovo_user, nuova_pwd)
            win.destroy()
            nascondi_popup()
            aggiorna_tabella()
            esporta_db_leggibile()

        win.bind("<Return>", salva_modifica)
        tk.Button(win, text="Salva modifiche", command=salva_modifica, bg="#2196F3", fg="white", font=font_button).grid(row=3, column=0, columnspan=2, pady=15)

    # --- Barra di ricerca ---
    frame_cerca = tk.Frame(root)
    frame_cerca.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 5))

    tk.Label(frame_cerca, text="Cerca sito:", font=font_label).pack(side="left", padx=(5, 5))
    entry_cerca = tk.Entry(frame_cerca, font=font_entry, width=30)
    entry_cerca.pack(side="left", padx=5)

    def esegui_ricerca(event=None):
        testo = entry_cerca.get().strip().lower()
        # Deseleziona tutto e rimuovi tag evidenziazione
        tabella.selection_remove(*tabella.selection())
        tabella.tag_configure("evidenziato", background="")
        for row in tabella.get_children():
            tabella.item(row, tags=())
        if not testo:
            return
        for row in tabella.get_children():
            valori = tabella.item(row)["values"]
            sito = str(valori[1]).lower()
            if testo in sito:
                tabella.item(row, tags=("evidenziato",))
                tabella.tag_configure("evidenziato", background="#FFEB3B")
                tabella.selection_add(row)
                tabella.see(row)

    btn_cerca = tk.Button(frame_cerca, text="Cerca", command=esegui_ricerca, bg="#2196F3", fg="white", font=font_button)
    btn_cerca.pack(side="left", padx=5)
    entry_cerca.bind("<Return>", esegui_ricerca)

    # --- Bottone "Modifica" flottante sopra la riga selezionata ---
    font_popup = ("Segoe UI", 9)
    btn_modifica_popup = tk.Button(frame_tabella, text="Modifica", command=on_modifica,
                                   bg="white", fg="black", font=font_popup,
                                   relief="solid", borderwidth=1, padx=4, pady=1)
    btn_cancella_popup = tk.Button(frame_tabella, text="\U0001F5D1", command=on_cancella,
                                   bg="#e53935", fg="white", font=font_popup,
                                   relief="solid", borderwidth=1, padx=4, pady=1)

    def nascondi_popup():
        btn_modifica_popup.place_forget()
        btn_cancella_popup.place_forget()

    def mostra_popup_su_riga(row_id):
        bbox = tabella.bbox(row_id)
        if not bbox:
            return
        x, y, w, h = bbox
        btn_mod_w = 70
        btn_del_w = 32
        gap = 4
        # Posiziona i bottoni a destra, con un margine dal bordo
        frame_w = frame_tabella.winfo_width()
        btn_del_x = frame_w - btn_del_w - 30
        btn_mod_x = btn_del_x - btn_mod_w - gap
        btn_y = y - 30
        if btn_y < 0:
            btn_y = y + h + 2
        btn_modifica_popup.place(x=btn_mod_x, y=btn_y, width=btn_mod_w)
        btn_cancella_popup.place(x=btn_del_x, y=btn_y, width=btn_del_w)

    def on_click_tabella(event):
        region = tabella.identify_region(event.x, event.y)
        if region == "nothing":
            # Click su spazio vuoto: resetta tutto
            nascondi_popup()
            tabella.selection_remove(*tabella.selection())
            for row in tabella.get_children():
                tabella.item(row, tags=())
            entry_cerca.delete(0, tk.END)
        elif region in ("cell", "tree"):
            row_id = tabella.identify_row(event.y)
            if row_id:
                tabella.selection_set(row_id)
                mostra_popup_su_riga(row_id)
            else:
                nascondi_popup()

    tabella.bind("<Button-1>", on_click_tabella, add=False)

    def on_click_globale(event):
        """Deseleziona la riga se si clicca fuori dalla tabella."""
        widget = event.widget
        # Se il click è sulla tabella, lascia gestire on_click_tabella
        if widget is tabella:
            return
        # Se il click è sui bottoni popup, non deselezionare
        if widget in (btn_modifica_popup, btn_cancella_popup):
            return
        nascondi_popup()
        tabella.selection_remove(*tabella.selection())
        for row in tabella.get_children():
            tabella.item(row, tags=())
        entry_cerca.delete(0, tk.END)

    root.bind_all("<Button-1>", on_click_globale, add=True)

    # --- Aggiorna la tabella ---
    def aggiorna_tabella():
        for row in tabella.get_children():
            tabella.delete(row)
        for voce in leggi_passwords():
            tabella.insert("", "end", values=voce)

    aggiorna_tabella()
    root.mainloop()

init_db()
esporta_db_leggibile()
avvia_app()