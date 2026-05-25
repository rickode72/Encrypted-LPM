import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import tkinter.font as tkfont
import sqlite3
import ctypes
import base64
import os
import sys
import platform
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Abilita DPI awareness su Windows per rendering nitido a 1920x1080
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# Sceglie un font disponibile sulla piattaforma corrente.
# Su Windows "Segoe UI" funziona; su Linux non esiste, quindi cerchiamo
# il primo font sans-serif disponibile tra una lista di fallback.
def _scegli_font_famiglia():
    if platform.system() == "Windows":
        return "Segoe UI"
    # Per inizializzare tkfont serve un root Tk: ne creiamo uno nascosto e temporaneo.
    tmp = tk.Tk()
    tmp.withdraw()
    try:
        disponibili = set(tkfont.families())
    finally:
        tmp.destroy()
    for candidato in ("Ubuntu", "Noto Sans", "DejaVu Sans", "Liberation Sans", "FreeSans", "Sans"):
        if candidato in disponibili:
            return candidato
    return "TkDefaultFont"

FONT_FAMILY = _scegli_font_famiglia()

# Scaling fisso: la rilevazione automatica del DPI su Linux era inaffidabile
# (xrandr/winfo_screenmmwidth restituiscono valori diversi a seconda di
# Wayland/X11 e del fractional scaling del compositor), quindi a volte la
# finestra si apriva minuscola. Valori fissi → comportamento riproducibile.
# Override manuale via env var TK_SCALING (es. `TK_SCALING=1.7 python3 ...`).
SCALING_DEFAULT = 1.5
GEOMETRY_MULT = SCALING_DEFAULT / 1.333

def applica_dpi_scaling(root):
    """Imposta lo scaling di Tk a un valore fisso e prevedibile."""
    global GEOMETRY_MULT
    try:
        override = os.environ.get("TK_SCALING")
        scaling = float(override) if override else SCALING_DEFAULT
        scaling = max(1.0, min(scaling, 2.5))
        root.tk.call("tk", "scaling", scaling)
        GEOMETRY_MULT = scaling / 1.333
    except Exception:
        pass

def S(v):
    """Scala un valore in pixel in base al DPI rilevato."""
    return int(round(v * GEOMETRY_MULT))

def centra_finestra(win, w, h):
    """Centra una finestra di dimensioni w x h sullo schermo corrente."""
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = max(0, (sw - w) // 2)
    y = max(0, (sh - h) // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")

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
    applica_dpi_scaling(login)
    login.title("Login - Password Manager")
    centra_finestra(login, S(520), S(240))
    login.minsize(S(520), S(240))
    login.resizable(False, False)

    font_label = (FONT_FAMILY, 12)
    font_entry = (FONT_FAMILY, 12)
    font_button = (FONT_FAMILY, 11, "bold")

    tk.Label(login, text="Inserisci la Master Password:", font=font_label).pack(pady=(25, 8))
    entry_master = tk.Entry(login, font=font_entry, show="*", width=30)
    entry_master.pack(pady=8, ipady=4)
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

    tk.Button(login, text="Sblocca", command=tentativo, bg="#2196F3", fg="white",
              font=font_button, padx=12, pady=4).pack(pady=15)

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
    applica_dpi_scaling(root)
    root.title("Password Manager Locale")
    # Dimensioni fisse scalate dal moltiplicatore DPI: comportamento
    # riproducibile a ogni avvio, dimensionate per schermi >= 1600x900.
    w_main = S(1280)
    h_main = S(780)
    centra_finestra(root, w_main, h_main)
    root.minsize(S(900), S(560))

    # --- Stile e font scalati per rendering nitido ---
    font_label = (FONT_FAMILY, 11)
    font_entry = (FONT_FAMILY, 11)
    font_button = (FONT_FAMILY, 10, "bold")
    font_tabella = (FONT_FAMILY, 11)

    # Calcola l'altezza riga dalle metriche reali del font: su Linux il font
    # di fallback è spesso più alto del previsto e con rowheight fisso le
    # righe finiscono per sovrapporsi.
    _f_tab = tkfont.Font(family=FONT_FAMILY, size=11)
    row_h = _f_tab.metrics("linespace") + 12

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", font=font_tabella, rowheight=row_h)
    style.configure("Treeview.Heading", font=(FONT_FAMILY, 11, "bold"))

    # Mappa: id riga Treeview -> password in chiaro. Tiene le password fuori
    # dalla UI ma raggiungibili per Ctrl+C e per la finestra di modifica.
    password_reali = {}

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
    tabella.column("ID", width=S(60), minwidth=S(40), stretch=False)
    tabella.column("Sito", width=S(250), minwidth=S(100))
    tabella.column("Username", width=S(250), minwidth=S(100))
    tabella.column("Password", width=S(300), minwidth=S(100))
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
        row_id = selezione[0]
        item = tabella.item(row_id)
        id_ = item["values"][0]
        vecchio_sito = str(item["values"][1])
        vecchio_user = str(item["values"][2])
        vecchia_pwd = password_reali.get(row_id, "")

        # Finestra di modifica
        win = tk.Toplevel(root)
        win.title("Modifica credenziale")
        centra_finestra(win, S(640), S(300))
        win.minsize(S(640), S(300))
        win.resizable(True, False)
        win.grab_set()
        # Colonna dell'Entry si espande, label e toggle restano fissi
        win.columnconfigure(1, weight=1)

        tk.Label(win, text="Sito:", font=font_label).grid(row=0, column=0, padx=10, pady=(15, 5), sticky="e")
        e_sito = tk.Entry(win, font=font_entry, width=30)
        e_sito.grid(row=0, column=1, padx=10, pady=(15, 5), columnspan=2, sticky="ew")
        e_sito.insert(0, vecchio_sito)

        tk.Label(win, text="Username:", font=font_label).grid(row=1, column=0, padx=10, pady=5, sticky="e")
        e_user = tk.Entry(win, font=font_entry, width=30)
        e_user.grid(row=1, column=1, padx=10, pady=5, columnspan=2, sticky="ew")
        e_user.insert(0, vecchio_user)

        tk.Label(win, text="Password:", font=font_label).grid(row=2, column=0, padx=10, pady=5, sticky="e")
        e_pwd = tk.Entry(win, font=font_entry, width=30, show="*")
        e_pwd.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        e_pwd.insert(0, vecchia_pwd)

        def toggle_pwd_modifica():
            if e_pwd.cget("show") == "*":
                e_pwd.config(show="")
                btn_toggle_pwd.config(text="Nascondi")
            else:
                e_pwd.config(show="*")
                btn_toggle_pwd.config(text="Mostra")

        btn_toggle_pwd = tk.Button(win, text="Mostra", command=toggle_pwd_modifica,
                                   font=font_button, width=8)
        btn_toggle_pwd.grid(row=2, column=2, padx=(0, 10), pady=5)

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
        tk.Button(win, text="Salva modifiche", command=salva_modifica, bg="#2196F3", fg="white", font=font_button).grid(row=3, column=0, columnspan=3, pady=15)

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

    # Label di feedback per la copia in clipboard (es. "Password copiata")
    lbl_feedback = tk.Label(frame_cerca, text="", font=font_label, fg="#2E7D32")
    lbl_feedback.pack(side="left", padx=15)

    def mostra_feedback(messaggio, durata_ms=2000):
        lbl_feedback.config(text=messaggio)
        lbl_feedback.after(durata_ms, lambda: lbl_feedback.config(text=""))

    def on_copia_password(event=None):
        """Copia la password della riga selezionata negli appunti senza mostrarla."""
        selezione = tabella.selection()
        if not selezione:
            return "break"
        row_id = selezione[0]
        pwd = password_reali.get(row_id)
        if pwd is None:
            return "break"
        root.clipboard_clear()
        root.clipboard_append(pwd)
        root.update()  # forza l'aggiornamento del clipboard
        mostra_feedback("Password copiata negli appunti")
        return "break"

    tabella.bind("<Control-c>", on_copia_password)
    tabella.bind("<Control-C>", on_copia_password)

    # --- Bottone "Modifica" flottante sopra la riga selezionata ---
    font_popup = (FONT_FAMILY, 10, "bold")
    btn_modifica_popup = tk.Button(frame_tabella, text="Modifica", command=on_modifica,
                                   bg="white", fg="black", font=font_popup,
                                   relief="solid", borderwidth=1)
    btn_cancella_popup = tk.Button(frame_tabella, text="\U0001F5D1", command=on_cancella,
                                   bg="#e53935", fg="white", font=font_popup,
                                   relief="solid", borderwidth=1)

    def nascondi_popup():
        btn_modifica_popup.place_forget()
        btn_cancella_popup.place_forget()

    def mostra_popup_su_riga(row_id):
        bbox = tabella.bbox(row_id)
        if not bbox:
            return
        x, y, w, h = bbox
        # Dimensioni proporzionate all'altezza riga (che è già scalata sul font).
        # Così su qualunque DPI/dimensione finestra i bottoni restano armonici.
        btn_h = max(h - 4, 24)
        btn_mod_w = max(int(btn_h * 3.2), 90)
        btn_del_w = max(int(btn_h * 1.3), 42)
        gap = 6
        # Margine dal bordo destro: tiene conto dello scrollbar
        margine_dx = scrollbar.winfo_width() + 10 if scrollbar.winfo_ismapped() else 14
        frame_w = frame_tabella.winfo_width()
        btn_del_x = frame_w - btn_del_w - margine_dx
        btn_mod_x = btn_del_x - btn_mod_w - gap
        # Centrato verticalmente sulla riga: non esce mai dal frame visibile
        btn_y = y + (h - btn_h) // 2
        btn_modifica_popup.place(x=btn_mod_x, y=btn_y, width=btn_mod_w, height=btn_h)
        btn_cancella_popup.place(x=btn_del_x, y=btn_y, width=btn_del_w, height=btn_h)

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
        password_reali.clear()
        for voce in leggi_passwords():
            id_, sito, username, pwd_reale = voce
            pwd_mascherata = "•" * len(pwd_reale)
            row_id = tabella.insert("", "end", values=(id_, sito, username, pwd_mascherata))
            password_reali[row_id] = pwd_reale

    aggiorna_tabella()
    root.mainloop()

init_db()
esporta_db_leggibile()
avvia_app()