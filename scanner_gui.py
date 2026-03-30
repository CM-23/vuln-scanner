import socket
import requests
import tkinter as tk
from tkinter import font as tkfont
import threading
import time

# ── Palette ──────────────────────────────────────────────────────────────────
BG          = "#0a0e1a"
PANEL       = "#0f1525"
BORDER      = "#1a2540"
ACCENT      = "#00d4ff"
ACCENT2     = "#7b2fff"
GREEN       = "#00ff88"
YELLOW      = "#ffd60a"
RED         = "#ff4560"
TEXT        = "#c8d8f0"
TEXT_DIM    = "#4a6080"
TEXT_BRIGHT = "#ffffff"

# ── Scanline / noise overlay chars ───────────────────────────────────────────
HEADER_ART = (
    "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗\n"
    "  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝\n"
    "  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     \n"
    "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     \n"
    "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗\n"
    "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝"
)

def make_gui():
    root = tk.Tk()
    root.title("VULNSC • Threat Intelligence Platform")
    root.geometry("780x720")
    root.configure(bg=BG)
    root.resizable(False, False)

    # ── Fonts ─────────────────────────────────────────────────────────────────
    try:
        mono  = tkfont.Font(family="Courier New", size=9,  weight="normal")
        mono_b= tkfont.Font(family="Courier New", size=9,  weight="bold")
        mono_lg=tkfont.Font(family="Courier New", size=10, weight="bold")
        art_f = tkfont.Font(family="Courier New", size=7,  weight="bold")
        lbl_f = tkfont.Font(family="Courier New", size=8,  weight="normal")
        btn_f = tkfont.Font(family="Courier New", size=10, weight="bold")
    except Exception:
        mono = mono_b = mono_lg = art_f = lbl_f = btn_f = None

    # ── ASCII header ──────────────────────────────────────────────────────────
    hdr_frame = tk.Frame(root, bg=BG)
    hdr_frame.pack(fill="x", padx=20, pady=(18, 4))

    art_lbl = tk.Label(hdr_frame, text=HEADER_ART,
                       font=art_f, bg=BG, fg=ACCENT, justify="left",
                       anchor="w")
    art_lbl.pack(side="left")

    # version / badge column
    badge_col = tk.Frame(hdr_frame, bg=BG)
    badge_col.pack(side="right", anchor="ne", padx=(0,4))
    tk.Label(badge_col, text="v2.0.1", font=lbl_f,
             bg=BG, fg=TEXT_DIM).pack(anchor="e")
    tk.Label(badge_col, text="[ RECON MODULE ]", font=lbl_f,
             bg=BG, fg=ACCENT2).pack(anchor="e", pady=(4,0))

    # ── Thin separator ────────────────────────────────────────────────────────
    sep = tk.Frame(root, bg=ACCENT, height=1)
    sep.pack(fill="x", padx=20, pady=(6, 14))

    # ── Input card ────────────────────────────────────────────────────────────
    card = tk.Frame(root, bg=PANEL, bd=0, relief="flat",
                    highlightthickness=1, highlightbackground=BORDER)
    card.pack(fill="x", padx=20, pady=(0, 12))

    inner = tk.Frame(card, bg=PANEL)
    inner.pack(padx=16, pady=12, fill="x")

    tk.Label(inner, text="TARGET  URL", font=lbl_f,
             bg=PANEL, fg=TEXT_DIM).grid(row=0, column=0, sticky="w")
    tk.Label(inner, text="PROTOCOL", font=lbl_f,
             bg=PANEL, fg=TEXT_DIM).grid(row=0, column=2, sticky="w", padx=(18,0))

    url_var  = tk.StringVar(value="https://")
    proto_var= tk.StringVar(value="TCP/IP")

    url_entry = tk.Entry(inner, textvariable=url_var, width=44,
                         font=mono_b, bg="#0c1220", fg=ACCENT,
                         insertbackground=ACCENT, relief="flat",
                         bd=0, highlightthickness=1,
                         highlightbackground=BORDER,
                         highlightcolor=ACCENT)
    url_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4,0))

    proto_menu = tk.OptionMenu(inner, proto_var, "TCP/IP", "HTTP", "HTTPS")
    proto_menu.config(bg="#0c1220", fg=TEXT, activebackground=ACCENT2,
                      activeforeground=TEXT_BRIGHT, relief="flat",
                      font=mono, bd=0, highlightthickness=0,
                      indicatoron=0, width=8)
    proto_menu["menu"].config(bg="#0c1220", fg=TEXT, font=mono)
    proto_menu.grid(row=1, column=2, sticky="ew", padx=(18,0), pady=(4,0))

    inner.columnconfigure(0, weight=1)

    # ── Port checkboxes ───────────────────────────────────────────────────────
    ports_frame = tk.Frame(card, bg=PANEL)
    ports_frame.pack(padx=16, pady=(0,10), fill="x")

    tk.Label(ports_frame, text="PORTS TO SCAN", font=lbl_f,
             bg=PANEL, fg=TEXT_DIM).pack(side="left", padx=(0,10))

    port_vars = {}
    for p in [21, 22, 80, 443, 8080, 8443]:
        v = tk.BooleanVar(value=(p in [80, 443]))
        cb = tk.Checkbutton(ports_frame, text=str(p), variable=v,
                            font=lbl_f, bg=PANEL, fg=TEXT,
                            selectcolor="#0c1220",
                            activebackground=PANEL, activeforeground=ACCENT,
                            bd=0, highlightthickness=0)
        cb.pack(side="left", padx=4)
        port_vars[p] = v

    # ── Scan button ───────────────────────────────────────────────────────────
    btn_row = tk.Frame(root, bg=BG)
    btn_row.pack(fill="x", padx=20, pady=(0, 12))

    def make_btn(parent, text, cmd, color):
        f = tk.Frame(parent, bg=color, padx=1, pady=1)
        b = tk.Button(f, text=text, command=cmd, font=btn_f,
                      bg=PANEL, fg=color, activebackground=color,
                      activeforeground=BG, relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2")
        b.pack()
        def on_enter(e): b.config(bg=color, fg=BG)
        def on_leave(e): b.config(bg=PANEL, fg=color)
        b.bind("<Enter>", on_enter)
        b.bind("<Leave>", on_leave)
        return f

    scan_btn  = make_btn(btn_row, "▶  INITIATE SCAN", lambda: start_scan(), ACCENT)
    clear_btn = make_btn(btn_row, "⌫  CLEAR",          lambda: clear_output(), TEXT_DIM)
    scan_btn.pack(side="left")
    clear_btn.pack(side="left", padx=(10,0))

    # status badge (right side)
    status_var = tk.StringVar(value="● IDLE")
    status_lbl = tk.Label(btn_row, textvariable=status_var,
                          font=lbl_f, bg=BG, fg=TEXT_DIM)
    status_lbl.pack(side="right")

    # ── Progress bar ──────────────────────────────────────────────────────────
    prog_frame = tk.Frame(root, bg=BG)
    prog_frame.pack(fill="x", padx=20, pady=(0,8))

    canvas_prog = tk.Canvas(prog_frame, height=3, bg=BORDER,
                            bd=0, highlightthickness=0)
    canvas_prog.pack(fill="x")
    prog_bar = canvas_prog.create_rectangle(0, 0, 0, 3, fill=ACCENT, width=0)

    def set_progress(pct):
        w = canvas_prog.winfo_width()
        canvas_prog.coords(prog_bar, 0, 0, int(w * pct / 100), 3)

    # ── Output terminal ───────────────────────────────────────────────────────
    term_outer = tk.Frame(root, bg=BORDER, bd=0)
    term_outer.pack(fill="both", expand=True, padx=20, pady=(0,14))

    # terminal title bar
    term_title = tk.Frame(term_outer, bg=BORDER)
    term_title.pack(fill="x", padx=1, pady=(1,0))

    for col, char in zip([RED, YELLOW, GREEN], ["●","●","●"]):
        tk.Label(term_title, text=char, bg=BORDER, fg=col,
                 font=lbl_f).pack(side="left", padx=(4,0), pady=2)
    tk.Label(term_title, text="  TERMINAL OUTPUT — VULNSC v2",
             bg=BORDER, fg=TEXT_DIM, font=lbl_f).pack(side="left")

    output = tk.Text(term_outer, font=mono, bg="#070b14", fg=TEXT,
                     insertbackground=ACCENT, relief="flat", bd=0,
                     padx=12, pady=10, wrap="word",
                     selectbackground=ACCENT2, selectforeground=TEXT_BRIGHT)
    output.pack(fill="both", expand=True, padx=1, pady=(0,1))

    scroll = tk.Scrollbar(output, command=output.yview,
                          bg=BORDER, activebackground=ACCENT,
                          troughcolor=BG, bd=0, relief="flat")
    output.config(yscrollcommand=scroll.set)

    # colour tags
    output.tag_config("accent",  foreground=ACCENT)
    output.tag_config("green",   foreground=GREEN)
    output.tag_config("yellow",  foreground=YELLOW)
    output.tag_config("red",     foreground=RED)
    output.tag_config("dim",     foreground=TEXT_DIM)
    output.tag_config("bright",  foreground=TEXT_BRIGHT)
    output.tag_config("purple",  foreground=ACCENT2)
    output.tag_config("header",  foreground=ACCENT, font=mono_lg)

    def write(text, tag=""):
        output.config(state="normal")
        if tag:
            output.insert("end", text, tag)
        else:
            output.insert("end", text)
        output.see("end")
        output.config(state="disabled")

    def clear_output():
        output.config(state="normal")
        output.delete("1.0", "end")
        output.config(state="disabled")
        set_progress(0)
        status_var.set("● IDLE")
        status_lbl.config(fg=TEXT_DIM)

    # ── Spinner animation ─────────────────────────────────────────────────────
    spinner_chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    spinner_idx   = [0]
    spinner_id    = [None]

    def spin_tick():
        c = spinner_chars[spinner_idx[0] % len(spinner_chars)]
        status_var.set(f"{c} SCANNING")
        status_lbl.config(fg=ACCENT)
        spinner_idx[0] += 1
        spinner_id[0]   = root.after(80, spin_tick)

    def stop_spin():
        if spinner_id[0]:
            root.after_cancel(spinner_id[0])
            spinner_id[0] = None

    # ── Core scan logic ───────────────────────────────────────────────────────
    def run_scan():
        url = url_var.get().strip()
        clear_output()

        if not url or url in ("https://", "http://", ""):
            write("  ERROR  ", "red")
            write(" Please enter a valid URL.\n")
            stop_spin()
            status_var.set("● IDLE"); status_lbl.config(fg=TEXT_DIM)
            return

        # ── Header ─────────────────────────────────────────────
        write("┌─────────────────────────────────────────────────┐\n", "dim")
        write("│  VULNSC RECON ENGINE  ", "dim")
        write("v2.0.1", "purple")
        write("                        │\n", "dim")
        write("└─────────────────────────────────────────────────┘\n", "dim")
        write(f"\n  TARGET   ", "dim"); write(f"{url}\n", "bright")
        write(f"  TIME     ", "dim"); write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n", "dim")

        # ── HTTPS check ────────────────────────────────────────
        set_progress(10)
        write("  [1/4]  ", "accent"); write("PROTOCOL CHECK\n", "bright")
        if url.startswith("https://"):
            write("         ✔  TLS/HTTPS", "green")
            write("  — encrypted transport\n", "dim")
        else:
            write("         ✘  PLAIN HTTP", "red")
            write("  — traffic is unencrypted!\n", "yellow")

        host = url.replace("https://","").replace("http://","").split("/")[0]
        write(f"         HOST  ", "dim"); write(f"{host}\n\n", "accent")

        # ── Port scan ──────────────────────────────────────────
        set_progress(30)
        write("  [2/4]  ", "accent"); write("PORT SCAN\n", "bright")
        selected_ports = [p for p, v in port_vars.items() if v.get()]
        open_ports   = []
        closed_ports = []

        for port in selected_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                    write(f"         ◉  {port:<6}", "green")
                    write("OPEN\n", "green")
                else:
                    closed_ports.append(port)
                    write(f"         ○  {port:<6}", "dim")
                    write("closed\n", "dim")
                s.close()
            except Exception:
                write(f"         ?  {port:<6}", "yellow")
                write("unreachable\n", "dim")

        write(f"\n         Summary: ", "dim")
        write(f"{len(open_ports)} open", "green")
        write(f"  /  {len(closed_ports)} closed\n\n", "dim")

        # ── Path scan ──────────────────────────────────────────
        set_progress(60)
        write("  [3/4]  ", "accent"); write("PATH DISCOVERY\n", "bright")
        paths = ["/admin", "/login", "/wp-admin", "/dashboard",
                 "/api", "/config", "/.env", "/backup"]
        found = []

        base = url.rstrip("/")
        for path in paths:
            try:
                res = requests.get(base + path, timeout=4,
                                   headers={"User-Agent": "Mozilla/5.0"},
                                   allow_redirects=True)
                code = res.status_code
                if code == 200:
                    found.append(path)
                    write(f"         ◉  {path:<20}", "red")
                    write(f"  {code} FOUND\n", "red")
                elif code in (301, 302):
                    write(f"         →  {path:<20}", "yellow")
                    write(f"  {code} REDIRECT\n", "dim")
                else:
                    write(f"         ○  {path:<20}", "dim")
                    write(f"  {code}\n", "dim")
            except Exception:
                write(f"         ×  {path:<20}", "dim")
                write("  timeout\n", "dim")

        write(f"\n         Exposed paths: ", "dim")
        if found:
            write(f"{len(found)} detected\n\n", "red")
        else:
            write("none detected\n\n", "green")

        # ── Server info ────────────────────────────────────────
        set_progress(85)
        write("  [4/4]  ", "accent"); write("HEADER FINGERPRINTING\n", "bright")
        try:
            res = requests.get(base, timeout=5,
                               headers={"User-Agent": "Mozilla/5.0"})
            interesting = ["Server","X-Powered-By","X-Frame-Options",
                           "Content-Security-Policy","Strict-Transport-Security",
                           "X-Content-Type-Options","Access-Control-Allow-Origin"]
            for h in interesting:
                val = res.headers.get(h)
                if val:
                    tag = "dim" if h in ("Server","X-Powered-By") else "green"
                    write(f"         {h:<35}", "dim")
                    write(f"{val[:50]}\n", tag)
                else:
                    write(f"         {h:<35}", "dim")
                    write("—\n", "dim")
        except Exception as e:
            write(f"         Error: {e}\n", "red")

        # ── Footer ─────────────────────────────────────────────
        set_progress(100)
        write("\n┌─────────────────────────────────────────────────┐\n", "dim")
        write("│  ", "dim"); write("SCAN COMPLETE", "green")
        write("                                   │\n", "dim")
        write("└─────────────────────────────────────────────────┘\n", "dim")

        stop_spin()
        status_var.set("● DONE")
        status_lbl.config(fg=GREEN)

    def start_scan():
        spin_tick()
        t = threading.Thread(target=run_scan, daemon=True)
        t.start()

    # startup banner
    write("  VULNSC Threat Intelligence Platform  —  Ready\n", "dim")
    write("  Enter a target URL above and press INITIATE SCAN.\n\n", "dim")

    root.mainloop()

if __name__ == "__main__":
    make_gui()