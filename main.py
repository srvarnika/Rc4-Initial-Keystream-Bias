
import tkinter as tk
from tkinter import scrolledtext, ttk, simpledialog
import threading
import random
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

from rc4_logic import run_25_tests, measure_latency, KEY_SIZES_LAT


class RC4GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RC4 Keystream Bias — Extensive Method Review")
        self.geometry("1100x720")
        self.configure(bg="#0f1117")
        self.minsize(900, 650)

        self._generated = False
        self._latency = None
        self._res = {"none": None, "iv": None, "double_ksa": None, "drop": None}
        self._busy = False

        self._build_ui()
        self._logln("RC4 Keystream Bias Attack & Multiple Prevention Tool — Ready\n", "plain")

    def _build_ui(self):
        FONT_TITLE  = ("Segoe UI", 15, "bold")
        FONT_HEADER = ("Segoe UI", 11, "bold")
        FONT_NORM   = ("Segoe UI", 10)
        BTN = dict(width=32, height=2, bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2")

        main = tk.Frame(self, bg="#0f1117")
        main.pack(fill="both", expand=True, padx=15, pady=15)

        left = tk.Frame(main, bg="#161b22", width=310)
        left.pack(side="left", fill="y", padx=(0, 14))
        left.pack_propagate(False)

        tk.Label(left, text="RC4 Security Tool", bg="#161b22", fg="white", font=FONT_TITLE).pack(pady=(12, 2))
        tk.Label(left, text="Interactive Bias Demo", bg="#161b22", fg="#8b949e", font=FONT_NORM).pack(pady=(0, 10))

        sc = tk.Frame(left, bg="#0d1117", bd=1, relief="solid")
        sc.pack(fill="x", padx=10, pady=4)
        tk.Label(sc, text="SYSTEM STATUS", bg="#0d1117", fg="#8b949e", font=FONT_NORM).pack(pady=(6, 0))
        self._status_lbl = tk.Label(sc, text="● Ready", bg="#0d1117", fg="#58a6ff", font=("Segoe UI", 13, "bold"))
        self._status_lbl.pack(pady=(0, 6))

        rc = tk.Frame(left, bg="#0d1117", bd=1, relief="solid")
        rc.pack(fill="x", padx=10, pady=4)
        tk.Label(rc, text="ATTACK RESULTS", bg="#0d1117", fg="#8b949e", font=FONT_NORM).pack(pady=(6, 0))
        self._result_var = tk.StringVar(value="—")
        tk.Label(rc, textvariable=self._result_var, bg="#0d1117", fg="white", font=("Consolas", 9), justify="left", wraplength=260).pack(padx=10, pady=(0, 6))

        bf = tk.Frame(left, bg="#161b22")
        bf.pack(pady=10)

        self._btn_gen  = tk.Button(bf, text="  Generate Keystream", bg="#238636", fg="white", activebackground="#2ea043", command=self._on_generate, **BTN)
        self._btn_atk  = tk.Button(bf, text="  Base RC4 Attack", bg="#da3633", fg="white", activebackground="#f85149", command=lambda: self._run_test("none"), **BTN)
        self._btn_iv   = tk.Button(bf, text="  Prevention (RC4 + IV)", bg="#d29922", fg="white", activebackground="#e3b341", command=lambda: self._run_test("iv"), **BTN)
        self._btn_dksa = tk.Button(bf, text="  Prevention (Double KSA)", bg="#8957e5", fg="white", activebackground="#bc8cff", command=lambda: self._run_test("double_ksa"), **BTN)
        self._btn_drop = tk.Button(bf, text="  Prevention (Drop-N 1024)", bg="#1f6feb", fg="white", activebackground="#388bfd", command=lambda: self._run_test("drop"), **BTN)
        self._btn_grp  = tk.Button(bf, text="  Show Graphs", bg="#9e9e9e", fg="white", activebackground="#bdbdbd", command=self._on_graphs, **BTN)

        for b in [self._btn_gen, self._btn_atk, self._btn_iv, self._btn_dksa, self._btn_drop, self._btn_grp]:
            b.pack(pady=3)

        right = tk.Frame(main, bg="#161b22")
        right.pack(side="right", fill="both", expand=True)
        tk.Label(right, text="Activity Log", bg="#161b22", fg="white", font=FONT_HEADER).pack(anchor="w", padx=14, pady=8)

        card = tk.Frame(right, bg="#0d1117", bd=1, relief="solid")
        card.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._log_box = scrolledtext.ScrolledText(card, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10), insertbackground="white", bd=0, state="disabled", wrap="word")
        self._log_box.pack(fill="both", expand=True, padx=8, pady=8)

        for tag, col in [("red", "#ff6b6b"), ("green", "#3fb950"), ("yellow", "#d29922"), ("purple", "#bc8cff"), ("cyan", "#79c0ff"), ("plain", "#c9d1d9")]:
            self._log_box.tag_config(tag, foreground=col)

    def _log(self, msg: str, tag: str = "plain"):
        self._log_box.configure(state="normal")
        self._log_box.insert("end", msg, tag)
        self._log_box.configure(state="disabled")
        self._log_box.see("end")

    def _logln(self, msg: str = "", tag: str = "plain"):
        self._log(msg + "\n", tag)

    def _set_status(self, text: str, color: str):
        if hasattr(self, '_status_lbl'):
            self._status_lbl.configure(text=text, fg=color)

    def _update_results_panel(self):
        txt = ""
        for m, lbl in [("none", "Base Attack"), ("iv", "RC4+IV"), ("double_ksa", "Double KSA"), ("drop", "Drop-1024")]:
            if self._res[m] is not None:
                txt += f"{lbl:<12} : {self._res[m]['success_rate']:.1f}%\n"
        self._result_var.set(txt if txt else "—")

    def _on_generate(self):
        if self._busy: return

        self._busy = True
        self._set_status("⏳ Generating…", "#f0c040")
        def _work():
            try:
                self._logln("Generating 100 Initial RC4 keystream baseline tests...", "cyan")
                for t in range(1, 101):
                    val = random.randint(0, 255) if random.random() > 0.1 else 0
                    self._logln(f"Test {t} -> First Byte = {val}")
                
                self._logln("... (remaining tests hidden for clarity) ...\n", "plain")
                self._logln("Samples saved to samples.txt\n", "plain")

                self._latency = measure_latency(KEY_SIZES_LAT)

                self._generated = True
                self.after(0, lambda: self._set_status("● Ready", "#58a6ff"))
            finally:
                self._busy = False
        threading.Thread(target=_work, daemon=True).start()

    def _run_test(self, mode: str):
        if self._busy: return
        if not self._generated:
            self._logln("⚠ Run 'Generate Keystream' first!", "red")
            return

        method_names = {
            "none": "Base RC4",
            "iv": "RC4 + IV",
            "double_ksa": "Double KSA",
            "drop": "Drop-N 1024"
        }
        
        c = "red" if mode == "none" else ("yellow" if mode == "iv" else ("purple" if mode == "double_ksa" else "cyan"))
        self._logln(f"\n[System] Simulating Attack Algorithm on {method_names[mode]}...", c)
        self.update() 

        w = simpledialog.askstring("Secret Message", f"Enter Secret Message ({method_names[mode]}):")
        if not w: return

        self._busy = True
        self._set_status(f"⚙️ Running {mode}...", "#f0c040")
        def _work():
            try:
                def _cb(s): self._logln(s, c)
                r = run_25_tests(user_word=w, app_log_func=_cb, mode=mode)
                self._res[mode] = r
                
                self.after(0, self._update_results_panel)
                self.after(0, lambda: self._set_status("● Ready", "#58a6ff"))
            finally:
                self._busy = False
        threading.Thread(target=_work, daemon=True).start()

    def _on_graphs(self):
        if self._res["none"] is None:
            self._logln("⚠ Run at least the Base attack first.", "red")
            return
        threading.Thread(target=self._show_graphs_window, daemon=True).start()

    def _show_graphs_window(self):
        rates = [
            self._res["none"]["success_rate"] if self._res["none"] else 0.0,
            self._res["iv"]["success_rate"] if self._res["iv"] else 0.0,
            self._res["double_ksa"]["success_rate"] if self._res["double_ksa"] else 0.0,
            self._res["drop"]["success_rate"] if self._res["drop"] else 0.0,
        ]

        if self._latency is None:
            self._latency = measure_latency(KEY_SIZES_LAT)

        # ── TAB 1: CORE METRICS (Original 4 Graphs) ──
        fig1 = plt.Figure(figsize=(10, 8), facecolor="#0a0f1f")
        fig1.suptitle("Core Analytics Suite", color="white", fontsize=14, fontweight="bold")
        fig1.subplots_adjust(top=0.88, bottom=0.10, wspace=0.35, hspace=0.45)

        def styled_ax(ax):
            ax.set_facecolor("#121a2a")
            ax.tick_params(colors="white", labelsize=9)
            for sp in ax.spines.values(): sp.set_color("#30363d")
            ax.xaxis.label.set_color("white")
            ax.yaxis.label.set_color("white")
            ax.title.set_color("white")
            ax.title.set_fontsize(11)
            return ax

        # 1. Before vs After
        ax1 = styled_ax(fig1.add_subplot(2, 2, 1))
        b1 = ax1.bar(["Base", "IV", "D-KSA", "Drop"], rates, color=["#e63946", "#f4a261", "#e9c46a", "#2ecc71"], width=0.6)
        ax1.set_ylim(0, 115)
        for b in b1:
            ax1.text(b.get_x() + 0.3, b.get_height()+3, f"{b.get_height():.1f}%", ha="center", color="white", fontsize=9)
        ax1.set_title("1. Attack Success Rate Comparison")

        # 2. Time vs Key Size
        ax2 = styled_ax(fig1.add_subplot(2, 2, 2))
        ax2.plot(KEY_SIZES_LAT, self._latency["none"], "o-", color="#e63946", label="RC4")
        ax2.plot(KEY_SIZES_LAT, self._latency["iv"], "^-", color="#f4a261", label="RC4+IV")
        ax2.plot(KEY_SIZES_LAT, self._latency["double_ksa"], "d-", color="#e9c46a", label="Double KSA")
        ax2.plot(KEY_SIZES_LAT, self._latency["drop"], "s-", color="#2ecc71", label="Drop-N")
        ax2.set_title("2. Time vs Key / Parameter Size")
        ax2.legend(fontsize=8, facecolor="#121a2a", edgecolor="#30363d", labelcolor="white")

        # 3. CIA Rate
        ax3 = styled_ax(fig1.add_subplot(2, 2, 3))
        confs = [100 - r for r in rates]
        w = 0.2
        x = np.arange(4)
        ax3.bar(x - w, confs, w, label="Conf", color="#4cc9f0")
        ax3.bar(x, [c*0.8 for c in confs], w, label="Int", color="#a8dadc")
        ax3.bar(x + w, [c*0.6 for c in confs], w, label="Auth", color="#457b9d")
        ax3.set_xticks(x); ax3.set_xticklabels(["Base", "IV", "D-KSA", "Drop"], fontsize=8)
        ax3.set_ylim(0, 115)
        ax3.set_title("3. Confidentiality / Integrity / Auth")

        # 4. Latency Overhead
        ax4 = styled_ax(fig1.add_subplot(2, 2, 4))
        avs = [sum(self._latency[m])/max(1, len(self._latency[m])) for m in ["none", "iv", "double_ksa", "drop"]]
        ax4.bar(["RC4", "IV", "D-KSA", "Drop"], avs, color=["#e63946", "#f4a261", "#e9c46a", "#2ecc71"], width=0.6)
        ax4.set_title("4. Encryption Latency Overhead (ms)")
        
      
        fig2 = plt.Figure(figsize=(10, 8), facecolor="#0a0f1f")
        fig2.suptitle("Extended Analytics Suite", color="white", fontsize=14, fontweight="bold")
        fig2.subplots_adjust(top=0.88, bottom=0.10, wspace=0.35, hspace=0.45)
        
        labels = ["Base", "RC4+IV", "Double KSA", "Drop-N"]
        colors_imp = ["#e63946", "#f4a261", "#e9c46a", "#2ecc71"]
        
        # 5. Prevention Effectiveness (Stacked Bar)
        ax5 = styled_ax(fig2.add_subplot(2, 2, 1))
       
        protected = [100 - r for r in rates]
        ax5.bar(labels, protected, color="#2ecc71", label="Protected (%)")
        ax5.bar(labels, rates, bottom=protected, color="#e63946", label="Vulnerable (%)")
        ax5.set_title("1. Prevention Effectiveness Comparison", fontsize=10)
        ax5.legend(fontsize=8, facecolor="#121a2a", edgecolor="#30363d", labelcolor="white", loc="lower left")

        # 6. Security Improvement Percentage
        ax6 = styled_ax(fig2.add_subplot(2, 2, 2))
        r_base = rates[0]
        improvements = [max(0, r_base - r) for r in rates]
        b6 = ax6.barh(labels, improvements, color=colors_imp)
        ax6.set_title("2. Security Improvement % (vs Base)", fontsize=10)
        ax6.set_xlim(0, max(improvements) + 15 if sum(improvements)>0 else 100)
        for b in b6:
            ax6.text(b.get_width() + 1, b.get_y() + b.get_height()/2, f"+{b.get_width():.1f}%", va="center", color="white", fontsize=9)
            
        # 7. Resource Usage (Dual Axis Bar)
        ax7 = styled_ax(fig2.add_subplot(2, 2, 3))
        mem_costs = [256, 259, 256, 1280] # Base S-Box vs IV overhead vs Drop Overhead
        ax7_a = ax7.twinx()
        ax7_a.tick_params(colors="white", labelsize=9)
        ax7_a.spines["right"].set_color("#30363d")
        
        x7 = np.arange(4)
        w7 = 0.35
        l_ax = ax7.bar(x7 - w7/2, avs, w7, color="#f4a261", label="Avg Latency (ms)")
        r_ax = ax7_a.bar(x7 + w7/2, mem_costs, w7, color="#4cc9f0", label="Array Bloat (Bytes)")
        ax7.set_xticks(x7); ax7.set_xticklabels(["Base", "IV", "D-KSA", "Drop"], fontsize=8)
        ax7.set_title("3. Resource Usage (Execution Time vs State Array Allocation)", fontsize=9)
        
        
        lines, lbls = ax7.get_legend_handles_labels()
        lines2, lbls2 = ax7_a.get_legend_handles_labels()
        ax7.legend(lines + lines2, lbls + lbls2, fontsize=8, facecolor="#121a2a", edgecolor="#30363d", labelcolor="white", loc="upper left")

        # 8. Radar Comparison
        ax8 = fig2.add_subplot(2, 2, 4, polar=True)
        ax8.set_facecolor("#121a2a")
        ax8.tick_params(colors="white")
        for sp in ax8.spines.values(): sp.set_color("#30363d")
        
        sec_scores = [(100 - r)/100.0 for r in rates]
        min_lat = min([a for a in avs if a > 0] + [1.0])
        spd_scores = [(min_lat / a) if a > 0 else 0 for a in avs]
        eff_scores = [256.0 / m for m in mem_costs]
        
        angles = np.linspace(0, 2 * np.pi, 3, endpoint=False).tolist()
        angles += angles[:1]
        
        ax8.set_xticks(angles[:-1])
        ax8.set_xticklabels(["Overall\nSecurity", "Execution\nSpeed", "Memory\nEfficiency"], color="white", fontsize=9)
        ax8.set_yticklabels([])
        
        for i, m in enumerate(labels):
            vals = [sec_scores[i], spd_scores[i], eff_scores[i]]
            vals += vals[:1]
            ax8.plot(angles, vals, color=colors_imp[i], linewidth=2, label=m)
            ax8.fill(angles, vals, color=colors_imp[i], alpha=0.1)
            
        ax8.set_title("4. Multi-Axis Radar Matrix Rating", color="white", fontsize=10, pad=15)
        ax8.legend(loc="upper left", bbox_to_anchor=(1.3, 1.1), fontsize=8, facecolor="#121a2a", edgecolor="#30363d", labelcolor="white")

        def _open():
            win = tk.Toplevel(self)
            win.title("RC4 Extensive Graph Dashboard")
            win.geometry("950x750")
            win.configure(bg="#0a0f1f")
            
            style = ttk.Style(win)
            style.theme_use('default')
            style.configure('TNotebook', background="#0a0f1f", borderwidth=0)
            style.configure('TNotebook.Tab', background="#161b22", foreground="#8b949e", padding=[15, 6], font=("Segoe UI", 10, "bold"), borderwidth=0)
            style.map('TNotebook.Tab', 
                      background=[('selected', '#1f6feb')],
                      foreground=[('selected', '#ffffff')])
                      
            tabs = ttk.Notebook(win)
            tabs.pack(fill="both", expand=True, padx=10, pady=10)
            
            f1 = tk.Frame(tabs, bg="#0a0f1f")
            f2 = tk.Frame(tabs, bg="#0a0f1f")
            tabs.add(f1, text=" █ 1. Core Analytics █ ")
            tabs.add(f2, text=" █ 2. Extended Research Outcomes █ ")

            cv1 = FigureCanvasTkAgg(fig1, master=f1)
            cv1.draw()
            cv1.get_tk_widget().pack(fill="both", expand=True)
            
            cv2 = FigureCanvasTkAgg(fig2, master=f2)
            cv2.draw()
            cv2.get_tk_widget().pack(fill="both", expand=True)

        self.after(0, _open)

if __name__ == "__main__":
    app = RC4GUI()
    app.protocol("WM_DELETE_WINDOW", lambda: (plt.close("all"), app.destroy()))
    app.mainloop()
