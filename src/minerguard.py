import os, sys, re, json, time, queue, threading, subprocess, platform
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = 'MinerGuard'
VERSION = '1.0.0'

try:
    import psutil
except Exception:
    psutil = None

SUSPICIOUS_NAMES = {
    'xmrig', 'minerd', 'miner', 'cpuminer', 'ethminer', 'phoenixminer',
    'nbminer', 'lolminer', 'teamredminer', 't-rex', 'trex', ' kawpowminer',
    'nanominer', 'gminer', 'claymore', 'srbminer', 'wildrig', 'verusminer'
}
SUSPICIOUS_TERMS = [
    'xmrig', 'stratum+tcp', 'stratum+ssl', 'mining.pool', 'cryptonight',
    'randomx', 'coinhive', 'cryptoloot', 'minergate', 'supportxmr',
    'nanopool', '2miners', 'unmineable', 'nicehash'
]
POOL_PORTS = {3333, 3334, 4444, 5555, 7777, 8888, 14444, 14433, 45560}
RISK_ORDER = {'Alto': 3, 'Medio': 2, 'Bajo': 1, 'Informativo': 0}


def run_command(args, timeout=12):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), errors='replace')
        return p.stdout.strip()
    except Exception:
        return ''


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class Scanner:
    def __init__(self, log):
        self.log = log
        self.findings = []

    def add(self, category, risk, title, details, path=''):
        self.findings.append({'category': category, 'risk': risk, 'title': title,
                              'details': details, 'path': path})
        self.log(f'[{risk}] {title} — {details}')

    def scan_processes(self):
        self.log('Analizando procesos y consumo de CPU...')
        if psutil is None:
            self.add('Procesos', 'Medio', 'No se pudo cargar psutil', 'Reinstala usando el instalador incluido.')
            return
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                p.cpu_percent(None)
                procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        time.sleep(1.2)
        for p in procs:
            try:
                info = p.info
                cpu = p.cpu_percent(None)
                name = (info.get('name') or '').lower()
                cmd = ' '.join(info.get('cmdline') or []).lower()
                exe = info.get('exe') or ''
                hay = name + ' ' + cmd + ' ' + exe.lower()
                hits = [term for term in SUSPICIOUS_TERMS if term in hay]
                base = Path(name).stem
                if base in SUSPICIOUS_NAMES or any(x in base for x in SUSPICIOUS_NAMES):
                    self.add('Procesos', 'Alto', f'Nombre asociado a minería: {info.get("name")}',
                             f'PID {info.get("pid")}; CPU {cpu:.1f}%; revisar antes de actuar.', exe)
                elif hits:
                    risk = 'Alto' if any(x in hay for x in ('xmrig', 'stratum+', 'coinhive')) else 'Medio'
                    self.add('Procesos', risk, f'Indicadores de minería en {info.get("name")}',
                             f'PID {info.get("pid")}; coincidencias: {", ".join(hits)}; CPU {cpu:.1f}%.', exe)
                elif cpu >= 70:
                    self.add('Consumo', 'Informativo', f'Consumo elevado: {info.get("name")}',
                             f'PID {info.get("pid")}; CPU {cpu:.1f}%. El consumo alto por sí solo no demuestra minería.', exe)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def scan_network(self):
        self.log('Revisando conexiones de red de procesos...')
        if psutil is None:
            return
        for p in psutil.process_iter(['pid', 'name']):
            try:
                for c in p.net_connections(kind='inet'):
                    if c.raddr and c.raddr.port in POOL_PORTS:
                        self.add('Red', 'Medio', f'Conexión a puerto usado por algunos pools: {p.info.get("name")}',
                                 f'PID {p.info.get("pid")}; destino {c.raddr.ip}:{c.raddr.port}. Estos puertos también pueden tener usos legítimos.')
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                pass

    def scan_startup(self):
        self.log('Revisando ubicaciones de inicio automático...')
        try:
            import winreg
            roots = [(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                     (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                     (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')]
            for root, keypath in roots:
                try:
                    key = winreg.OpenKey(root, keypath)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i); i += 1
                            text = f'{name} {value}'.lower()
                            hits = [x for x in SUSPICIOUS_TERMS if x in text]
                            if hits:
                                self.add('Inicio', 'Alto', f'Entrada de inicio sospechosa: {name}',
                                         f'Coincidencias: {", ".join(hits)}', str(value))
                            elif any(x in text for x in ('\\appdata\\local\\temp\\', '\\users\\public\\')):
                                self.add('Inicio', 'Bajo', f'Inicio desde ubicación poco habitual: {name}', str(value))
                        except OSError:
                            break
                except OSError:
                    pass
        except Exception as e:
            self.add('Inicio', 'Informativo', 'No se pudo revisar el registro', str(e))

    def scan_services_tasks(self):
        self.log('Revisando servicios y tareas programadas...')
        services = run_command(['powershell', '-NoProfile', '-Command',
            "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode | ConvertTo-Json -Compress"], 25)
        try:
            data = json.loads(services) if services else []
            if isinstance(data, dict): data = [data]
            for s in data:
                val = ' '.join(str(s.get(k, '')) for k in ('Name','DisplayName','PathName')).lower()
                hits = [x for x in SUSPICIOUS_TERMS if x in val]
                if hits:
                    self.add('Servicios', 'Alto', f'Servicio con indicadores: {s.get("Name")}',
                             f'Coincidencias: {", ".join(hits)}; inicio: {s.get("StartMode")}', str(s.get('PathName','')))
                elif any(x in val for x in ('\\appdata\\local\\temp\\', '\\users\\public\\')):
                    self.add('Servicios', 'Bajo', f'Servicio ejecutado desde ruta inusual: {s.get("Name")}', str(s.get('PathName','')))
        except Exception:
            self.add('Servicios', 'Informativo', 'No se pudo interpretar la lista de servicios', 'Ejecuta MinerGuard como administrador para ampliar el análisis.')
        tasks = run_command(['schtasks', '/query', '/fo', 'LIST', '/v'], 25).lower()
        for term in SUSPICIOUS_TERMS:
            if term in tasks:
                self.add('Tareas programadas', 'Medio', 'Indicador sospechoso en tareas programadas',
                         f'Se encontró el término "{term}" en la salida de tareas. Verifica la tarea manualmente.')
                break

    def scan_gpu(self):
        self.log('Comprobando actividad de GPU NVIDIA...')
        out = run_command(['nvidia-smi', '--query-gpu=name,utilization.gpu,memory.used,temperature.gpu', '--format=csv,noheader,nounits'], 8)
        if out:
            self.add('GPU', 'Informativo', 'GPU NVIDIA detectada', out.replace('\n', ' | ') + '. La utilización elevada no confirma minería.')
        else:
            self.add('GPU', 'Informativo', 'No se obtuvo información de NVIDIA', 'nvidia-smi no está disponible; puede que no tengas NVIDIA o que el controlador no lo exponga.')

    def scan_files(self):
        self.log('Buscando nombres conocidos en carpetas habituales...')
        roots = [os.environ.get('TEMP', ''), os.environ.get('LOCALAPPDATA', ''),
                 os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                 os.path.join(os.environ.get('PROGRAMDATA', ''), '')]
        checked = 0
        for root in roots:
            if not root or not os.path.isdir(root): continue
            for current, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d.lower() not in ('$recycle.bin', 'cache', 'node_modules')]
                for fn in files:
                    low = fn.lower()
                    if low.endswith(('.exe', '.bat', '.cmd', '.ps1')) and any(n in low for n in SUSPICIOUS_NAMES):
                        self.add('Archivos', 'Alto', f'Archivo con nombre asociado a minero: {fn}', current, os.path.join(current, fn))
                    checked += 1
                    if checked >= 12000:
                        self.log('Límite preventivo de 12 000 archivos alcanzado.')
                        return

    def run(self):
        self.findings = []
        self.scan_processes(); self.scan_network(); self.scan_startup()
        self.scan_services_tasks(); self.scan_gpu(); self.scan_files()
        return self.findings


class MinerGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f'{APP_NAME} {VERSION}')
        self.root.geometry('980x680')
        self.root.minsize(820, 580)
        self.root.configure(bg='#10151f')
        self.q = queue.Queue(); self.findings = []; self.scanning = False
        self.setup_style(); self.build_ui(); self.root.after(120, self.process_queue)

    def setup_style(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('TFrame', background='#10151f')
        s.configure('Panel.TFrame', background='#182231')
        s.configure('TLabel', background='#10151f', foreground='#e8eef7', font=('Segoe UI', 10))
        s.configure('Title.TLabel', font=('Segoe UI', 23, 'bold'), foreground='#f5f8ff')
        s.configure('Muted.TLabel', foreground='#9eacc0')
        s.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=10)
        s.configure('Treeview', background='#182231', fieldbackground='#182231', foreground='#e8eef7', rowheight=29, borderwidth=0)
        s.configure('Treeview.Heading', background='#263449', foreground='#e8eef7', font=('Segoe UI', 9, 'bold'))

    def build_ui(self):
        outer = ttk.Frame(self.root, padding=22); outer.pack(fill='both', expand=True)
        header = ttk.Frame(outer); header.pack(fill='x')
        ttk.Label(header, text='🛡  MinerGuard', style='Title.TLabel').pack(side='left')
        ttk.Label(header, text='WINDOWS SECURITY SCANNER  •  v'+VERSION, style='Muted.TLabel').pack(side='right', pady=12)
        ttk.Label(outer, text='Busca indicadores de minería no autorizada en tu equipo.', style='Muted.TLabel').pack(anchor='w', pady=(3,16))
        cards = ttk.Frame(outer); cards.pack(fill='x', pady=(0,14))
        self.status = tk.StringVar(value='Listo para analizar')
        self.count = tk.StringVar(value='0 hallazgos')
        for title, var in [('ESTADO', self.status), ('RESULTADOS', self.count)]:
            f = tk.Frame(cards, bg='#182231', padx=16, pady=12); f.pack(side='left', fill='x', expand=True, padx=(0,10))
            tk.Label(f, text=title, bg='#182231', fg='#91a2ba', font=('Segoe UI',8,'bold')).pack(anchor='w')
            tk.Label(f, textvariable=var, bg='#182231', fg='#f3f6fc', font=('Segoe UI',13,'bold')).pack(anchor='w', pady=(4,0))
        actions = ttk.Frame(outer); actions.pack(fill='x', pady=(0,12))
        self.scan_btn = ttk.Button(actions, text='▶  INICIAR ANÁLISIS COMPLETO', command=self.start_scan)
        self.scan_btn.pack(side='left')
        ttk.Button(actions, text='Guardar informe', command=self.save_report).pack(side='left', padx=8)
        ttk.Button(actions, text='Abrir Seguridad de Windows', command=self.open_security).pack(side='right')
        self.progress = ttk.Progressbar(outer, mode='indeterminate'); self.progress.pack(fill='x', pady=(0,12))
        cols = ('risk','category','title','details')
        self.tree = ttk.Treeview(outer, columns=cols, show='headings')
        for c, label, width in [('risk','RIESGO',85),('category','ÁREA',125),('title','DETECCIÓN',260),('details','DETALLES',430)]:
            self.tree.heading(c, text=label); self.tree.column(c, width=width, minwidth=70, anchor='w')
        self.tree.pack(fill='both', expand=True)
        self.tree.tag_configure('Alto', foreground='#ff8585'); self.tree.tag_configure('Medio', foreground='#ffd27a')
        self.tree.tag_configure('Bajo', foreground='#a9c8ff'); self.tree.tag_configure('Informativo', foreground='#b8c6d9')
        footer = ttk.Frame(outer); footer.pack(fill='x', pady=(12,0))
        ttk.Label(footer, text='MinerGuard no elimina ni modifica archivos. Los resultados requieren verificación.', style='Muted.TLabel').pack(side='left')
        ttk.Label(footer, text='Admin: '+('Sí' if is_admin() else 'No'), style='Muted.TLabel').pack(side='right')

    def log(self, message): self.q.put(('log', message))

    def start_scan(self):
        if self.scanning: return
        self.scanning = True; self.findings = []; self.tree.delete(*self.tree.get_children())
        self.status.set('Analizando...'); self.count.set('0 hallazgos'); self.progress.start(12); self.scan_btn.configure(state='disabled')
        def worker():
            try:
                scanner = Scanner(self.log); results = scanner.run(); self.q.put(('done', results))
            except Exception as e:
                self.q.put(('error', str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def process_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == 'log': self.status.set(payload)
                elif kind == 'done':
                    self.findings = payload; self.scanning = False; self.progress.stop(); self.scan_btn.configure(state='normal')
                    self.status.set('Análisis finalizado'); self.count.set(f'{len(payload)} hallazgos')
                    for f in payload:
                        self.tree.insert('', 'end', values=(f['risk'], f['category'], f['title'], f['details']), tags=(f['risk'],))
                    if not payload:
                        self.tree.insert('', 'end', values=('—','General','No se encontraron indicadores','Esto no garantiza que el equipo esté libre de malware.'))
                elif kind == 'error':
                    self.scanning = False; self.progress.stop(); self.scan_btn.configure(state='normal'); self.status.set('Error de análisis')
                    messagebox.showerror('MinerGuard', payload)
        except queue.Empty: pass
        self.root.after(120, self.process_queue)

    def save_report(self):
        if not self.findings:
            messagebox.showinfo('MinerGuard', 'Primero realiza un análisis.'); return
        path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Informe de texto','*.txt'),('JSON','*.json')], initialfile='MinerGuard-informe-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
        if not path: return
        report = {'app': APP_NAME, 'version': VERSION, 'date': datetime.now().isoformat(), 'computer': platform.node(), 'admin': is_admin(), 'findings': self.findings,
                  'notice': 'Los indicadores no son prueba definitiva de infección. Verifique antes de eliminar o deshabilitar elementos.'}
        try:
            if path.lower().endswith('.json'):
                with open(path,'w',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
            else:
                with open(path,'w',encoding='utf-8') as f:
                    f.write(f'MinerGuard {VERSION}\nFecha: {report["date"]}\nEquipo: {platform.node()}\n\n')
                    for x in self.findings: f.write(f'[{x["risk"]}] {x["category"]} — {x["title"]}\n{x["details"]}\nRuta: {x["path"]}\n\n')
                    f.write('\nLos indicadores no son prueba definitiva de infección.\n')
            messagebox.showinfo('MinerGuard', 'Informe guardado correctamente.')
        except Exception as e: messagebox.showerror('Error', str(e))

    def open_security(self):
        try: os.startfile('windowsdefender:')
        except Exception: run_command(['powershell','-NoProfile','-Command','Start-Process windowsdefender:'])


def main():
    if os.name != 'nt':
        print('MinerGuard está diseñado para Windows.'); return
    root = tk.Tk(); MinerGuardApp(root); root.mainloop()

if __name__ == '__main__': main()
