# app.py - DAN + LogSight AI Desktop App
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import webbrowser
from datetime import datetime
import json

# Import modules
try:
    from modules.storage import list_all_incidents, load_incident
    from modules.diagram_generator import create_attack_diagram, create_network_flow_diagram
    from modules.report_generator import generate_report, generate_comprehensive_report
    from modules.email_manager import load_customers, save_customer, delete_customer, load_all_reports, \
        save_report_record
    from config import DIAGRAMS_DIR, REPORTS_DIR, CUSTOMERS_FILE, WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD
except Exception as e:
    messagebox.showerror("Startup Error", f"Failed to load modules:\n{str(e)}")
    exit()

# App Info
APP_NAME = "DAN"
APP_VERSION = "v1.0"
AUTHOR_NAME = "Danish Mir"
LINKEDIN_URL = "https://www.linkedin.com/in/danishahmadmir/"
CONTACT_EMAIL = "Heezaizme@gmail.com"

# Colors
GLASS_BG = "#1a1b26"
GLASS_FG = "#a9b1d6"
ACCENT_COLOR = "#7aa2f7"
HIGHLIGHT_COLOR = "#bb9af7"
SUCCESS_COLOR = "#9ece6a"
WARNING_COLOR = "#e0af68"
ERROR_COLOR = "#f7768e"


class GlassFrame(tk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, bg=GLASS_BG, **kwargs)
        self.configure(relief=tk.RAISED, bd=1)


class GlassButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            bg=ACCENT_COLOR,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            bd=0,
            padx=15,
            pady=5,
            cursor="hand2"
        )
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self.configure(bg=HIGHLIGHT_COLOR)

    def on_leave(self, e):
        self.configure(bg=ACCENT_COLOR)


def show_splash_screen(root):
    """Enhanced SIEM Integration Splash Screen"""
    splash = tk.Toplevel(root)
    splash.title("LogSight AI - SIEM Integration")
    splash.geometry("600x500")
    splash.configure(bg="#1a1b26")
    splash.transient(root)
    splash.grab_set()
    splash.resizable(False, False)
    
    # Center the window
    splash.update_idletasks()
    x = (splash.winfo_screenwidth() // 2) - (600 // 2)
    y = (splash.winfo_screenheight() // 2) - (500 // 2)
    splash.geometry(f"600x500+{x}+{y}")

    # Title
    title_frame = tk.Frame(splash, bg="#1a1b26")
    title_frame.pack(pady=20)
    
    title = tk.Label(title_frame, text="🛡️ DAN", font=("Segoe UI", 18, "bold"),
                     fg=ACCENT_COLOR, bg="#1a1b26")
    title.pack()
    
    subtitle = tk.Label(title_frame, text="Security Intelligence & Incident Reporting",
                       font=("Segoe UI", 10), fg=GLASS_FG, bg="#1a1b26")
    subtitle.pack(pady=(5, 0))

    # SIEM Configuration Frame
    config_frame = GlassFrame(splash)
    config_frame.pack(fill=tk.X, padx=40, pady=20)
    
    tk.Label(config_frame, text="🔌 SIEM Integration Setup", font=("Segoe UI", 12, "bold"),
             fg=ACCENT_COLOR, bg=GLASS_BG).pack(pady=10)
    
    # SIEM Type Selection
    siem_type_frame = tk.Frame(config_frame, bg=GLASS_BG)
    siem_type_frame.pack(fill=tk.X, padx=20, pady=10)
    
    tk.Label(siem_type_frame, text="SIEM Platform:", font=("Segoe UI", 9, "bold"),
             fg=GLASS_FG, bg=GLASS_BG).pack(anchor=tk.W)
    
    siem_var = tk.StringVar(value="Wazuh")
    siem_combo = ttk.Combobox(siem_type_frame, textvariable=siem_var,
                              values=["Wazuh"],
                              state="readonly", width=30)
    siem_combo.pack(fill=tk.X, pady=5)
    
    # Configuration Fields
    fields_frame = tk.Frame(config_frame, bg=GLASS_BG)
    fields_frame.pack(fill=tk.X, padx=20, pady=10)
    
    # URL Field
    tk.Label(fields_frame, text="SIEM URL:", font=("Segoe UI", 9, "bold"),
             fg=GLASS_FG, bg=GLASS_BG).grid(row=0, column=0, sticky=tk.W, pady=5)
    url_var = tk.StringVar(value="https://10.118.20.164:55000")
    url_entry = tk.Entry(fields_frame, textvariable=url_var, width=40,
                         font=("Segoe UI", 9), bg="#3a3a3a", fg=GLASS_FG)
    url_entry.grid(row=0, column=1, padx=(10, 0), pady=5, sticky=tk.W+tk.E)
    
    # Username Field
    tk.Label(fields_frame, text="Username:", font=("Segoe UI", 9, "bold"),
             fg=GLASS_FG, bg=GLASS_BG).grid(row=1, column=0, sticky=tk.W, pady=5)
    user_var = tk.StringVar(value="wazuh_user")
    user_entry = tk.Entry(fields_frame, textvariable=user_var, width=40,
                          font=("Segoe UI", 9), bg="#3a3a3a", fg=GLASS_FG)
    user_entry.grid(row=1, column=1, padx=(10, 0), pady=5, sticky=tk.W+tk.E)
    
    # Password Field
    tk.Label(fields_frame, text="Password:", font=("Segoe UI", 9, "bold"),
             fg=GLASS_FG, bg=GLASS_BG).grid(row=2, column=0, sticky=tk.W, pady=5)
    pass_var = tk.StringVar(value="wazuh")
    pass_entry = tk.Entry(fields_frame, textvariable=pass_var, width=40, show="*",
                          font=("Segoe UI", 9), bg="#3a3a3a", fg=GLASS_FG)
    pass_entry.grid(row=2, column=1, padx=(10, 0), pady=5, sticky=tk.W+tk.E)
    
    # Configure grid weights
    fields_frame.grid_columnconfigure(1, weight=1)
    
    # Status Frame
    status_frame = tk.Frame(config_frame, bg=GLASS_BG)
    status_frame.pack(fill=tk.X, padx=20, pady=10)
    
    status_label = tk.Label(status_frame, text="🟡 Ready to test connection",
                           font=("Segoe UI", 9), fg=WARNING_COLOR, bg=GLASS_BG)
    status_label.pack()
    
    # Buttons Frame
    buttons_frame = tk.Frame(config_frame, bg=GLASS_BG)
    buttons_frame.pack(fill=tk.X, padx=20, pady=15)
    
    def test_connection():
        """Test SIEM connection"""
        status_label.config(text="🔄 Testing connection...", fg=WARNING_COLOR)
        splash.update()
        
        try:
            # Import and test connection
            import requests
            from requests.auth import HTTPBasicAuth
            
            url = url_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get().strip()
            
            if not all([url, username, password]):
                status_label.config(text="❌ Please fill all fields", fg=ERROR_COLOR)
                return
            
            # Test endpoint (Wazuh API info endpoint)
            test_url = f"{url.rstrip('/')}/"
            
            response = requests.get(test_url, 
                                  auth=HTTPBasicAuth(username, password),
                                  verify=False, timeout=10)
            
            if response.status_code == 200:
                status_label.config(text="✅ Connection successful!", fg=SUCCESS_COLOR)
                save_btn.config(state="normal")
            else:
                status_label.config(text=f"❌ Connection failed (Status: {response.status_code})", fg=ERROR_COLOR)
                
        except requests.exceptions.ConnectTimeout:
            status_label.config(text="❌ Connection timeout - Check URL and network", fg=ERROR_COLOR)
        except requests.exceptions.ConnectionError:
            status_label.config(text="❌ Cannot connect - Check URL and firewall", fg=ERROR_COLOR)
        except Exception as e:
            status_label.config(text=f"❌ Error: {str(e)[:50]}...", fg=ERROR_COLOR)
    
    def save_config_and_start():
        """Save configuration and start the app"""
        try:
            # Update config.py with new values
            url = url_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get().strip()
            
            # Read current config
            config_path = "config.py"
            with open(config_path, 'r') as f:
                config_content = f.read()
            
            # Update values
            import re
            config_content = re.sub(r'WAZUH_URL = "[^"]*"', f'WAZUH_URL = "{url}"', config_content)
            config_content = re.sub(r'WAZUH_USER = "[^"]*"', f'WAZUH_USER = "{username}"', config_content)
            config_content = re.sub(r'WAZUH_PASSWORD = "[^"]*"', f'WAZUH_PASSWORD = "{password}"', config_content)
            
            # Save updated config
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            status_label.config(text="✅ Configuration saved!", fg=SUCCESS_COLOR)
            splash.after(1000, splash.destroy)  # Close after 1 second
            
        except Exception as e:
            status_label.config(text=f"❌ Save failed: {str(e)[:30]}...", fg=ERROR_COLOR)
    
    def skip_config():
        """Skip configuration and start with defaults"""
        splash.destroy()
    
    # Test Connection Button
    test_btn = GlassButton(buttons_frame, text="🔌 Test Connection", command=test_connection)
    test_btn.pack(side=tk.LEFT, padx=(0, 10))
    
    # Save and Start Button
    save_btn = GlassButton(buttons_frame, text="✅ Save & Start", command=save_config_and_start)
    save_btn.pack(side=tk.LEFT, padx=(0, 10))
    save_btn.config(state="disabled")  # Enable only after successful test
    
    # Skip Button
    skip_btn = GlassButton(buttons_frame, text="⏭️ Skip for Now", command=skip_config)
    skip_btn.pack(side=tk.RIGHT)
    
    # Info Frame
    info_frame = tk.Frame(splash, bg="#1a1b26")
    info_frame.pack(fill=tk.X, padx=40, pady=10)
    
    info_text = "Connect your SIEM to automatically import incidents and generate real-time reports.\n" \
                "You can also use the app with sample data by clicking 'Skip for Now'."
    
    tk.Label(info_frame, text=info_text, font=("Segoe UI", 8),
             fg="#7a7a7a", bg="#1a1b26", justify=tk.CENTER, wraplength=500).pack()


class DANApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DAN")
        self.root.state('zoomed')
        self.root.configure(bg="#0a0e14")
        self.current_incident = None
        self.all_report_data = []
        self.customer_filter_var = tk.StringVar(value="All Customers")
        self.severity_filter_var = tk.StringVar(value="All")
        self.date_from_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-01"))
        self.date_to_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))

        # Show splash screen
        show_splash_screen(root)

        self.setup_ui()
        self.load_incidents()
    
    def check_siem_status(self):
        """Check SIEM connectivity status"""
        try:
            from modules.wazuh_connector import test_wazuh_connection
            result = test_wazuh_connection()
            
            if result["success"]:
                self.siem_status_label.config(text="✅ SIEM: Connected", fg=SUCCESS_COLOR)
            else:
                self.siem_status_label.config(text=f"❌ SIEM: {result['message']}", fg=ERROR_COLOR)
                
        except Exception as e:
            self.siem_status_label.config(text="🟡 SIEM: Demo Mode", fg=WARNING_COLOR)
    
    def update_settings_siem_status(self):
        """Update SIEM status in settings tab"""
        try:
            from modules.wazuh_connector import test_wazuh_connection
            result = test_wazuh_connection()
            
            if result["success"]:
                status_text = f"✅ Connected to SIEM at {WAZUH_URL}"
                self.settings_siem_status.config(text=status_text, fg=SUCCESS_COLOR)
            else:
                status_text = f"❌ SIEM Connection Failed: {result['message']}"
                self.settings_siem_status.config(text=status_text, fg=ERROR_COLOR)
                
        except Exception as e:
            self.settings_siem_status.config(text="🟡 SIEM: Demo Mode - Using sample data", fg=WARNING_COLOR)
    
    def show_siem_config(self):
        """Show SIEM configuration dialog"""
        show_splash_screen(self.root)
    
    def test_siem_connection(self):
        """Test current SIEM connection"""
        try:
            from modules.wazuh_connector import test_wazuh_connection
            result = test_wazuh_connection()
            
            if result["success"]:
                messagebox.showinfo("SIEM Test", f"✅ SIEM connection successful!\n\nURL: {WAZUH_URL}\nUser: {WAZUH_USER}")
                self.check_siem_status()  # Update main status
                self.update_settings_siem_status()  # Update settings status
            else:
                messagebox.showerror("SIEM Test", f"❌ SIEM connection failed!\n\nError: {result['message']}\nURL: {WAZUH_URL}")
                
        except Exception as e:
            messagebox.showerror("SIEM Test", f"❌ Test failed!\n\nError: {str(e)}")

    def setup_ui(self):
        main_frame = GlassFrame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        header_frame = GlassFrame(main_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="DAN", font=("Segoe UI", 16, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(side=tk.LEFT, padx=10)
        self.time_label = tk.Label(header_frame, font=("Segoe UI", 10),
                                   fg=GLASS_FG, bg=GLASS_BG)
        self.time_label.pack(side=tk.RIGHT, padx=10)
        self.update_time()

        status_frame = GlassFrame(main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=2)
        self.status_label = tk.Label(status_frame, text="🟢 System Ready", font=("Segoe UI", 9),
                                     fg=SUCCESS_COLOR, bg=GLASS_BG)
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # SIEM Status Indicator
        self.siem_status_label = tk.Label(status_frame, text="🟡 SIEM: Checking...", font=("Segoe UI", 9),
                                         fg=WARNING_COLOR, bg=GLASS_BG)
        self.siem_status_label.pack(side=tk.LEFT, padx=20)
        
        self.stats_label = tk.Label(status_frame, text="Incidents: 0 | Critical: 0",
                                    font=("Segoe UI", 9), fg=GLASS_FG, bg=GLASS_BG)
        self.stats_label.pack(side=tk.RIGHT, padx=10)
        
        # Check SIEM status after UI setup
        self.root.after(1000, self.check_siem_status)

        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left_panel = GlassFrame(paned)
        paned.add(left_panel, weight=1)

        right_panel = GlassFrame(paned)
        paned.add(right_panel, weight=2)

        self.setup_left_panel(left_panel)
        self.setup_right_panel(right_panel)

    def setup_left_panel(self, parent):
        search_frame = GlassFrame(parent)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(search_frame, text="🔍 Search Incidents", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W, padx=2)
        self.search_var = tk.StringVar()
        entry = tk.Entry(search_frame, textvariable=self.search_var, font=("Segoe UI", 9),
                         bg="#3a3a3a", fg=GLASS_FG, insertbackground=GLASS_FG)
        entry.pack(fill=tk.X, pady=2)
        entry.bind('<KeyRelease>', self.filter_incidents)

        filter_frame = GlassFrame(parent)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(filter_frame, text="📊 Filters", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W, padx=2)
        tk.Label(filter_frame, text="Severity:", fg=GLASS_FG, bg=GLASS_BG).pack(anchor=tk.W, pady=(2, 0))
        self.severity_var = tk.StringVar(value="All")
        combo = ttk.Combobox(filter_frame, textvariable=self.severity_var,
                             values=["All", "Critical", "High", "Medium", "Low"],
                             state="readonly", font=("Segoe UI", 9))
        combo.pack(fill=tk.X, pady=2)
        combo.bind('<<ComboboxSelected>>', self.filter_incidents)

        list_frame = GlassFrame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tk.Label(list_frame, text="📋 Recent Incidents", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W, pady=(0, 2))

        columns = ('time', 'type', 'severity')
        self.incident_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        self.incident_tree.heading('time', text='Time', anchor=tk.W)
        self.incident_tree.heading('type', text='Type', anchor=tk.W)
        self.incident_tree.heading('severity', text='Level', anchor=tk.W)
        self.incident_tree.column('time', width=80, stretch=True)
        self.incident_tree.column('type', width=100, stretch=True)
        self.incident_tree.column('severity', width=60, stretch=True)

        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.incident_tree.yview)
        self.incident_tree.configure(yscrollcommand=scroll.set)
        self.incident_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.incident_tree.bind('<<TreeviewSelect>>', self.on_incident_select)

        refresh_btn = GlassButton(parent, text="🔄 Refresh", command=self.load_incidents)
        refresh_btn.pack(pady=5, fill=tk.X, padx=5)

    def setup_right_panel(self, parent):
        tab_control = ttk.Notebook(parent)
        tab_control.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_overview = GlassFrame(tab_control)
        self.tab_flow = GlassFrame(tab_control)
        self.tab_report = GlassFrame(tab_control)
        self.tab_settings = GlassFrame(tab_control)

        tab_control.add(self.tab_overview, text="📋 Incident Details")
        tab_control.add(self.tab_flow, text="📊 Incident Analytics")
        tab_control.add(self.tab_report, text="📄 Generate Report")
        tab_control.add(self.tab_settings, text="⚙️ Settings")

        self.setup_overview_tab()
        self.setup_flow_tab()
        self.setup_report_tab()
        self.setup_settings_tab()

    def setup_overview_tab(self):
        overview_paned = ttk.PanedWindow(self.tab_overview, orient=tk.VERTICAL)
        overview_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        top_frame = GlassFrame(overview_paned)
        overview_paned.add(top_frame, weight=1)

        detail_notebook = ttk.Notebook(top_frame)
        detail_notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        basic_frame = GlassFrame(detail_notebook)
        detail_notebook.add(basic_frame, text="📝 Basic Info")
        self.basic_info_text = scrolledtext.ScrolledText(basic_frame, bg=GLASS_BG, fg=GLASS_FG,
                                                         font=("Consolas", 9), wrap=tk.WORD)
        self.basic_info_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        logs_frame = GlassFrame(detail_notebook)
        detail_notebook.add(logs_frame, text="📊 Related Logs")
        log_columns = ('timestamp', 'source', 'destination', 'event_type')
        self.logs_tree = ttk.Treeview(logs_frame, columns=log_columns, show='headings', height=8)
        self.logs_tree.heading('timestamp', text='Timestamp')
        self.logs_tree.heading('source', text='Source')
        self.logs_tree.heading('destination', text='Destination')
        self.logs_tree.heading('event_type', text='Event Type')
        self.logs_tree.column('timestamp', width=120)
        self.logs_tree.column('source', width=100)
        self.logs_tree.column('destination', width=100)
        self.logs_tree.column('event_type', width=180)
        log_scroll = ttk.Scrollbar(logs_frame, orient="vertical", command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=log_scroll.set)
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Raw JSON display frame
        json_frame = GlassFrame(detail_notebook)
        detail_notebook.add(json_frame, text="📜 Raw JSON")
        self.json_text = scrolledtext.ScrolledText(json_frame, bg=GLASS_BG, fg=GLASS_FG,
                                                   font=("Consolas", 9), wrap=tk.WORD)
        self.json_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

    def setup_flow_tab(self):
        """Setup incident analytics tab with P1/P2/P3/P4 graph"""
        flow_frame = GlassFrame(self.tab_flow)
        flow_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Title
        tk.Label(flow_frame, text="🎯 Incident Severity Analytics", font=("Segoe UI", 12, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(pady=10)
        
        # Analytics canvas frame
        canvas_frame = GlassFrame(flow_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs within analytics
        from tkinter import ttk
        analytics_notebook = ttk.Notebook(canvas_frame)
        analytics_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Chart tab
        chart_tab = GlassFrame(analytics_notebook)
        analytics_notebook.add(chart_tab, text="📊 Priority Chart")
        
        # Create canvas for analytics with better sizing
        from tkinter import Canvas
        
        self.analytics_canvas = Canvas(chart_tab, bg="white", width=800, height=500)
        self.analytics_canvas.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        
        # All Incidents tab
        incidents_tab = GlassFrame(analytics_notebook)
        analytics_notebook.add(incidents_tab, text="📋 All Incidents")
        
        # Setup incidents table
        self.setup_incidents_table(incidents_tab)
        
        # Control buttons
        control_frame = tk.Frame(flow_frame, bg=GLASS_BG)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        refresh_btn = GlassButton(control_frame, text="📊 Generate Linear Analytics", command=self.generate_incident_analytics)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = GlassButton(control_frame, text="💾 Export Chart", command=self.export_analytics)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Add Generate All Reports button
        all_reports_btn = GlassButton(control_frame, text="📊 Generate All Reports", command=self.generate_all_reports)
        all_reports_btn.pack(side=tk.LEFT, padx=5)
        
        # Add Test Data button for debugging
        test_btn = GlassButton(control_frame, text="🔍 Test Data", command=self.test_incident_data)
        test_btn.pack(side=tk.LEFT, padx=5)
        
        # Generate initial analytics after a delay to ensure canvas is ready
        self.root.after(5000, self.generate_incident_analytics)
    
    def setup_incidents_table(self, parent):
        """Setup the all incidents table with filtering"""
        # Filter frame
        filter_frame = GlassFrame(parent)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Priority filter
        tk.Label(filter_frame, text="Filter by Priority:", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(side=tk.LEFT, padx=(5, 10))
        
        self.all_incidents_priority_var = tk.StringVar(value="All")
        priority_combo = ttk.Combobox(filter_frame, textvariable=self.all_incidents_priority_var,
                                     values=["All", "P1 (Critical)", "P2 (High)", "P3 (Medium)", "P4 (Low)"],
                                     state="readonly", width=15)
        priority_combo.pack(side=tk.LEFT, padx=(0, 10))
        priority_combo.bind('<<ComboboxSelected>>', self.filter_all_incidents)
        
        # Search box
        tk.Label(filter_frame, text="Search:", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(side=tk.LEFT, padx=(10, 5))
        
        self.all_incidents_search_var = tk.StringVar()
        search_entry = tk.Entry(filter_frame, textvariable=self.all_incidents_search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=(0, 10))
        search_entry.bind('<KeyRelease>', self.filter_all_incidents)
        
        # Refresh button
        refresh_all_btn = GlassButton(filter_frame, text="🔄 Refresh", command=self.load_all_incidents_table)
        refresh_all_btn.pack(side=tk.LEFT, padx=5)
        
        # Stats label
        self.all_incidents_stats = tk.Label(filter_frame, text="Loading...", font=("Segoe UI", 9),
                                           fg=GLASS_FG, bg=GLASS_BG)
        self.all_incidents_stats.pack(side=tk.RIGHT, padx=5)
        
        # Table frame
        table_frame = GlassFrame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for all incidents
        columns = ('incident_id', 'timestamp', 'priority', 'attack_type', 'src_ip', 'threat_score')
        self.all_incidents_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.all_incidents_tree.heading('incident_id', text='Incident ID')
        self.all_incidents_tree.heading('timestamp', text='Timestamp')
        self.all_incidents_tree.heading('priority', text='Priority')
        self.all_incidents_tree.heading('attack_type', text='Attack Type')
        self.all_incidents_tree.heading('src_ip', text='Source IP')
        self.all_incidents_tree.heading('threat_score', text='Threat Score')
        
        # Configure column widths
        self.all_incidents_tree.column('incident_id', width=100)
        self.all_incidents_tree.column('timestamp', width=120)
        self.all_incidents_tree.column('priority', width=80)
        self.all_incidents_tree.column('attack_type', width=200)
        self.all_incidents_tree.column('src_ip', width=100)
        self.all_incidents_tree.column('threat_score', width=80)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.all_incidents_tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.all_incidents_tree.xview)
        self.all_incidents_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Pack table and scrollbars
        self.all_incidents_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind double-click to show details
        self.all_incidents_tree.bind('<Double-1>', self.on_all_incidents_select)
        
        # Control buttons for all incidents
        all_incidents_controls = tk.Frame(parent, bg=GLASS_BG)
        all_incidents_controls.pack(fill=tk.X, padx=5, pady=5)
        
        select_all_btn = GlassButton(all_incidents_controls, text="✓ Select All", command=self.select_all_incidents)
        select_all_btn.pack(side=tk.LEFT, padx=5)
        
        clear_selection_btn = GlassButton(all_incidents_controls, text="✘ Clear Selection", command=self.clear_all_incidents_selection)
        clear_selection_btn.pack(side=tk.LEFT, padx=5)
        
        export_selected_btn = GlassButton(all_incidents_controls, text="💾 Export Selected", command=self.export_selected_incidents)
        export_selected_btn.pack(side=tk.LEFT, padx=5)
        
        # Load initial data
        self.root.after(2000, self.load_all_incidents_table)



    def setup_report_tab(self):
        report_frame = GlassFrame(self.tab_report)
        report_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Instructions
        instruction_label = tk.Label(report_frame, 
                                    text="Select an incident from the left panel to generate a security report.",
                                    font=("Segoe UI", 11), fg=GLASS_FG, bg=GLASS_BG, justify=tk.CENTER)
        instruction_label.pack(pady=20)
        
        # Status display
        self.report_text = scrolledtext.ScrolledText(report_frame, bg=GLASS_BG, fg=GLASS_FG,
                                                     font=("Segoe UI", 9), wrap=tk.WORD, height=15)
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Control buttons
        control_frame = tk.Frame(report_frame, bg=GLASS_BG)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Single incident report buttons
        single_frame = tk.Frame(control_frame, bg=GLASS_BG)
        single_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        tk.Label(single_frame, text="Single Incident:", font=("Segoe UI", 9, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W)
        
        generate_btn = GlassButton(single_frame, text="📄 Generate Report", command=self.generate_report)
        generate_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        export_btn = GlassButton(single_frame, text="💾 Export", command=self.export_to_downloads)
        export_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        send_btn = GlassButton(single_frame, text="📧 Send", command=self.send_report)
        send_btn.pack(side=tk.LEFT)
        
        # All incidents report buttons
        all_frame = tk.Frame(control_frame, bg=GLASS_BG)
        all_frame.pack(side=tk.LEFT)
        
        tk.Label(all_frame, text="All Incidents:", font=("Segoe UI", 9, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W)
        
        all_generate_btn = GlassButton(all_frame, text="📊 Generate All Reports", command=self.generate_all_reports_with_choice)
        all_generate_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        all_export_btn = GlassButton(all_frame, text="💾 Export All", command=self.export_all_reports)
        all_export_btn.pack(side=tk.LEFT)





    def setup_settings_tab(self):
        settings_frame = GlassFrame(self.tab_settings)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        info_card = GlassFrame(settings_frame)
        info_card.pack(fill=tk.X, pady=5)
        tk.Label(info_card, text=f"{APP_NAME}", font=("Segoe UI", 12, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(pady=2)
        tk.Label(info_card, text=f"Version {APP_VERSION}", font=("Segoe UI", 9),
                 fg=GLASS_FG, bg=GLASS_BG).pack()
        tk.Label(info_card, text=f"👤 {AUTHOR_NAME}", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(pady=2)
        
        # LinkedIn profile link
        linkedin_label = tk.Label(info_card, text="🔗 LinkedIn Profile", font=("Segoe UI", 9),
                                  fg=ACCENT_COLOR, bg=GLASS_BG, cursor="hand2")
        linkedin_label.pack(padx=5, pady=2)
        linkedin_label.bind("<Button-1>", lambda e: webbrowser.open(LINKEDIN_URL))
        
        # Contact email
        contact_label = tk.Label(info_card, text=f"📧 {CONTACT_EMAIL}", font=("Segoe UI", 9),
                                 fg=ACCENT_COLOR, bg=GLASS_BG, cursor="hand2")
        contact_label.pack(padx=5, pady=2)
        contact_label.bind("<Button-1>", lambda e: webbrowser.open(f"mailto:{CONTACT_EMAIL}"))
        
        # Reports location info
        reports_card = GlassFrame(settings_frame)
        reports_card.pack(fill=tk.X, pady=5)
        tk.Label(reports_card, text="📁 Report Storage", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W, padx=5, pady=2)
        tk.Label(reports_card, text=f"Reports saved to: {REPORTS_DIR}", font=("Segoe UI", 9),
                 fg=GLASS_FG, bg=GLASS_BG).pack(anchor=tk.W, padx=5)
        
        # Data management
        data_card = GlassFrame(settings_frame)
        data_card.pack(fill=tk.X, pady=5)
        tk.Label(data_card, text="🗂️ Data Management", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W, padx=5, pady=2)
        tk.Label(data_card, text="JSON incident files can be manually managed in the data/incidents directory.", 
                 font=("Segoe UI", 9), fg=GLASS_FG, bg=GLASS_BG, wraplength=400).pack(anchor=tk.W, padx=5)
        
        # SIEM Integration
        siem_card = GlassFrame(settings_frame)
        siem_card.pack(fill=tk.X, pady=5)
        tk.Label(siem_card, text="🔌 SIEM Integration", font=("Segoe UI", 10, "bold"),
                 fg=ACCENT_COLOR, bg=GLASS_BG).pack(anchor=tk.W, padx=5, pady=2)
        
        # Current SIEM status
        siem_status_frame = tk.Frame(siem_card, bg=GLASS_BG)
        siem_status_frame.pack(fill=tk.X, padx=5)
        
        self.settings_siem_status = tk.Label(siem_status_frame, text="Checking SIEM status...",
                                           font=("Segoe UI", 9), fg=GLASS_FG, bg=GLASS_BG)
        self.settings_siem_status.pack(anchor=tk.W, pady=2)
        
        # SIEM action buttons
        siem_buttons_frame = tk.Frame(siem_card, bg=GLASS_BG)
        siem_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        reconfig_btn = GlassButton(siem_buttons_frame, text="🔧 Reconfigure SIEM", 
                                   command=self.show_siem_config)
        reconfig_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        test_btn = GlassButton(siem_buttons_frame, text="🔌 Test Connection", 
                              command=self.test_siem_connection)
        test_btn.pack(side=tk.LEFT)
        
        # Update SIEM status in settings
        self.root.after(2000, self.update_settings_siem_status)



    def load_incidents(self):
        for item in self.incident_tree.get_children():
            self.incident_tree.delete(item)
        incidents = list_all_incidents()
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for inc in incidents:
            incident_data = load_incident(inc)
            if incident_data:
                severity_val = incident_data.get('severity', 0)
                level = ("Critical" if severity_val >= 8 else
                         "High" if severity_val >= 6 else
                         "Medium" if severity_val >= 4 else "Low")
                severity_count[level] += 1
                self.incident_tree.insert('', 'end', text=inc, values=(
                    incident_data.get('timestamp', 'N/A'),
                    incident_data.get('attack_type', 'N/A'),
                    level
                ))
        self.stats_label.config(
            text=f"Incidents: {len(incidents)} | Critical: {severity_count['Critical']} | High: {severity_count['High']}")
        self.status_label.config(text=f"🟢 Loaded {len(incidents)} incidents")

    def filter_incidents(self, event=None):
        search_term = self.search_var.get().lower()
        selected_severity = self.severity_var.get()

        for item in self.incident_tree.get_children():
            self.incident_tree.delete(item)

        incidents = list_all_incidents()
        for inc in incidents:
            incident_data = load_incident(inc)
            if incident_data:
                attack_type = incident_data.get('attack_type', '').lower()
                timestamp = incident_data.get('timestamp', '')
                severity_val = incident_data.get('severity', 0)
                level = ("Critical" if severity_val >= 8 else
                         "High" if severity_val >= 6 else
                         "Medium" if severity_val >= 4 else "Low")

                matches_search = search_term in attack_type or search_term in timestamp
                if search_term and not matches_search:
                    continue

                if selected_severity != "All" and level != selected_severity:
                    continue

                self.incident_tree.insert('', 'end', text=inc, values=(
                    incident_data.get('timestamp', 'N/A'),
                    incident_data.get('attack_type', 'N/A'),
                    level
                ))

    def on_incident_select(self, event):
        selection = self.incident_tree.selection()
        if not selection:
            return
        item = self.incident_tree.item(selection[0])
        inc_id = item['text']
        self.current_incident = load_incident(inc_id)
        if self.current_incident:
            self.show_overview()
            self.status_label.config(text=f"🔍 Selected incident: {inc_id}")

    def show_overview(self):
        if not self.current_incident:
            return
        inc = self.current_incident
        self.basic_info_text.delete(1.0, tk.END)
        summary = f"""INCIDENT: {inc['incident_id']}
TIMESTAMP: {inc.get('timestamp', 'N/A')}
ATTACK TYPE: {inc['attack_type']}
SOURCE IP: {inc['src_ip']}
DESTINATION IP: {inc.get('dst_ip', 'N/A')}
SEVERITY: {inc['severity']}
THREAT SCORE: {inc['threat_score']}/10
CONFIDENCE: {inc['confidence']}
EVENTS: {inc['event_count']}
MITRE ATT&CK: {inc.get('mitre_id', 'T1000')} - {inc.get('mitre_name', 'Unknown')}
DESCRIPTION:
{inc.get('description', 'No description available')}
RECOMMENDED ACTION:
{inc.get('recommendation', 'No recommendations available')}
"""
        self.basic_info_text.insert(tk.END, summary)
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        if 'related_logs' in inc:
            for log in inc['related_logs']:
                self.logs_tree.insert('', 'end', values=(
                    log.get('timestamp', 'N/A'),
                    log.get('src_ip', 'N/A'),
                    log.get('dst_ip', 'N/A'),
                    log.get('event_type', 'N/A')
                ))
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, f"Incident {inc['incident_id']} selected.\n\nClick 'Generate Security Report' to create a detailed report.")
        
        # Display raw JSON data
        self.json_text.delete(1.0, tk.END)
        self.json_text.insert(tk.END, json.dumps(inc, indent=2))



    def generate_report(self):
        if not self.current_incident:
            messagebox.showwarning("No Selection", "Please select an incident first.")
            return
        try:
            # Generate attack diagram (uses real incident data)
            attack_diag = create_attack_diagram(self.current_incident)
            
            # Network flow diagram is disabled (was using fake data)
            src = self.current_incident['related_logs'][0]['src_ip']
            dst = self.current_incident['related_logs'][0].get('dst_ip', 'N/A')
            flow_diag = None  # Disabled fake network topology
            
            # Generate the report
            report_path = generate_report(self.current_incident, attack_diag, flow_diag)
            
            self.status_label.config(text="🟢 Report generated!")
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, f"✅ Security Report Generated Successfully!\n\n")
            self.report_text.insert(tk.END, f"Location: {report_path}\n\n")
            self.report_text.insert(tk.END, f"Incident ID: {self.current_incident['incident_id']}\n")
            self.report_text.insert(tk.END, f"Attack Type: {self.current_incident['attack_type']}\n")
            self.report_text.insert(tk.END, f"Source IP: {src}\n")
            self.report_text.insert(tk.END, f"Destination IP: {dst}\n\n")
            self.report_text.insert(tk.END, "The report includes:\n")
            self.report_text.insert(tk.END, "- Incident details and metadata\n")
            self.report_text.insert(tk.END, "- Attack chain diagram (real data)\n")
            self.report_text.insert(tk.END, "- Security recommendations\n")
            
            messagebox.showinfo("Success", f"Security report generated successfully!\n\nSaved to:\n{report_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed:\n{str(e)}")
            self.status_label.config(text="❌ Report generation failed")
    
    def export_to_downloads(self):
        """Export the current incident report directly to Downloads folder"""
        if not self.current_incident:
            messagebox.showwarning("No Selection", "Please select an incident first.")
            return
            
        try:
            # Generate the report first
            attack_diag = create_attack_diagram(self.current_incident)
            src = self.current_incident['related_logs'][0]['src_ip']
            dst = self.current_incident['related_logs'][0].get('dst_ip', 'N/A')
            flow_diag = None  # Disabled fake network topology
            
            # Generate the report
            report_path = generate_report(self.current_incident, attack_diag, flow_diag)
            
            # Get Downloads folder path
            import os
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
            
            # Create filename with timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.current_incident['incident_id']}_SecurityReport_{timestamp}.docx"
            destination_path = os.path.join(downloads_path, filename)
            
            # Copy report to Downloads folder
            import shutil
            shutil.copy2(report_path, destination_path)
            
            self.status_label.config(text="🟢 Report exported to Downloads!")
            messagebox.showinfo("Export Success", 
                               f"Security report exported successfully!\n\n"
                               f"Location: {destination_path}\n\n"
                               f"File: {filename}")
            
            # Update report text area
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, f"✅ Report Exported to Downloads!\n\n")
            self.report_text.insert(tk.END, f"Filename: {filename}\n")
            self.report_text.insert(tk.END, f"Location: {downloads_path}\n\n")
            self.report_text.insert(tk.END, f"Incident: {self.current_incident['incident_id']}\n")
            self.report_text.insert(tk.END, f"Attack Type: {self.current_incident['attack_type']}\n")
            self.report_text.insert(tk.END, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")
            self.status_label.config(text="❌ Export failed")
    
    def send_report(self):
        """Send report via email with automatic download and email body"""
        if not self.current_incident:
            messagebox.showwarning("No Selection", "Please select an incident first.")
            return
            
        try:
            # Generate and download the report first
            attack_diag = create_attack_diagram(self.current_incident)
            src = self.current_incident['related_logs'][0]['src_ip']
            dst = self.current_incident['related_logs'][0].get('dst_ip', 'N/A')
            flow_diag = None  # Disabled fake network topology
            
            # Generate the report
            report_path = generate_report(self.current_incident, attack_diag, flow_diag)
            
            # Get Downloads folder path and copy there
            import os
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
            
            # Create filename with timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.current_incident['incident_id']}_SecurityReport_{timestamp}.docx"
            destination_path = os.path.join(downloads_path, filename)
            
            # Copy report to Downloads folder
            import shutil
            shutil.copy2(report_path, destination_path)
            
            # Create email with your specific message
            subject = f"Security Report: {self.current_incident['incident_id']}"
            body = "Dear Team,\n\nPlease review the details of the offense generated by our SOC team."
            
            # Use Outlook via PowerShell (Windows only)
            import subprocess
            import sys
            
            if sys.platform == "win32":
                ps_script = f'''
                $Outlook = New-Object -ComObject Outlook.Application
                $Mail = $Outlook.CreateItem(0)
                $Mail.Subject = "{subject}"
                $Mail.Body = "{body}"
                $Mail.Attachments.Add("{destination_path}")
                $Mail.Display()
                '''
                with open("temp_email.ps1", "w") as f:
                    f.write(ps_script)
                subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "temp_email.ps1"])
                os.remove("temp_email.ps1")
                
                self.status_label.config(text="🟢 Report sent & downloaded!")
                messagebox.showinfo("Send Success", 
                                   f"Report downloaded and email prepared!\n\n"
                                   f"Downloaded to: {destination_path}\n\n"
                                   f"Email with attachment is ready to send.")
            else:
                messagebox.showinfo("Email", "Report downloaded. Please attach manually to email.")
            
            # Update report text area
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, f"✅ Report Sent & Downloaded!\n\n")
            self.report_text.insert(tk.END, f"Email Subject: {subject}\n")
            self.report_text.insert(tk.END, f"Email Body: {body}\n\n")
            self.report_text.insert(tk.END, f"Downloaded to: {destination_path}\n")
            self.report_text.insert(tk.END, f"File: {filename}\n")
            self.report_text.insert(tk.END, f"Sent: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send report:\n{str(e)}")
            self.status_label.config(text="❌ Send failed")
    
    def generate_incident_analytics(self):
        """Generate P1/P2/P3/P4 incident analytics using linear bar charts directly in canvas"""
        try:
            # Clear canvas
            self.analytics_canvas.delete("all")
            
            # Force canvas update to get proper dimensions
            self.analytics_canvas.update()
            
            # Get all incidents and categorize by priority
            incidents = list_all_incidents()
            priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
            
            for inc in incidents:
                incident_data = load_incident(inc)
                if incident_data:
                    threat_score = incident_data.get('threat_score', 0)
                    if threat_score >= 9:
                        priority_counts["P1"] += 1
                    elif threat_score >= 7:
                        priority_counts["P2"] += 1
                    elif threat_score >= 5:
                        priority_counts["P3"] += 1
                    else:
                        priority_counts["P4"] += 1
            
            # Colors for priorities
            colors = {
                "P1": "#e74c3c",  # Red
                "P2": "#f39c12",  # Orange 
                "P3": "#f1c40f",  # Yellow
                "P4": "#3498db"   # Blue
            }
            
            # Get canvas dimensions with fallback and responsive sizing
            canvas_width = self.analytics_canvas.winfo_width()
            canvas_height = self.analytics_canvas.winfo_height()
            
            # Ensure minimum dimensions with better defaults
            if canvas_width <= 1:
                canvas_width = 800
            if canvas_height <= 1:
                canvas_height = 500
            
            # Make canvas responsive to actual window size
            if canvas_width < 600:
                canvas_width = 600
            if canvas_height < 400:
                canvas_height = 400
            
            # Draw title
            title_text = "📊 INCIDENT SEVERITY ANALYTICS (LINEAR VIEW)"
            self.analytics_canvas.create_text(canvas_width//2, 30, 
                                            text=title_text, 
                                            font=("Arial", 16, "bold"), 
                                            fill="#2c3e50")
            
            total_incidents = sum(priority_counts.values())
            if total_incidents == 0:
                self.analytics_canvas.create_text(canvas_width//2, canvas_height//2,
                                                text="No incidents to display",
                                                font=("Arial", 14), fill="#7f8c8d")
                self.status_label.config(text="ℹ️ No incidents found")
                return
            
            # Chart area dimensions with better proportions
            margin_left = max(80, canvas_width * 0.1)  # 10% of width or 80px minimum
            margin_right = max(200, canvas_width * 0.25)  # 25% for legend
            margin_top = max(60, canvas_height * 0.12)  # 12% for title
            margin_bottom = max(100, canvas_height * 0.2)  # 20% for labels
            
            chart_left = margin_left
            chart_right = canvas_width - margin_right
            chart_top = margin_top
            chart_bottom = canvas_height - margin_bottom
            chart_width = chart_right - chart_left
            chart_height = chart_bottom - chart_top
            
            # Ensure minimum chart size
            if chart_width < 200:
                chart_width = 200
                chart_right = chart_left + chart_width
            if chart_height < 150:
                chart_height = 150
                chart_bottom = chart_top + chart_height
            
            # Draw chart background
            self.analytics_canvas.create_rectangle(chart_left, chart_top, chart_right, chart_bottom,
                                                 outline="#bdc3c7", width=2, fill="#f8f9fa")
            
            # Calculate bar dimensions with responsive sizing
            priorities = list(priority_counts.keys())
            bar_count = len(priorities)
            bar_spacing = max(15, chart_width * 0.05)  # 5% of chart width or 15px
            available_width = chart_width - (bar_spacing * (bar_count + 1))
            bar_width = max(40, available_width // bar_count)  # Minimum 40px wide bars
            
            # Find max count for scaling
            max_count = max(priority_counts.values()) if priority_counts.values() else 1
            if max_count == 0:
                max_count = 1
            
            # Draw Y-axis labels and grid lines with better scaling
            y_steps = min(5, max_count) if max_count > 0 else 5
            for i in range(y_steps + 1):
                y_value = (max_count * i) // y_steps if y_steps > 0 else 0
                y_pos = chart_bottom - (chart_height * i / y_steps) if y_steps > 0 else chart_bottom
                
                # Grid line
                self.analytics_canvas.create_line(chart_left, y_pos, chart_right, y_pos,
                                                fill="#ecf0f1", width=1)
                
                # Y-axis label with better positioning
                label_x = chart_left - max(15, margin_left * 0.2)
                self.analytics_canvas.create_text(label_x, y_pos,
                                                text=str(y_value),
                                                font=("Arial", 10),
                                                fill="#2c3e50",
                                                anchor="e")
            
            # Draw bars
            severity_names = {"P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM", "P4": "LOW"}
            
            for i, priority in enumerate(priorities):
                count = priority_counts[priority]
                
                # Calculate bar position and height
                bar_x = chart_left + bar_spacing + (i * (bar_width + bar_spacing))
                bar_height = (count / max_count) * chart_height if max_count > 0 else 0
                bar_y = chart_bottom - bar_height
                
                # Draw bar
                self.analytics_canvas.create_rectangle(bar_x, bar_y, bar_x + bar_width, chart_bottom,
                                                     fill=colors[priority], outline="#2c3e50", width=2)
                
                # Add count label on top of bar
                if count > 0:
                    self.analytics_canvas.create_text(bar_x + bar_width//2, bar_y - 10,
                                                    text=str(count),
                                                    font=("Arial", 12, "bold"),
                                                    fill="#2c3e50")
                
                # Add priority label below bar with better spacing
                label_y1 = chart_bottom + max(15, margin_bottom * 0.15)
                self.analytics_canvas.create_text(bar_x + bar_width//2, label_y1,
                                                text=priority,
                                                font=("Arial", 11, "bold"),
                                                fill="#2c3e50")
                
                # Add severity name below priority with better spacing
                label_y2 = chart_bottom + max(35, margin_bottom * 0.35)
                self.analytics_canvas.create_text(bar_x + bar_width//2, label_y2,
                                                text=severity_names[priority],
                                                font=("Arial", 9),
                                                fill="#7f8c8d")
            
            # Draw axes
            # Y-axis
            self.analytics_canvas.create_line(chart_left, chart_top, chart_left, chart_bottom,
                                            fill="#2c3e50", width=3)
            # X-axis
            self.analytics_canvas.create_line(chart_left, chart_bottom, chart_right, chart_bottom,
                                            fill="#2c3e50", width=3)
            
            # Add axis labels with responsive positioning
            axis_label_y = chart_left - max(40, margin_left * 0.5)
            self.analytics_canvas.create_text(axis_label_y, chart_top + chart_height//2,
                                            text="Number of\nIncidents",
                                            font=("Arial", 10, "bold"),
                                            fill="#2c3e50",
                                            angle=90)
            
            axis_label_x_y = chart_bottom + max(40, margin_bottom * 0.6)
            self.analytics_canvas.create_text(chart_left + chart_width//2, axis_label_x_y,
                                            text="Priority Levels",
                                            font=("Arial", 12, "bold"),
                                            fill="#2c3e50")
            
            # Add legend/statistics on the right with responsive positioning
            legend_x = chart_right + max(20, margin_right * 0.1)
            legend_y_start = chart_top + 20
            
            # Ensure legend fits within canvas
            if legend_x + 150 > canvas_width:
                legend_x = canvas_width - 150
            
            self.analytics_canvas.create_text(legend_x, legend_y_start,
                                            text="STATISTICS",
                                            font=("Arial", 12, "bold"),
                                            fill="#2c3e50",
                                            anchor="w")
            
            legend_item_height = max(30, chart_height // 8)  # Responsive spacing
            for i, (priority, count) in enumerate(priority_counts.items()):
                y_pos = legend_y_start + 40 + (i * legend_item_height)
                
                # Color indicator
                indicator_size = 12
                self.analytics_canvas.create_rectangle(legend_x, y_pos - indicator_size//2,
                                                     legend_x + indicator_size, y_pos + indicator_size//2,
                                                     fill=colors[priority], outline="black", width=1)
                
                # Statistics text
                percentage = (count / total_incidents * 100) if total_incidents > 0 else 0
                stats_text = f"{priority}: {count} ({percentage:.1f}%)"
                self.analytics_canvas.create_text(legend_x + 20, y_pos,
                                                text=stats_text,
                                                font=("Arial", 11),
                                                fill="#2c3e50",
                                                anchor="w")
            
            # Add summary statistics with responsive positioning
            summary_y = canvas_height - max(40, margin_bottom * 0.4)
            summary_text = f"📊 Total: {total_incidents} | Max: {max_count} | Time: {datetime.now().strftime('%H:%M:%S')}"
            self.analytics_canvas.create_text(canvas_width//2, summary_y,
                                            text=summary_text,
                                            font=("Arial", 11),
                                            fill="#27ae60")
            
            # Add critical incident warning if P1 exists with responsive positioning
            if priority_counts["P1"] > 0:
                warning_y = summary_y + max(20, margin_bottom * 0.2)
                warning_text = f"⚠️ {priority_counts['P1']} CRITICAL INCIDENT(S) REQUIRE IMMEDIATE ATTENTION"
                self.analytics_canvas.create_text(canvas_width//2, warning_y,
                                                text=warning_text,
                                                font=("Arial", 11, "bold"),
                                                fill="#e74c3c")
            
            self.status_label.config(text=f"🟢 Linear Analytics Generated - {total_incidents} incidents analyzed")
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Analytics Error Details: {error_details}")
            messagebox.showerror("Analytics Error", f"Failed to generate analytics:\n{str(e)}")
            self.status_label.config(text="❌ Analytics generation failed")
    
    def export_analytics(self):
        """Export analytics chart as image"""
        try:
            # Save canvas as PostScript first
            import os
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
            
            # Generate timestamp for unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            ps_file = os.path.join(downloads_path, f"DAN_Circular_Analytics_{timestamp}.ps")
            
            self.analytics_canvas.postscript(file=ps_file)
            
            messagebox.showinfo("Export Success", 
                              f"Circular Analytics chart exported to:\n{ps_file}\n\n"
                              f"Note: PostScript (.ps) files can be opened with:\n"
                              f"- Adobe Acrobat/Reader\n"
                              f"- GIMP (convert to PNG/JPG)\n"
                              f"- Online PS to PDF converters")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export analytics:\n{str(e)}")
    
    def test_incident_data(self):
        """Test method to debug incident data loading"""
        try:
            incidents = list_all_incidents()
            print(f"Found {len(incidents)} incidents: {incidents}")
            
            priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
            
            for inc in incidents[:5]:  # Test first 5
                incident_data = load_incident(inc)
                if incident_data:
                    threat_score = incident_data.get('threat_score', 0)
                    print(f"Incident {inc}: threat_score = {threat_score}")
                    if threat_score >= 9:
                        priority_counts["P1"] += 1
                    elif threat_score >= 7:
                        priority_counts["P2"] += 1
                    elif threat_score >= 5:
                        priority_counts["P3"] += 1
                    else:
                        priority_counts["P4"] += 1
                else:
                    print(f"Failed to load incident: {inc}")
            
            print(f"Priority counts: {priority_counts}")
            
            messagebox.showinfo("Test Results", 
                               f"Incidents found: {len(incidents)}\n"
                               f"P1: {priority_counts['P1']}\n"
                               f"P2: {priority_counts['P2']}\n"
                               f"P3: {priority_counts['P3']}\n"
                               f"P4: {priority_counts['P4']}\n\n"
                               f"Canvas size: {self.analytics_canvas.winfo_width()}x{self.analytics_canvas.winfo_height()}")
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Test Error: {error_details}")
            messagebox.showerror("Test Error", f"Test failed:\n{str(e)}")
    
    def generate_all_reports_with_choice(self):
        """Generate comprehensive report with all incidents with user confirmation"""
        try:
            incidents = list_all_incidents()
            if not incidents:
                messagebox.showwarning("No Data", "No incidents found to generate report.")
                return
            
            # Ask user for confirmation
            result = messagebox.askyesno(
                "Generate All Reports",
                f"This will generate a comprehensive report with all {len(incidents)} incidents.\n\n"
                f"This may take a few moments to process.\n\n"
                f"Do you want to continue?"
            )
            
            if result:
                self.generate_all_reports()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate all reports:\n{str(e)}")
    
    def export_all_reports(self):
        """Export all incidents as comprehensive report directly to Downloads"""
        try:
            incidents = list_all_incidents()
            if not incidents:
                messagebox.showwarning("No Data", "No incidents found to export.")
                return
            
            # Ask user for confirmation
            result = messagebox.askyesno(
                "Export All Reports",
                f"This will export a comprehensive report with all {len(incidents)} incidents to your Downloads folder.\n\n"
                f"File will be named: DAN_Comprehensive_Security_Report_[timestamp].docx\n\n"
                f"Do you want to continue?"
            )
            
            if not result:
                return
            
            self.status_label.config(text="🔄 Exporting comprehensive report...")
            
            from modules.report_generator import generate_comprehensive_report
            
            # Generate the comprehensive report
            report_path = generate_comprehensive_report(incidents)
            
            if report_path and os.path.exists(report_path):
                # Update status and show success
                self.status_label.config(text=f"✅ All reports exported - {len(incidents)} incidents")
                
                # Update report text area
                self.report_text.delete(1.0, tk.END)
                self.report_text.insert(tk.END, f"✅ All Incidents Report Exported!\n\n")
                self.report_text.insert(tk.END, f"Filename: {os.path.basename(report_path)}\n")
                self.report_text.insert(tk.END, f"Location: Downloads folder\n\n")
                self.report_text.insert(tk.END, f"Total Incidents: {len(incidents)}\n")
                self.report_text.insert(tk.END, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                self.report_text.insert(tk.END, "Report includes:\n")
                self.report_text.insert(tk.END, "- P-series incident distribution\n")
                self.report_text.insert(tk.END, "- Time-based analysis\n")
                self.report_text.insert(tk.END, "- Event-based statistics\n")
                self.report_text.insert(tk.END, "- Embedded charts and visualizations\n")
                self.report_text.insert(tk.END, "- Critical incidents analysis\n")
                
                messagebox.showinfo("Export Success", 
                                   f"Comprehensive report exported successfully!\n\n"
                                   f"File: {os.path.basename(report_path)}\n"
                                   f"Location: Downloads folder\n"
                                   f"Incidents: {len(incidents)}")
            else:
                messagebox.showerror("Error", "Failed to export comprehensive report.")
                self.status_label.config(text="❌ Export failed")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export all reports:\n{str(e)}")
            self.status_label.config(text="❌ Export failed")
    
    def load_all_incidents_table(self):
        """Load all incidents into the table"""
        try:
            # Clear existing items
            for item in self.all_incidents_tree.get_children():
                self.all_incidents_tree.delete(item)
            
            # Get all incidents
            incidents = list_all_incidents()
            priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
            
            for inc_id in incidents:
                incident_data = load_incident(inc_id)
                if incident_data:
                    threat_score = incident_data.get('threat_score', 0)
                    
                    # Determine priority
                    if threat_score >= 9:
                        priority = "P1"
                        priority_counts["P1"] += 1
                    elif threat_score >= 7:
                        priority = "P2"
                        priority_counts["P2"] += 1
                    elif threat_score >= 5:
                        priority = "P3"
                        priority_counts["P3"] += 1
                    else:
                        priority = "P4"
                        priority_counts["P4"] += 1
                    
                    # Add to table
                    self.all_incidents_tree.insert('', 'end', values=(
                        inc_id,
                        incident_data.get('timestamp', 'N/A')[:19],  # Truncate timestamp
                        priority,
                        incident_data.get('attack_type', 'Unknown')[:30],  # Truncate long names
                        incident_data.get('src_ip', 'N/A'),
                        f"{threat_score}/10"
                    ), tags=(priority.lower(),))
            
            # Configure row colors by priority
            self.all_incidents_tree.tag_configure('p1', background='#ffebee')  # Light red
            self.all_incidents_tree.tag_configure('p2', background='#fff3e0')  # Light orange
            self.all_incidents_tree.tag_configure('p3', background='#fffde7')  # Light yellow
            self.all_incidents_tree.tag_configure('p4', background='#e3f2fd')  # Light blue
            
            # Update stats
            total = len(incidents)
            stats_text = f"Total: {total} | P1: {priority_counts['P1']} | P2: {priority_counts['P2']} | P3: {priority_counts['P3']} | P4: {priority_counts['P4']}"
            self.all_incidents_stats.config(text=stats_text)
            
            self.status_label.config(text=f"🟢 Loaded {total} incidents in table")
            
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load incidents table:\n{str(e)}")
            self.status_label.config(text="❌ Failed to load incidents table")
    
    def filter_all_incidents(self, event=None):
        """Filter the all incidents table based on priority and search"""
        try:
            # Get filter criteria
            priority_filter = self.all_incidents_priority_var.get()
            search_term = self.all_incidents_search_var.get().lower()
            
            # Clear current display
            for item in self.all_incidents_tree.get_children():
                self.all_incidents_tree.delete(item)
            
            # Get all incidents
            incidents = list_all_incidents()
            filtered_count = 0
            priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
            
            for inc_id in incidents:
                incident_data = load_incident(inc_id)
                if incident_data:
                    threat_score = incident_data.get('threat_score', 0)
                    attack_type = incident_data.get('attack_type', '').lower()
                    src_ip = incident_data.get('src_ip', '')
                    
                    # Determine priority
                    if threat_score >= 9:
                        priority = "P1"
                    elif threat_score >= 7:
                        priority = "P2"
                    elif threat_score >= 5:
                        priority = "P3"
                    else:
                        priority = "P4"
                    
                    # Apply priority filter
                    if priority_filter != "All":
                        filter_priority = priority_filter.split()[0]  # Extract P1, P2, etc.
                        if priority != filter_priority:
                            continue
                    
                    # Apply search filter
                    if search_term:
                        if (search_term not in inc_id.lower() and 
                            search_term not in attack_type and 
                            search_term not in src_ip):
                            continue
                    
                    # Add to filtered results
                    self.all_incidents_tree.insert('', 'end', values=(
                        inc_id,
                        incident_data.get('timestamp', 'N/A')[:19],
                        priority,
                        incident_data.get('attack_type', 'Unknown')[:30],
                        incident_data.get('src_ip', 'N/A'),
                        f"{threat_score}/10"
                    ), tags=(priority.lower(),))
                    
                    filtered_count += 1
                    priority_counts[priority] += 1
            
            # Update stats
            total = len(incidents)
            stats_text = f"Showing: {filtered_count}/{total} | P1: {priority_counts['P1']} | P2: {priority_counts['P2']} | P3: {priority_counts['P3']} | P4: {priority_counts['P4']}"
            self.all_incidents_stats.config(text=stats_text)
            
        except Exception as e:
            print(f"Filter error: {e}")
    
    def on_all_incidents_select(self, event):
        """Handle double-click on incident in all incidents table"""
        try:
            selection = self.all_incidents_tree.selection()
            if not selection:
                return
            
            item = self.all_incidents_tree.item(selection[0])
            inc_id = item['values'][0]
            
            # Load incident details
            incident_data = load_incident(inc_id)
            if incident_data:
                self.show_incident_popup(incident_data)
            
        except Exception as e:
            messagebox.showerror("Selection Error", f"Failed to load incident details:\n{str(e)}")
    
    def show_incident_popup(self, incident_data):
        """Show incident details in a popup window - optimized to reduce lag"""
        try:
            # Create popup window
            popup = tk.Toplevel(self.root)
            popup.title(f"Incident Details - {incident_data['incident_id']}")
            popup.geometry("800x600")
            popup.configure(bg=GLASS_BG)
            
            # Make it modal
            popup.transient(self.root)
            popup.grab_set()
            
            # Center the popup
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (800 // 2)
            y = (popup.winfo_screenheight() // 2) - (600 // 2)
            popup.geometry(f"800x600+{x}+{y}")
            
            # Create notebook for tabs
            notebook = ttk.Notebook(popup)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Basic info tab
            info_frame = GlassFrame(notebook)
            notebook.add(info_frame, text="📄 Basic Info")
            
            info_text = scrolledtext.ScrolledText(info_frame, bg=GLASS_BG, fg=GLASS_FG,
                                                 font=("Segoe UI", 10), wrap=tk.WORD)
            info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Populate basic info efficiently
            basic_info = f"""INCIDENT: {incident_data['incident_id']}
TIMESTAMP: {incident_data.get('timestamp', 'N/A')}
ATTACK TYPE: {incident_data.get('attack_type', 'Unknown')}
SOURCE IP: {incident_data.get('src_ip', 'N/A')}
DESTINATION IP: {incident_data.get('dst_ip', 'N/A')}
THREAT SCORE: {incident_data.get('threat_score', 0)}/10
SEVERITY: {incident_data.get('severity', 'Unknown')}
CONFIDENCE: {incident_data.get('confidence', 0)}
EVENT COUNT: {incident_data.get('event_count', 1)}
MITRE ATT&CK: {incident_data.get('mitre_id', 'N/A')} - {incident_data.get('mitre_name', 'Unknown')}

DESCRIPTION:
{incident_data.get('description', 'No description available')}

RECOMMENDATION:
{incident_data.get('recommendation', 'No recommendations available')}"""
            
            info_text.insert(tk.END, basic_info)
            info_text.config(state=tk.DISABLED)
            
            # Raw JSON tab
            json_frame = GlassFrame(notebook)
            notebook.add(json_frame, text="📜 Raw JSON")
            
            json_text = scrolledtext.ScrolledText(json_frame, bg=GLASS_BG, fg=GLASS_FG,
                                                 font=("Consolas", 9), wrap=tk.WORD)
            json_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Format JSON efficiently
            import json
            formatted_json = json.dumps(incident_data, indent=2, sort_keys=True)
            json_text.insert(tk.END, formatted_json)
            json_text.config(state=tk.DISABLED)
            
            # Buttons frame
            buttons_frame = tk.Frame(popup, bg=GLASS_BG)
            buttons_frame.pack(fill=tk.X, padx=10, pady=5)
            
            close_btn = GlassButton(buttons_frame, text="✖ Close", command=popup.destroy)
            close_btn.pack(side=tk.RIGHT, padx=5)
            
            generate_btn = GlassButton(buttons_frame, text="📄 Generate Report", 
                                     command=lambda: self.generate_report_from_popup(incident_data, popup))
            generate_btn.pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Popup Error", f"Failed to show incident details:\n{str(e)}")
    
    def generate_report_from_popup(self, incident_data, popup):
        """Generate report for selected incident from popup"""
        try:
            # Set current incident and generate report
            self.current_incident = incident_data
            popup.destroy()
            
            # Switch to report tab and generate
            # Note: You might need to adjust tab switching logic here
            self.generate_report()
            
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report:\n{str(e)}")
    
    def select_all_incidents(self):
        """Select all visible incidents in the table"""
        try:
            for item in self.all_incidents_tree.get_children():
                self.all_incidents_tree.selection_add(item)
        except Exception as e:
            print(f"Select all error: {e}")
    
    def clear_all_incidents_selection(self):
        """Clear all selections in the table"""
        try:
            self.all_incidents_tree.selection_remove(self.all_incidents_tree.selection())
        except Exception as e:
            print(f"Clear selection error: {e}")
    
    def export_selected_incidents(self):
        """Export selected incidents as comprehensive report"""
        try:
            selected_items = self.all_incidents_tree.selection()
            if not selected_items:
                messagebox.showwarning("No Selection", "Please select incidents to export.")
                return
            
            # Get selected incident IDs
            selected_ids = []
            for item in selected_items:
                values = self.all_incidents_tree.item(item)['values']
                selected_ids.append(values[0])  # incident_id is first column
            
            # Confirm export
            result = messagebox.askyesno(
                "Export Selected",
                f"Export {len(selected_ids)} selected incident(s) as comprehensive report?\n\n"
                f"File will be saved to Downloads folder."
            )
            
            if result:
                self.status_label.config(text=f"🔄 Exporting {len(selected_ids)} selected incidents...")
                
                from modules.report_generator import generate_comprehensive_report
                report_path = generate_comprehensive_report(selected_ids)
                
                if report_path and os.path.exists(report_path):
                    messagebox.showinfo("Export Success", 
                                       f"Selected incidents exported successfully!\n\n"
                                       f"File: {os.path.basename(report_path)}\n"
                                       f"Location: Downloads folder\n"
                                       f"Incidents: {len(selected_ids)}")
                    self.status_label.config(text=f"✅ Exported {len(selected_ids)} selected incidents")
                else:
                    messagebox.showerror("Export Error", "Failed to export selected incidents.")
                    self.status_label.config(text="❌ Export failed")
                    
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export selected incidents:\n{str(e)}")
            self.status_label.config(text="❌ Export failed")
    
    def generate_all_reports(self):
        """Generate comprehensive report with all incidents, analytics, and visualizations"""
        try:
            self.status_label.config(text="🔄 Generating comprehensive report...")
            
            # Get all incidents
            incidents = list_all_incidents()
            if not incidents:
                messagebox.showwarning("No Data", "No incidents found to generate report.")
                self.status_label.config(text="ℹ️ No incidents available")
                return
            
            from modules.report_generator import generate_comprehensive_report
            
            # Generate the comprehensive report
            report_path = generate_comprehensive_report(incidents)
            
            if report_path and os.path.exists(report_path):
                # Update status
                self.status_label.config(text=f"✅ Comprehensive report generated: {len(incidents)} incidents")
                
                # Update report text area with detailed summary
                self.report_text.delete(1.0, tk.END)
                self.report_text.insert(tk.END, f"✅ Comprehensive Security Report Generated!\n\n")
                self.report_text.insert(tk.END, f"Report File: {os.path.basename(report_path)}\n")
                self.report_text.insert(tk.END, f"Location: Downloads folder\n\n")
                self.report_text.insert(tk.END, f"Analysis Summary:\n")
                self.report_text.insert(tk.END, f"- Total Incidents Analyzed: {len(incidents)}\n")
                
                # Count incidents by priority
                priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
                for inc_id in incidents:
                    incident_data = load_incident(inc_id)
                    if incident_data:
                        threat_score = incident_data.get('threat_score', 0)
                        if threat_score >= 9:
                            priority_counts["P1"] += 1
                        elif threat_score >= 7:
                            priority_counts["P2"] += 1
                        elif threat_score >= 5:
                            priority_counts["P3"] += 1
                        else:
                            priority_counts["P4"] += 1
                
                self.report_text.insert(tk.END, f"- Critical (P1): {priority_counts['P1']}\n")
                self.report_text.insert(tk.END, f"- High (P2): {priority_counts['P2']}\n")
                self.report_text.insert(tk.END, f"- Medium (P3): {priority_counts['P3']}\n")
                self.report_text.insert(tk.END, f"- Low (P4): {priority_counts['P4']}\n\n")
                
                self.report_text.insert(tk.END, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                self.report_text.insert(tk.END, "Report Contents:\n")
                self.report_text.insert(tk.END, "✓ Executive Summary\n")
                self.report_text.insert(tk.END, "✓ P-series Distribution Charts\n")
                self.report_text.insert(tk.END, "✓ Time-based Analysis\n")
                self.report_text.insert(tk.END, "✓ Attack Type Statistics\n")
                self.report_text.insert(tk.END, "✓ Source IP Analysis\n")
                self.report_text.insert(tk.END, "✓ Critical Incidents Details\n")
                self.report_text.insert(tk.END, "✓ Security Recommendations\n")
                
                # Show success message with options
                result = messagebox.askyesno(
                    "Report Generated", 
                    f"Comprehensive Security Report generated successfully!\n\n"
                    f"File: {os.path.basename(report_path)}\n"
                    f"Location: Downloads folder\n"
                    f"Incidents Analyzed: {len(incidents)}\n\n"
                    f"Would you like to open the report now?"
                )
                
                if result:
                    # Open the report
                    import subprocess
                    try:
                        subprocess.Popen(["start", report_path], shell=True)
                    except Exception as e:
                        print(f"Failed to open report: {e}")
                        messagebox.showinfo("Info", f"Report saved to: {report_path}")
                        
            else:
                messagebox.showerror("Error", "Failed to generate comprehensive report.")
                self.status_label.config(text="❌ Report generation failed")
                
        except Exception as e:
            messagebox.showerror("Generate Error", f"Failed to generate comprehensive report:\n{str(e)}")
            self.status_label.config(text="❌ Report generation failed")
    
    def update_time(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)




# 🚀 Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = DANApp(root)
    root.mainloop()