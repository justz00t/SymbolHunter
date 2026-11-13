using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using SymbolHunter.Core;

namespace SymbolHunter.Gui
{
    public sealed class MainForm : Form
    {
        readonly ComboBox folderBox = new ComboBox();
        readonly Button browseBtn = new Button(), scanBtn = new Button(), stopBtn = new Button();
        readonly ComboBox strengthBox = new ComboBox();
        readonly CheckBox subfolders = new CheckBox();
        readonly TextBox filterBox = new TextBox();
        readonly TabControl tabs = new TabControl();
        readonly ListView hitList = new ListView(), detailList = new ListView(), allList = new ListView(), problemList = new ListView();
        readonly TextBox explainBox = new TextBox(), logBox = new TextBox();
        readonly StatusStrip status = new StatusStrip();
        readonly ToolStripProgressBar progress = new ToolStripProgressBar();
        readonly ToolStripStatusLabel statusLabel = new ToolStripStatusLabel(), countLabel = new ToolStripStatusLabel();
        readonly System.Windows.Forms.Timer uiTimer = new System.Windows.Forms.Timer();
        readonly ImageList stateImages = new ImageList();
        readonly Settings settings = Settings.Load();

        Scanner scanner; Thread scanThread; string scanRoot; DateTime scanStart;
        readonly ConcurrentQueue<ItemResult> finished = new ConcurrentQueue<ItemResult>();
        readonly ConcurrentQueue<string> logQueue = new ConcurrentQueue<string>();
        List<ItemResult> allResults = new List<ItemResult>();
        List<ItemResult> hitRows = new List<ItemResult>();
        List<ItemResult> allRows = new List<ItemResult>();
        List<Tuple<ItemResult, Problem>> problemRows = new List<Tuple<ItemResult, Problem>>();
        List<Hit> detailHits = new List<Hit>();
        int hitSortCol = 2; bool hitSortDesc = true;
        int allSortCol = 0; bool allSortDesc;

        static readonly Color StrongColor = Color.FromArgb(176, 30, 24), MediumColor = Color.FromArgb(165, 98, 0), WeakColor = Color.FromArgb(90, 104, 120);

        public MainForm()
        {
            Text = AppInfo.Name + " " + AppInfo.Version + " - DOS-era debug symbol finder";
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(Math.Max(900, settings.Width), Math.Max(600, settings.Height));
            MinimumSize = new Size(760, 480);
            if (settings.Maximized) WindowState = FormWindowState.Maximized;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            AllowDrop = true;
            DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            DragDrop += (s, e) =>
            {
                var p = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (p != null && p.Length > 0 && scanThread == null) { folderBox.Text = p[0]; StartScan(); }
            };
            BuildStateImages();
            BuildMenu();
            BuildTop();
            BuildTabs();
            BuildStatus();
            uiTimer.Interval = 250;
            uiTimer.Tick += (s, e) => PumpUpdates();
            uiTimer.Start();
            FormClosing += (s, e) =>
            {
                if (scanner != null) scanner.Cancel();
                settings.Maximized = WindowState == FormWindowState.Maximized;
                if (WindowState == FormWindowState.Normal) { settings.Width = Width; settings.Height = Height; }
                settings.Save();
            };
            UpdateButtons();
        }

        /// <summary>Hidden test mode: scan a folder, select the first result, save a screenshot, close.</summary>
        public void RunSelfTest(string folder, string png)
        {
            Shown += (s, e) =>
            {
                folderBox.Text = folder;
                StartScan();
                var t = new System.Windows.Forms.Timer { Interval = 300 };
                int phase = 0, waited = 0;
                t.Tick += (o, a) =>
                {
                    waited++;
                    if (phase == 0 && scanThread == null) { if (hitRows.Count > 0) { hitList.SelectedIndices.Add(0); hitList.Focus(); } phase = 1; return; }
                    if (phase == 1) { phase = 2; return; }
                    if (phase == 2 || waited > 600)
                    {
                        t.Stop();
                        try
                        {
                            using (var bmp = new Bitmap(Width, Height))
                            {
                                DrawToBitmap(bmp, new Rectangle(0, 0, Width, Height));
                                bmp.Save(png, System.Drawing.Imaging.ImageFormat.Png);
                            }
                            File.WriteAllText(png + ".txt", "rows=" + hitRows.Count + " all=" + allRows.Count + " problems=" + problemRows.Count + " details=" + detailList.Items.Count + "\n" + statusFull + "\n" + explainBox.Text);
                        }
                        catch (Exception ex) { File.WriteAllText(png + ".txt", "screenshot failed: " + ex); }
                        // second picture: the problems tab (an outside tool captures the screen after each marker file)
                        var next = new System.Windows.Forms.Timer { Interval = 6000 };
                        next.Tick += (o2, a2) =>
                        {
                            next.Stop();
                            tabs.SelectedIndex = 2;
                            if (problemRows.Count > 0) { problemList.SelectedIndices.Add(0); problemList.Focus(); }
                            try { File.WriteAllText(png + ".tab2", "problems=" + problemRows.Count); } catch { }
                            var closer = new System.Windows.Forms.Timer { Interval = 6000 };
                            closer.Tick += (o3, a3) => { closer.Stop(); Close(); };
                            closer.Start();
                        };
                        next.Start();
                    }
                };
                t.Start();
            };
        }

        // ------------------------------------------------------------------ layout

        void BuildStateImages()
        {
            stateImages.ImageSize = new Size(14, 14);
            stateImages.ColorDepth = ColorDepth.Depth32Bit;
            foreach (var c in new[] { StrongColor, MediumColor, WeakColor, Color.Silver })
            {
                var b = new Bitmap(14, 14);
                using (var g = Graphics.FromImage(b))
                {
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    using (var br = new SolidBrush(c)) g.FillEllipse(br, 2, 2, 10, 10);
                }
                stateImages.Images.Add(b);
            }
        }

        static int StateIndex(Strength s) { return s == Strength.Strong ? 0 : s == Strength.Medium ? 1 : s == Strength.Weak ? 2 : 3; }

        void BuildMenu()
        {
            var ms = new MenuStrip();
            var file = new ToolStripMenuItem("&File");
            file.DropDownItems.Add(new ToolStripMenuItem("&Scan Folder...", null, (s, e) => { if (Browse()) StartScan(); }, Keys.Control | Keys.O));
            file.DropDownItems.Add(new ToolStripMenuItem("Scan &Single File...", null, (s, e) => BrowseFile()));
            var exp = new ToolStripMenuItem("&Export Results");
            exp.DropDownItems.Add(new ToolStripMenuItem("&HTML Report...", null, (s, e) => DoExport("html"), Keys.Control | Keys.E));
            exp.DropDownItems.Add(new ToolStripMenuItem("&CSV (spreadsheet)...", null, (s, e) => DoExport("csv")));
            exp.DropDownItems.Add(new ToolStripMenuItem("&JSON...", null, (s, e) => DoExport("json")));
            exp.DropDownItems.Add(new ToolStripMenuItem("&Text list of archives...", null, (s, e) => DoExport("txt")));
            file.DropDownItems.Add(exp);
            file.DropDownItems.Add(new ToolStripMenuItem("Export &YARA Rules...", null, (s, e) => ExportYara()));
            file.DropDownItems.Add(new ToolStripSeparator());
            file.DropDownItems.Add(new ToolStripMenuItem("E&xit", null, (s, e) => Close()));
            var view = new ToolStripMenuItem("&View");
            view.DropDownItems.Add(new ToolStripMenuItem("&Refresh", null, (s, e) => RebuildRows(), Keys.F5));
            var tools = new ToolStripMenuItem("&Tools");
            tools.DropDownItems.Add(new ToolStripMenuItem("&Options...", null, (s, e) => ShowOptions()));
            tools.DropDownItems.Add(new ToolStripMenuItem("&Clear Temporary Files", null, (s, e) => ClearTemp()));
            var help = new ToolStripMenuItem("&Help");
            help.DropDownItems.Add(new ToolStripMenuItem("&What the Findings Mean", null, (s, e) => ShowLegend(), Keys.F1));
            help.DropDownItems.Add(new ToolStripMenuItem("&Supported Formats", null, (s, e) => ShowFormats()));
            help.DropDownItems.Add(new ToolStripMenuItem("&About", null, (s, e) => MessageBox.Show(this, AppInfo.Name + " " + AppInfo.Version + "\n\nFinds debug symbols (CodeView, Turbo Debugger, Watcom, DWARF/COFF, MAP and SYM files, debug objects) inside old DOS archives and disk images.\n\nIncludes SharpCompress (MIT license) for RAR and 7-Zip decoding and libyara " + (YaraRuleSet.Version ?? "4.x") + " (BSD license) for YARA rules.", "About", MessageBoxButtons.OK, MessageBoxIcon.Information)));
            ms.Items.AddRange(new ToolStripItem[] { file, view, tools, help });
            MainMenuStrip = ms;
            Controls.Add(ms);
        }

        void BuildTop()
        {
            var top = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 6, Padding = new Padding(8, 6, 8, 4) };
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 4; i++) top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var lbl = new Label { Text = "Folder to scan:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 6, 0) };
            folderBox.Dock = DockStyle.Fill;
            folderBox.Items.AddRange(settings.Recent.ToArray());
            folderBox.Text = settings.Recent.FirstOrDefault() ?? "";
            folderBox.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            folderBox.AutoCompleteSource = AutoCompleteSource.FileSystemDirectories;
            folderBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; StartScan(); } };
            browseBtn.Text = "Browse..."; browseBtn.AutoSize = true; browseBtn.Click += (s, e) => Browse();
            scanBtn.Text = "Scan"; scanBtn.AutoSize = true; scanBtn.Font = new Font(Font, FontStyle.Bold); scanBtn.Click += (s, e) => StartScan();
            stopBtn.Text = "Stop"; stopBtn.AutoSize = true; stopBtn.Click += (s, e) => { if (scanner != null) { scanner.Cancel(); SetStatus("Stopping..."); } };
            subfolders.Text = "Include subfolders"; subfolders.AutoSize = true; subfolders.Checked = settings.Recurse; subfolders.Anchor = AnchorStyles.Left;
            top.Controls.Add(lbl, 0, 0); top.Controls.Add(folderBox, 1, 0); top.Controls.Add(browseBtn, 2, 0); top.Controls.Add(scanBtn, 3, 0); top.Controls.Add(stopBtn, 4, 0);
            top.Controls.Add(subfolders, 5, 0);

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 0) };
            var showLbl = new Label { Text = "Show:", AutoSize = true, Margin = new Padding(0, 6, 4, 0) };
            strengthBox.DropDownStyle = ComboBoxStyle.DropDownList;
            strengthBox.Items.AddRange(new object[] { "Symbol tables only", "Symbols and dev leftovers", "Everything, including hints" });
            strengthBox.SelectedIndex = Math.Max(0, Math.Min(2, settings.StrengthIndex));
            strengthBox.Width = 240;
            strengthBox.SelectedIndexChanged += (s, e) => { settings.StrengthIndex = strengthBox.SelectedIndex; RebuildRows(); };
            var filtLbl = new Label { Text = "Filter:", AutoSize = true, Margin = new Padding(14, 6, 4, 0) };
            filterBox.Width = 260;
            filterBox.TextChanged += (s, e) => RebuildRows();
            row2.Controls.AddRange(new Control[] { showLbl, strengthBox, filtLbl, filterBox });
            top.Controls.Add(row2, 0, 1);
            top.SetColumnSpan(row2, 6);
            Controls.Add(top);
            top.BringToFront();
        }

        static void Columns(ListView lv, params object[] cols)
        {
            for (int i = 0; i < cols.Length; i += 2) lv.Columns.Add((string)cols[i], (int)cols[i + 1]);
        }

        static void SetupList(ListView lv)
        {
            lv.View = View.Details; lv.FullRowSelect = true; lv.HideSelection = false; lv.Dock = DockStyle.Fill;
            lv.GridLines = false; lv.MultiSelect = true;
            typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).SetValue(lv, true, null);
        }

        void BuildTabs()
        {
            tabs.Dock = DockStyle.Fill;
            // ---- results tab
            var tpHits = new TabPage("Debug symbols found");
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 260 };
            SetupList(hitList);
            hitList.VirtualMode = true; hitList.SmallImageList = stateImages; hitList.MultiSelect = false;
            Columns(hitList, "Archive / file", 360, "Debug information found", 330, "Best", 70, "Hits", 50, "First location inside", 300, "Size", 80, "Format", 200);
            hitList.RetrieveVirtualItem += (s, e) => e.Item = MakeHitRow(e.ItemIndex);
            hitList.ColumnClick += (s, e) => { if (hitSortCol == e.Column) hitSortDesc = !hitSortDesc; else { hitSortCol = e.Column; hitSortDesc = e.Column == 2 || e.Column == 3 || e.Column == 5; } RebuildRows(); };
            hitList.SelectedIndexChanged += (s, e) => ShowDetails();
            hitList.DoubleClick += (s, e) => OpenFolder(SelectedItem());
            MakeLinkColumn(hitList, i => i >= 0 && i < hitRows.Count ? hitRows[i] : null);
            var hitMenu = new ContextMenuStrip();
            hitMenu.Items.Add("Open containing folder", null, (s, e) => OpenFolder(SelectedItem()));
            hitMenu.Items.Add("Copy archive path", null, (s, e) => { var it = SelectedItem(); if (it != null) Clipboard.SetText(it.FullPath); });
            hitMenu.Items.Add("Copy summary", null, (s, e) => { var it = SelectedItem(); if (it != null) Clipboard.SetText(Summary(it)); });
            hitList.ContextMenuStrip = hitMenu;

            var lower = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
            SetupList(detailList);
            detailList.SmallImageList = stateImages;
            MakeLinkColumn(detailList, null);
            Columns(detailList, "File inside the archive", 330, "Debug information", 220, "Details", 360, "Names found (sample)", 300);
            detailList.SelectedIndexChanged += (s, e) => ShowHitExplain();
            detailList.DoubleClick += (s, e) => ExtractSelected();
            var detMenu = new ContextMenuStrip();
            detMenu.Items.Add("Extract this file...", null, (s, e) => ExtractSelected());
            detMenu.Items.Add("Copy location", null, (s, e) => { var h = SelectedHit(); if (h != null) Clipboard.SetText(h.FullPath); });
            detMenu.Items.Add("Copy details", null, (s, e) => { if (explainBox.Text.Length > 0) Clipboard.SetText(explainBox.Text); });
            detailList.ContextMenuStrip = detMenu;
            explainBox.Multiline = true; explainBox.ReadOnly = true; explainBox.ScrollBars = ScrollBars.Vertical; explainBox.Dock = DockStyle.Fill;
            explainBox.BackColor = SystemColors.Window; explainBox.Font = new Font(FontFamily.GenericMonospace, Font.SizeInPoints);
            lower.Panel1.Controls.Add(detailList);
            var btnBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(0, 0, 0, 2) };
            var openBtn = new Button { Text = "Open in Explorer", AutoSize = true };
            openBtn.Click += (s, e) => OpenFolder(SelectedItem());
            var extractBtn = new Button { Text = "Extract file...", AutoSize = true };
            extractBtn.Click += (s, e) => ExtractSelected();
            btnBar.Controls.Add(openBtn); btnBar.Controls.Add(extractBtn);
            lower.Panel2.Controls.Add(explainBox);
            lower.Panel2.Controls.Add(btnBar);
            split.Panel1.Controls.Add(hitList);
            split.Panel2.Controls.Add(lower);
            tpHits.Controls.Add(split);
            Load += (s, e) => { try { split.SplitterDistance = Math.Max(120, split.Height * 55 / 100); lower.SplitterDistance = Math.Max(200, lower.Width * 62 / 100); } catch { } };

            // ---- all items tab
            var tpAll = new TabPage("All scanned files");
            SetupList(allList);
            allList.VirtualMode = true; allList.SmallImageList = stateImages;
            Columns(allList, "File", 380, "Format", 230, "Status", 90, "Debug info", 90, "Files inside", 80, "Disk images", 80, "Problems", 70, "Size", 80, "Time", 60, "Notes", 300);
            allList.RetrieveVirtualItem += (s, e) => e.Item = MakeAllRow(e.ItemIndex);
            allList.ColumnClick += (s, e) => { if (allSortCol == e.Column) allSortDesc = !allSortDesc; else { allSortCol = e.Column; allSortDesc = false; } RebuildRows(); };
            allList.DoubleClick += (s, e) => { if (allList.SelectedIndices.Count > 0) OpenFolder(allRows[allList.SelectedIndices[0]]); };
            MakeLinkColumn(allList, i => i >= 0 && i < allRows.Count ? allRows[i] : null);
            tpAll.Controls.Add(allList);

            // ---- problems tab
            var tpProb = new TabPage("Could not be fully read");
            SetupList(problemList);
            problemList.VirtualMode = true;
            Columns(problemList, "Where", 520, "Problem", 110, "Details", 520);
            problemList.RetrieveVirtualItem += (s, e) =>
            {
                var t = problemRows[e.ItemIndex];
                var it = new ListViewItem(t.Item2.Where);
                it.SubItems.Add(ProblemLabel(t.Item2.Kind)); it.SubItems.Add(t.Item2.Message);
                e.Item = it;
            };
            problemList.DoubleClick += (s, e) => { if (problemList.SelectedIndices.Count > 0) OpenFolder(problemRows[problemList.SelectedIndices[0]].Item1); };
            MakeLinkColumn(problemList, null);
            tpProb.Controls.Add(problemList);

            // ---- log
            var tpLog = new TabPage("Log");
            logBox.Multiline = true; logBox.ReadOnly = true; logBox.ScrollBars = ScrollBars.Both; logBox.WordWrap = false; logBox.Dock = DockStyle.Fill;
            logBox.BackColor = SystemColors.Window; logBox.Font = new Font(FontFamily.GenericMonospace, Font.SizeInPoints);
            tpLog.Controls.Add(logBox);

            tabs.TabPages.AddRange(new[] { tpHits, tpAll, tpProb, tpLog });
            Controls.Add(tabs);
            tabs.BringToFront();
        }

        void BuildStatus()
        {
            progress.Size = new Size(200, 16);
            statusLabel.Spring = true; statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            countLabel.TextAlign = ContentAlignment.MiddleRight;
            countLabel.AutoSize = false; countLabel.Width = 260;
            status.Items.AddRange(new ToolStripItem[] { progress, statusLabel, countLabel });
            status.ShowItemToolTips = true;
            status.Resize += (s, e) => SetStatus(statusFull);
            Controls.Add(status);
            SetStatus("Choose a folder with your archives and disk images, then press Scan (or drop a folder here). Click a file name in the results to open it in Explorer.");
        }

        void ExportYara()
        {
            using (var dlg = new SaveFileDialog { Title = "Export YARA rules", FileName = "dos_debug_symbols.yar", Filter = "YARA rules (*.yar)|*.yar|All files (*.*)|*.*" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    YaraRules.Write(dlg.FileName);
                    SetStatus("YARA rules saved to " + dlg.FileName + ". They work on loose files; this program also looks inside archives and disk images.");
                }
                catch (Exception ex) { MessageBox.Show(this, "Could not save: " + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            }
        }

        string statusFull = "";

        static string ProblemLabel(string kind)
        {
            switch (kind)
            {
                case "corrupt": return "Damaged";
                case "crc": return "CRC error";
                case "unsupported": return "Unsupported";
                case "encrypted": return "Password";
                case "missing-volume": return "Missing part";
                case "unreadable": return "Unreadable";
                case "timeout": return "Timed out";
                case "depth": return "Nested too deep";
                case "warning": return "Note";
                default: return "Error";
            }
        }

        /// <summary>Shows a status message, shortened with "..." when it does not fit; the full text is in the tooltip.</summary>
        void SetStatus(string text)
        {
            statusFull = text ?? "";
            int avail = status.ClientSize.Width - progress.Width - countLabel.Width - 40;
            string shown = statusFull;
            if (avail > 50)
            {
                var font = statusLabel.Font ?? Font;
                if (TextRenderer.MeasureText(shown, font).Width > avail)
                {
                    int lo = 0, hi = shown.Length;
                    while (lo < hi) { int mid = (lo + hi + 1) / 2; if (TextRenderer.MeasureText(statusFull.Substring(0, mid) + "...", font).Width <= avail) lo = mid; else hi = mid - 1; }
                    shown = statusFull.Substring(0, lo).TrimEnd() + "...";
                }
            }
            statusLabel.Text = shown;
            statusLabel.ToolTipText = shown != statusFull ? statusFull : null;
        }

        // ------------------------------------------------------------------ scanning

        Strength MinStrength { get { return strengthBox.SelectedIndex == 0 ? Strength.Strong : strengthBox.SelectedIndex == 1 ? Strength.Medium : Strength.Weak; } }

        bool Browse()
        {
            using (var d = new FolderBrowserDialog { Description = "Choose the folder that holds your archives and disk images", ShowNewFolderButton = false })
            {
                if (Directory.Exists(folderBox.Text)) d.SelectedPath = folderBox.Text;
                if (d.ShowDialog(this) != DialogResult.OK) return false;
                folderBox.Text = d.SelectedPath;
                return true;
            }
        }

        void BrowseFile()
        {
            using (var d = new OpenFileDialog { Title = "Choose an archive, disk image or executable", Filter = "All files (*.*)|*.*" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                folderBox.Text = d.FileName;
                StartScan();
            }
        }

        void StartScan()
        {
            if (scanThread != null) return;
            string root = folderBox.Text.Trim().Trim('"');
            if (!Directory.Exists(root) && !File.Exists(root)) { MessageBox.Show(this, "That folder does not exist:\n" + root, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            settings.AddRecent(root);
            settings.Recurse = subfolders.Checked;
            folderBox.Items.Clear(); folderBox.Items.AddRange(settings.Recent.ToArray()); folderBox.Text = root;
            settings.Save();
            allResults = new List<ItemResult>();
            while (finished.TryDequeue(out var _)) { }
            hitRows.Clear(); allRows.Clear(); problemRows.Clear(); detailHits.Clear();
            hitList.VirtualListSize = 0; allList.VirtualListSize = 0; problemList.VirtualListSize = 0; detailList.Items.Clear(); explainBox.Clear();
            logBox.Clear();
            var opt = new ScanOptions { Threads = settings.Threads, MaxDepth = settings.MaxDepth, IncludeDeleted = settings.IncludeDeleted, Recurse = settings.Recurse, ItemTimeout = TimeSpan.FromMinutes(settings.TimeoutMinutes), YaraOnContainers = settings.YaraOnContainers };
            var rulePaths = settings.YaraRules.ToList();
            { var later = YaraRuleSet.BuiltinLaterRules(); if (later != null) rulePaths.Insert(0, later); }
            if (Directory.Exists(YaraRuleSet.ProgramRulesFolder)) rulePaths.Add(YaraRuleSet.ProgramRulesFolder);
            scanner = new Scanner(opt);
            scanner.ItemFinished += it => finished.Enqueue(it);
            scanner.Log += m => logQueue.Enqueue(m);
            scanRoot = root;
            scanStart = DateTime.Now;
            logQueue.Enqueue("Scanning " + root + " (" + opt.Threads + " threads)");
            var sc = scanner;
            scanError = null;
            scanThread = new Thread(() =>
            {
                if (rulePaths.Count > 0)
                {
                    var msgs = new List<YaraMessage>();
                    try { opt.Yara = YaraRuleSet.Compile(rulePaths, msgs); } catch (Exception ex) { msgs.Add(new YaraMessage { File = "YARA", Text = ex.Message }); }
                    foreach (var m in msgs) logQueue.Enqueue("YARA " + m);
                    if (opt.Yara != null) logQueue.Enqueue("YARA: " + opt.Yara.RuleCount + " rules loaded from " + opt.Yara.Files.Count + " file(s)" + (msgs.Any(m => !m.Warning) ? "; files with errors were skipped (see above)" : ""));
                    else logQueue.Enqueue("YARA: no usable rules" + (msgs.Count > 0 ? " (see the messages above)" : ""));
                }
                try { var r = sc.Run(root); lock (allResults) allResults = r; }
                catch (Exception ex) { scanError = ex.Message; logQueue.Enqueue("ERROR: " + ex); }
                if (opt.Yara != null) { try { opt.Yara.Dispose(); } catch { } }
                try { BeginInvoke(new Action(ScanDone)); } catch { }
            }) { IsBackground = true, Name = "scan" };
            scanThread.Start();
            tabs.SelectedIndex = 0;
            UpdateButtons();
        }

        string scanError;

        void ScanDone()
        {
            scanThread = null;
            PumpUpdates();
            lock (allResults) allRows = allResults.ToList();
            RebuildRows();
            var st = scanner.Stats;
            var el = DateTime.Now - scanStart;
            int strong = allRows.Count(i => i.Best == Strength.Strong);
            SetStatus((scanner.Cancelled ? "Stopped. " : "Done in " + FormatTime(el) + ". ") + st.TopDone + " items in " + st.Folders + " folders, " + st.Files + " files examined, " + st.Containers + " archives/images opened. " + strong + " with real symbol tables.");
            logQueue.Enqueue(statusFull);
            progress.Value = 0;
            UpdateButtons();
            PumpUpdates();
            if (scanError != null && st.TopItems == 0)
            {
                tabs.SelectedIndex = 3;
                MessageBox.Show(this, "The scan stopped with an error:\n\n" + scanError + "\n\nThe Log tab has the details.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else if (!scanner.Cancelled && st.TopItems == 0)
            {
                tabs.SelectedIndex = 3;
                MessageBox.Show(this, "No files were found in\n" + scanRoot + (st.Folders > 1 ? "\nor in any of its " + (st.Folders - 1) + (st.Folders == 2 ? " subfolder." : " subfolders.") : ".") + "\n\nIf the files are there, check that this account may read them (the Log tab lists folders that could not be opened).", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else if (hitRows.Count == 0 && st.TopItems > 0)
            {
                // nothing with debug info: show the full list so the scan visibly did something
                tabs.SelectedIndex = 1;
            }
            try { Limits.Cleanup(); } catch { }
        }

        static string FormatTime(TimeSpan t) { return t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss") : t.ToString(@"m\:ss"); }

        void PumpUpdates()
        {
            string m; int n = 0;
            var sb = new StringBuilder();
            while (n++ < 500 && logQueue.TryDequeue(out m)) sb.AppendLine(DateTime.Now.ToString("HH:mm:ss ") + m);
            if (sb.Length > 0) logBox.AppendText(sb.ToString());
            bool changed = false;
            ItemResult it;
            while (finished.TryDequeue(out it))
            {
                changed = true;
                if (it.Hits.Count > 0) logQueue.Enqueue("found " + string.Join(", ", it.KindLabels(Strength.Weak)) + " in " + it.RelPath);
            }
            if (scanner != null && scanThread != null)
            {
                var st = scanner.Stats;
                if (st.TopItems > 0) { progress.Maximum = 1000; progress.Value = (int)Math.Min(1000, st.BytesTop > 0 ? st.BytesDone * 1000 / Math.Max(1, st.BytesTop) : st.TopDone * 1000L / st.TopItems); }
                string cur = st.Current;
                if (st.Discovering)
                    SetStatus("Looking through folders: " + st.Folders + " folders, " + st.TopItems + " files found so far, " + st.TopDone + " scanned. " + (st.TopDone < st.TopItems && !string.IsNullOrEmpty(cur) ? "Scanning " + Shorten(cur, 70) : "In " + Shorten(st.DiscoverDir, 70)));
                else
                    SetStatus("Scanning " + st.TopDone + "/" + st.TopItems + " (" + st.Folders + " folders): " + Shorten(cur, 100));
                if (changed) { lock (scanner.Results) allRows = scanner.Results.ToList(); RebuildRows(); }
            }
            var hits = hitRows.Count;
            countLabel.Text = hits + " with debug info  |  " + problemRows.Count + " problems";
        }

        static string Shorten(string s, int n) { if (s == null) return ""; return s.Length <= n ? s : "..." + s.Substring(s.Length - n); }

        void UpdateButtons()
        {
            bool busy = scanThread != null;
            scanBtn.Enabled = !busy; browseBtn.Enabled = !busy; folderBox.Enabled = !busy; stopBtn.Enabled = busy; subfolders.Enabled = !busy;
        }

        // ------------------------------------------------------------------ rows

        void RebuildRows()
        {
            var min = MinStrength;
            string f = filterBox.Text.Trim();
            var selected = SelectedItem();
            IEnumerable<ItemResult> q = allRows.Where(i => i.Status != ItemStatus.PartOfSet && i.HitsAtLeast(min).Any());
            if (f.Length > 0) q = q.Where(i => i.RelPath.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0 || i.KindLabels(min).Any(k => k.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) || i.Hits.ToList().Any(h => h.InnerPath.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0));
            Func<ItemResult, IComparable> key;
            switch (hitSortCol)
            {
                case 1: key = i => string.Join(", ", i.KindLabels(min)); break;
                case 2: key = i => (int)i.Best * 100000 + Math.Min(99999, i.HitsAtLeast(min).Count()); break;
                case 3: key = i => i.HitsAtLeast(min).Count(); break;
                case 4: key = i => { var h = i.BestHit(min); return h == null ? "" : h.InnerPath; }; break;
                case 5: key = i => i.Size; break;
                case 6: key = i => i.Format; break;
                default: key = i => i.RelPath.ToLowerInvariant(); break;
            }
            var list = q.ToList();
            list.Sort((a, b) => { int c = key(a).CompareTo(key(b)); if (c == 0) c = string.Compare(a.RelPath, b.RelPath, StringComparison.OrdinalIgnoreCase); return hitSortDesc ? -c : c; });
            hitRows = list;
            hitList.VirtualListSize = hitRows.Count;
            hitList.Invalidate();
            if (selected != null)
            {
                int idx = hitRows.IndexOf(selected);
                if (idx >= 0 && (hitList.SelectedIndices.Count == 0 || hitList.SelectedIndices[0] != idx)) { hitList.SelectedIndices.Clear(); hitList.SelectedIndices.Add(idx); }
            }
            ShowDetails();

            Func<ItemResult, IComparable> ak;
            switch (allSortCol)
            {
                case 1: ak = i => i.Format ?? ""; break;
                case 2: ak = i => i.Status.ToString(); break;
                case 3: ak = i => (int)i.Best; break;
                case 4: ak = i => i.FilesExamined; break;
                case 5: ak = i => i.ImagesOpened; break;
                case 6: ak = i => i.Problems.Count; break;
                case 7: ak = i => i.Size; break;
                case 8: ak = i => i.Elapsed; break;
                default: ak = i => i.RelPath.ToLowerInvariant(); break;
            }
            var all = allRows.ToList();
            all.Sort((a, b) => { int c = ak(a).CompareTo(ak(b)); return allSortDesc ? -c : c; });
            allRows = all;
            allList.VirtualListSize = allRows.Count;
            allList.Invalidate();

            var probs = new List<Tuple<ItemResult, Problem>>();
            foreach (var i in allRows) { List<Problem> ps; lock (i.Problems) ps = i.Problems.ToList(); foreach (var p in ps) if (p.Kind != "warning" || settings.ShowWarnings) probs.Add(Tuple.Create(i, p)); }
            problemRows = probs;
            problemList.VirtualListSize = problemRows.Count;
            problemList.Invalidate();
            countLabel.Text = hitRows.Count + " with debug info  |  " + problemRows.Count + " problems";
        }

        ListViewItem MakeHitRow(int i)
        {
            if (i < 0 || i >= hitRows.Count) return new ListViewItem("");
            var it = hitRows[i];
            var min = MinStrength;
            var best = it.BestHit(min);
            var row = new ListViewItem(it.RelPath, StateIndex(it.Best));
            row.SubItems.Add(string.Join(", ", it.KindLabels(min)));
            row.SubItems.Add(it.Best.ToString());
            row.SubItems.Add(it.HitsAtLeast(min).Count().ToString());
            row.SubItems.Add(best == null ? "" : (best.InnerPath.Length > 0 ? best.InnerPath : "(the file itself)"));
            row.SubItems.Add(Fmt.Size(it.Size));
            row.SubItems.Add(it.Format + (it.Volumes.Count > 0 ? " + " + it.Volumes.Count + " volume(s)" : ""));
            row.ForeColor = it.Best == Strength.Strong ? StrongColor : it.Best == Strength.Medium ? MediumColor : WeakColor;
            return row;
        }

        ListViewItem MakeAllRow(int i)
        {
            if (i < 0 || i >= allRows.Count) return new ListViewItem("");
            var it = allRows[i];
            var row = new ListViewItem(it.RelPath, StateIndex(it.Best));
            row.SubItems.Add(it.Format ?? "");
            row.SubItems.Add(it.Status == ItemStatus.PartOfSet ? "part of set" : it.Status.ToString());
            row.SubItems.Add(it.Best == Strength.None ? "" : it.Best.ToString());
            row.SubItems.Add(it.FilesExamined.ToString());
            row.SubItems.Add(it.ImagesOpened == 0 ? "" : it.ImagesOpened.ToString());
            int pc; lock (it.Problems) pc = it.Problems.Count(p => p.Kind != "warning");
            row.SubItems.Add(pc == 0 ? "" : pc.ToString());
            row.SubItems.Add(Fmt.Size(it.Size));
            row.SubItems.Add(it.Elapsed.TotalSeconds < 0.05 ? "" : it.Elapsed.TotalSeconds.ToString("0.0") + " s");
            row.SubItems.Add(it.Note ?? "");
            if (it.Status == ItemStatus.PartOfSet) row.ForeColor = SystemColors.GrayText;
            return row;
        }

        static readonly Color LinkColor = Color.FromArgb(0, 95, 184);
        Font linkFont;

        /// <summary>Draws column 0 as a hyperlink; clicking it opens Explorer at the file.</summary>
        void MakeLinkColumn(ListView lv, Func<int, ItemResult> rowItem)
        {
            lv.OwnerDraw = true;
            lv.DrawColumnHeader += (s, e) => e.DrawDefault = true;
            lv.DrawItem += (s, e) => { };
            lv.DrawSubItem += (s, e) =>
            {
                // Every cell is drawn here. The selection state comes from the list itself: the state Windows passes in
                // also flags the row under the mouse, which made rows light up while scrolling or moving the mouse.
                if (linkFont == null) linkFont = new Font(lv.Font, FontStyle.Underline);
                bool sel = e.ItemIndex >= 0 && lv.SelectedIndices.Contains(e.ItemIndex);
                var back = sel ? (lv.Focused ? SystemColors.Highlight : SystemColors.ControlLight) : lv.BackColor;
                using (var b = new SolidBrush(back)) e.Graphics.FillRectangle(b, e.Bounds);
                var flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
                if (e.ColumnIndex != 0)
                {
                    if (e.Header != null && e.Header.TextAlign == HorizontalAlignment.Right) flags = (flags & ~TextFormatFlags.Left) | TextFormatFlags.Right;
                    var cr = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, Math.Max(0, e.Bounds.Width - 8), e.Bounds.Height);
                    var cf = sel && lv.Focused ? SystemColors.HighlightText : (e.Item.ForeColor.IsEmpty ? lv.ForeColor : e.Item.ForeColor);
                    TextRenderer.DrawText(e.Graphics, e.SubItem.Text, lv.Font, cr, cf, flags);
                    return;
                }
                int x = e.Bounds.X + 2;
                if (e.Item.ImageIndex >= 0 && lv.SmallImageList != null)
                {
                    lv.SmallImageList.Draw(e.Graphics, x, e.Bounds.Y + (e.Bounds.Height - lv.SmallImageList.ImageSize.Height) / 2, e.Item.ImageIndex);
                    x += lv.SmallImageList.ImageSize.Width + 4;
                }
                var r = new Rectangle(x, e.Bounds.Y, Math.Max(0, e.Bounds.Right - x - 2), e.Bounds.Height);
                var fore = sel && lv.Focused ? SystemColors.HighlightText : (rowItem != null ? LinkColor : (e.Item.ForeColor.IsEmpty ? lv.ForeColor : e.Item.ForeColor));
                TextRenderer.DrawText(e.Graphics, e.SubItem.Text, rowItem != null ? linkFont : lv.Font, r, fore, flags);
            };
            // repaint when the selection or focus changes so no stale highlight is left behind
            lv.SelectedIndexChanged += (s, e) => lv.Invalidate();
            lv.VirtualItemsSelectionRangeChanged += (s, e) => lv.Invalidate();
            lv.GotFocus += (s, e) => lv.Invalidate();
            lv.LostFocus += (s, e) => lv.Invalidate();
            if (rowItem == null) return;   // plain list: same drawing, no link behaviour
            Func<Point, bool> overLink = p =>
            {
                var h = lv.HitTest(p);
                if (h.Item == null || h.SubItem == null) return false;
                if (h.Item.SubItems.IndexOf(h.SubItem) != 0) return false;
                return p.X > h.Item.Bounds.X + 18;   // not the state icon
            };
            lv.MouseMove += (s, e) => lv.Cursor = overLink(e.Location) ? Cursors.Hand : Cursors.Default;
            lv.MouseLeave += (s, e) => lv.Cursor = Cursors.Default;
            lv.MouseClick += (s, e) =>
            {
                if (e.Button != MouseButtons.Left || !overLink(e.Location)) return;
                var h = lv.HitTest(e.Location);
                var it = rowItem(h.Item.Index);
                if (it != null) OpenFolder(it);
            };
            var tip = new ToolTip();
            tip.SetToolTip(lv, "Click a file name to show it in Explorer");
        }

        ItemResult SelectedItem() { return hitList.SelectedIndices.Count > 0 && hitList.SelectedIndices[0] < hitRows.Count ? hitRows[hitList.SelectedIndices[0]] : null; }
        Hit SelectedHit() { return detailList.SelectedIndices.Count > 0 && detailList.SelectedIndices[0] < detailHits.Count ? detailHits[detailList.SelectedIndices[0]] : null; }

        void ShowDetails()
        {
            var it = SelectedItem();
            detailList.BeginUpdate();
            detailList.Items.Clear();
            detailHits = it == null ? new List<Hit>() : it.HitsAtLeast(MinStrength).OrderByDescending(h => h.Finding.Strength).ThenBy(h => h.InnerPath).ToList();
            foreach (var h in detailHits)
            {
                var row = new ListViewItem((h.InnerPath.Length > 0 ? h.InnerPath : PathUtil.FileName(it.RelPath)) + (h.Deleted ? " (deleted)" : ""), StateIndex(h.Finding.Strength));
                row.SubItems.Add(h.Finding.Label);
                row.SubItems.Add(h.Finding.Detail);
                row.SubItems.Add(string.Join(", ", h.Finding.Samples.Take(8)));
                row.ForeColor = h.Finding.Strength == Strength.Strong ? StrongColor : h.Finding.Strength == Strength.Medium ? MediumColor : WeakColor;
                detailList.Items.Add(row);
            }
            detailList.EndUpdate();
            if (detailList.Items.Count > 0) detailList.Items[0].Selected = true; else explainBox.Text = it == null ? "" : Summary(it);
        }

        void ShowHitExplain()
        {
            var h = SelectedHit(); var it = SelectedItem();
            if (h == null || it == null) return;
            var k = Kinds.Get(h.Finding.Kind);
            var sb = new StringBuilder();
            sb.AppendLine(h.Finding.Label + "  [" + h.Finding.Strength + "]");
            sb.AppendLine();
            sb.AppendLine("Archive:  " + it.FullPath);
            if (h.InnerPath.Length > 0) sb.AppendLine("Inside:   " + h.InnerPath + (h.Deleted ? "  (deleted file, recovered)" : ""));
            sb.AppendLine("File:     " + h.FileType + (h.Packer != null ? ", packed with " + h.Packer : "") + ", " + Fmt.Size(h.FileSize));
            sb.AppendLine("Details:  " + h.Finding.Detail);
            if (h.Finding.Offset >= 0) sb.AppendLine("Location: offset " + Bin.Hex(h.Finding.Offset) + (h.Finding.Size > 0 ? ", " + Fmt.Size(h.Finding.Size) : ""));
            if (h.Finding.Samples.Count > 0) { sb.AppendLine(); sb.AppendLine("Names found: " + string.Join(", ", h.Finding.Samples)); }
            sb.AppendLine();
            sb.AppendLine(k.Explain);
            sb.AppendLine();
            sb.AppendLine(h.Chain.Count > 1 ? "Click the archive name above (or Open in Explorer) to see the archive; double-click this row or use Extract file to save the inner file." : "Click the file name above (or Open in Explorer) to see it in Explorer.");
            explainBox.Text = sb.ToString().Replace("\n", "\r\n").Replace("\r\r\n", "\r\n");
        }

        static string Summary(ItemResult it)
        {
            var sb = new StringBuilder();
            sb.AppendLine(it.FullPath);
            foreach (var h in it.HitsAtLeast(Strength.Weak).OrderByDescending(x => x.Finding.Strength))
                sb.AppendLine("  " + h.Finding.Strength + "  " + (h.InnerPath.Length > 0 ? h.InnerPath : "(file itself)") + ": " + h.Finding);
            return sb.ToString();
        }

        void OpenFolder(ItemResult it)
        {
            if (it == null) return;
            try
            {
                if (File.Exists(it.FullPath)) Process.Start("explorer.exe", "/select,\"" + it.FullPath + "\"");
                else if (Directory.Exists(Path.GetDirectoryName(it.FullPath))) Process.Start("explorer.exe", "\"" + Path.GetDirectoryName(it.FullPath) + "\"");
                else MessageBox.Show(this, "The file is no longer there:\n" + it.FullPath, AppInfo.Name);
                SetStatus("Opened " + it.FullPath + " in Explorer");
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name); }
        }

        void ExtractSelected()
        {
            var h = SelectedHit(); var it = SelectedItem();
            if (h == null || it == null) return;
            if (h.Chain.Count <= 1) { OpenFolder(it); return; }
            using (var d = new SaveFileDialog { FileName = SafeName(PathUtil.FileName(h.Chain[h.Chain.Count - 1].Replace(" (deleted)", ""))), Title = "Save the file from inside the archive", Filter = "All files (*.*)|*.*" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var keep = new List<IDisposable>();
                try
                {
                    var data = ChainOpener.Open(it, h.Chain, keep);
                    using (var fs = File.Create(d.FileName))
                    {
                        var buf = new byte[1 << 16];
                        for (long p = 0; p < data.Length; ) { int n = data.Read(p, buf, 0, buf.Length); if (n <= 0) break; fs.Write(buf, 0, n); p += n; }
                    }
                    SetStatus("Saved " + d.FileName);
                }
                catch (Exception ex) { MessageBox.Show(this, "Could not extract the file:\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error); }
                finally { for (int i = keep.Count - 1; i >= 0; i--) try { keep[i].Dispose(); } catch { } }
            }
        }

        static string SafeName(string n) { foreach (var c in Path.GetInvalidFileNameChars()) n = n.Replace(c, '_'); return n; }

        // ------------------------------------------------------------------ export, options, help

        void DoExport(string kind)
        {
            if (allRows.Count == 0) { MessageBox.Show(this, "Run a scan first.", AppInfo.Name); return; }
            string filter = kind == "html" ? "HTML report (*.html)|*.html" : kind == "csv" ? "CSV file (*.csv)|*.csv" : kind == "json" ? "JSON file (*.json)|*.json" : "Text file (*.txt)|*.txt";
            using (var d = new SaveFileDialog { Filter = filter, FileName = "symbol-hunter-report." + kind })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    var items = allRows.ToList();
                    if (kind == "html") Export.WriteHtml(d.FileName, scanRoot, items, MinStrength, scanner != null ? scanner.Stats : null);
                    else if (kind == "csv") Export.WriteCsv(d.FileName, items, MinStrength);
                    else if (kind == "json") Export.WriteJson(d.FileName, scanRoot, items, scanner != null ? scanner.Stats : null);
                    else Export.WriteText(d.FileName, items, MinStrength);
                    SetStatus("Exported " + d.FileName);
                    if (kind == "html" && MessageBox.Show(this, "Report saved. Open it now?", AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                        Process.Start(d.FileName);
                }
                catch (Exception ex) { MessageBox.Show(this, "Export failed:\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        void ShowOptions()
        {
            using (var f = new OptionsForm(settings))
                if (f.ShowDialog(this) == DialogResult.OK) { settings.Save(); RebuildRows(); }
        }

        void ClearTemp()
        {
            int n = Limits.Cleanup();
            SetStatus("Removed " + n + " temporary file(s).");
        }

        void ShowLegend()
        {
            var sb = new StringBuilder();
            sb.AppendLine("STRONG  real symbol tables: names (and usually line numbers) you can load into a disassembler or debugger.");
            sb.AppendLine("MEDIUM  development leftovers: source code, object files, units, listings, symbol-file references.");
            sb.AppendLine("WEAK    hints only: assert() messages or build paths inside a program without a symbol table.");
            sb.AppendLine();
            foreach (var k in Kinds.All.Values.OrderByDescending(x => x.Strength).ThenBy(x => x.Label))
            {
                sb.AppendLine(k.Label + "  [" + k.Strength + "]");
                sb.AppendLine("    " + k.Explain);
            }
            TextDialog.Show(this, "What the findings mean", sb.ToString());
        }

        void ShowFormats()
        {
            TextDialog.Show(this, "Supported formats", Formats.SupportedText);
        }
    }

    /// <summary>Simple read-only text window.</summary>
    public static class TextDialog
    {
        public static void Show(IWin32Window owner, string title, string text)
        {
            using (var f = new Form { Text = title, Size = new Size(820, 600), StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, ShowIcon = false, Font = SystemFonts.MessageBoxFont })
            {
                var tb = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Text = text.Replace("\r\n", "\n").Replace("\n", "\r\n"), BackColor = SystemColors.Window };
                var ok = new Button { Text = "Close", DialogResult = DialogResult.OK, Dock = DockStyle.Bottom, Height = 32 };
                f.Controls.Add(tb); f.Controls.Add(ok); f.AcceptButton = ok;
                tb.Select(0, 0);
                f.ShowDialog(owner);
            }
        }
    }

    public sealed class OptionsForm : Form
    {
        readonly Settings s;
        readonly NumericUpDown threads = new NumericUpDown(), depth = new NumericUpDown(), timeout = new NumericUpDown();
        readonly CheckBox deleted = new CheckBox(), warnings = new CheckBox(), yaraContainers = new CheckBox();
        readonly ListBox yaraList = new ListBox();
        public OptionsForm(Settings settings)
        {
            s = settings;
            Text = "Options"; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; ShowIcon = false;
            StartPosition = FormStartPosition.CenterParent; Font = SystemFonts.MessageBoxFont; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            var t = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Padding = new Padding(12), Dock = DockStyle.Fill };
            threads.Minimum = 1; threads.Maximum = 64; threads.Value = Math.Max(1, Math.Min(64, s.Threads));
            depth.Minimum = 2; depth.Maximum = 40; depth.Value = Math.Max(2, Math.Min(40, s.MaxDepth));
            timeout.Minimum = 1; timeout.Maximum = 600; timeout.Value = Math.Max(1, Math.Min(600, s.TimeoutMinutes));
            deleted.Text = "Recover deleted files on disk images and scan them"; deleted.Checked = s.IncludeDeleted; deleted.AutoSize = true;
            warnings.Text = "Show minor warnings in the problems list"; warnings.Checked = s.ShowWarnings; warnings.AutoSize = true;
            Action<string, Control> row = (l, c) => { t.Controls.Add(new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 10, 6) }); t.Controls.Add(c); };
            row("Files scanned at the same time (threads):", threads);
            row("Maximum nesting (archive inside archive...):", depth);
            row("Give up on one archive after (minutes):", timeout);
            t.Controls.Add(deleted); t.SetColumnSpan(deleted, 2);
            t.Controls.Add(warnings); t.SetColumnSpan(warnings, 2);

            // YARA rule files
            var yLabel = new Label { Text = "Your YARA rule files and folders (.yar/.yara). They run on every file found, also inside archives and disk images." +
                                            (Directory.Exists(YaraRuleSet.ProgramRulesFolder ?? "") ? "\nRules in the \"rules\" folder next to the program are always used too." : "\nTip: a folder named \"rules\" next to the program is also used automatically."),
                                     AutoSize = true, MaximumSize = new Size(560, 0), Margin = new Padding(0, 14, 0, 4) };
            t.Controls.Add(yLabel); t.SetColumnSpan(yLabel, 2);
            yaraList.Width = 560; yaraList.Height = 110; yaraList.HorizontalScrollbar = true; yaraList.SelectionMode = SelectionMode.MultiExtended;
            foreach (var r in s.YaraRules) yaraList.Items.Add(r);
            t.Controls.Add(yaraList); t.SetColumnSpan(yaraList, 2);
            var yButtons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false };
            var addFiles = new Button { Text = "Add files...", AutoSize = true };
            var addFolder = new Button { Text = "Add folder...", AutoSize = true };
            var remove = new Button { Text = "Remove", AutoSize = true };
            var check = new Button { Text = "Check rules", AutoSize = true };
            yButtons.Controls.AddRange(new Control[] { addFiles, addFolder, remove, check });
            t.Controls.Add(yButtons); t.SetColumnSpan(yButtons, 2);
            yaraContainers.Text = "Also run YARA rules on the archive and disk image files themselves"; yaraContainers.Checked = s.YaraOnContainers; yaraContainers.AutoSize = true;
            t.Controls.Add(yaraContainers); t.SetColumnSpan(yaraContainers, 2);
            addFiles.Click += (o, e) =>
            {
                using (var dlg = new OpenFileDialog { Title = "Add YARA rule files", Multiselect = true, Filter = "YARA rules (*.yar;*.yara)|*.yar;*.yara|All files (*.*)|*.*" })
                    if (dlg.ShowDialog(this) == DialogResult.OK) foreach (var f in dlg.FileNames) if (!yaraList.Items.Contains(f)) yaraList.Items.Add(f);
            };
            addFolder.Click += (o, e) =>
            {
                using (var dlg = new FolderBrowserDialog { Description = "Folder with YARA rule files (searched with subfolders)" })
                    if (dlg.ShowDialog(this) == DialogResult.OK && !yaraList.Items.Contains(dlg.SelectedPath)) yaraList.Items.Add(dlg.SelectedPath);
            };
            remove.Click += (o, e) => { foreach (var it in yaraList.SelectedItems.Cast<object>().ToList()) yaraList.Items.Remove(it); };
            check.Click += (o, e) =>
            {
                var paths = yaraList.Items.Cast<string>().ToList();
                if (Directory.Exists(YaraRuleSet.ProgramRulesFolder ?? "")) paths.Add(YaraRuleSet.ProgramRulesFolder);
                var msgs = new List<YaraMessage>();
                Cursor = Cursors.WaitCursor;
                YaraRuleSet set = null;
                try { set = YaraRuleSet.Compile(paths, msgs); } catch (Exception ex) { msgs.Add(new YaraMessage { File = "YARA", Text = ex.Message }); }
                Cursor = Cursors.Default;
                var files = YaraRuleSet.ExpandPaths(paths);
                string head = set != null ? set.RuleCount + " rules ready from " + set.Files.Count + " of " + files.Count + " file(s)" + (YaraRuleSet.Version != null ? " (libyara " + YaraRuleSet.Version + ")" : "") + "." : "No usable rules (" + files.Count + " file(s) found).";
                if (set != null) set.Dispose();
                TextDialog.Show(this, "YARA rules", head + "\n\n" + (msgs.Count == 0 ? "No errors or warnings." : string.Join("\n", msgs.Select(m => m.ToString()))));
            };

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel };
            buttons.Controls.Add(cancel); buttons.Controls.Add(ok);
            t.Controls.Add(buttons); t.SetColumnSpan(buttons, 2);
            Controls.Add(t);
            AcceptButton = ok; CancelButton = cancel;
            ok.Click += (o, e) =>
            {
                s.Threads = (int)threads.Value; s.MaxDepth = (int)depth.Value; s.TimeoutMinutes = (int)timeout.Value; s.IncludeDeleted = deleted.Checked; s.ShowWarnings = warnings.Checked;
                s.YaraRules = yaraList.Items.Cast<string>().ToList(); s.YaraOnContainers = yaraContainers.Checked;
            };
        }
    }

    /// <summary>Persisted user settings (%APPDATA%\SymbolHunter\settings.ini).</summary>
    public sealed class Settings
    {
        public List<string> Recent = new List<string>();
        public int StrengthIndex = 1, Threads = Math.Max(1, Math.Min(8, Environment.ProcessorCount)), MaxDepth = 12, TimeoutMinutes = 30, Width = 1200, Height = 760;
        public bool Recurse = true, IncludeDeleted = true, ShowWarnings, Maximized, YaraOnContainers;
        public List<string> YaraRules = new List<string>();
        static string PathName { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SymbolHunter", "settings.ini"); } }

        public static Settings Load()
        {
            var s = new Settings();
            try
            {
                if (!File.Exists(PathName)) return s;
                foreach (var line in File.ReadAllLines(PathName))
                {
                    int eq = line.IndexOf('='); if (eq < 0) continue;
                    string k = line.Substring(0, eq), v = line.Substring(eq + 1);
                    int n; int.TryParse(v, out n);
                    switch (k)
                    {
                        case "recent": if (v.Length > 0) s.Recent.Add(v); break;
                        case "strength": s.StrengthIndex = n; break;
                        case "threads": if (n > 0) s.Threads = n; break;
                        case "depth": if (n > 1) s.MaxDepth = n; break;
                        case "timeout": if (n > 0) s.TimeoutMinutes = n; break;
                        case "width": if (n > 0) s.Width = n; break;
                        case "height": if (n > 0) s.Height = n; break;
                        case "recurse": s.Recurse = v == "1"; break;
                        case "deleted": s.IncludeDeleted = v == "1"; break;
                        case "warnings": s.ShowWarnings = v == "1"; break;
                        case "maximized": s.Maximized = v == "1"; break;
                        case "yararule": if (v.Length > 0 && !s.YaraRules.Contains(v)) s.YaraRules.Add(v); break;
                        case "yaracontainers": s.YaraOnContainers = v == "1"; break;
                    }
                }
            }
            catch { }
            return s;
        }

        public void AddRecent(string p)
        {
            Recent.RemoveAll(x => x.Equals(p, StringComparison.OrdinalIgnoreCase));
            Recent.Insert(0, p);
            if (Recent.Count > 12) Recent.RemoveRange(12, Recent.Count - 12);
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(PathName));
                var sb = new StringBuilder();
                foreach (var r in Recent) sb.AppendLine("recent=" + r);
                sb.AppendLine("strength=" + StrengthIndex); sb.AppendLine("threads=" + Threads); sb.AppendLine("depth=" + MaxDepth); sb.AppendLine("timeout=" + TimeoutMinutes);
                sb.AppendLine("width=" + Width); sb.AppendLine("height=" + Height);
                sb.AppendLine("recurse=" + (Recurse ? 1 : 0)); sb.AppendLine("deleted=" + (IncludeDeleted ? 1 : 0)); sb.AppendLine("warnings=" + (ShowWarnings ? 1 : 0)); sb.AppendLine("maximized=" + (Maximized ? 1 : 0));
                foreach (var r in YaraRules) sb.AppendLine("yararule=" + r);
                sb.AppendLine("yaracontainers=" + (YaraOnContainers ? 1 : 0));
                File.WriteAllText(PathName, sb.ToString());
            }
            catch { }
        }
    }
}
