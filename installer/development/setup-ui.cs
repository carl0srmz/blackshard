using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace blackshardDevelopmentSetup
{
    internal sealed class SetupForm : Form
    {
        private static readonly Color Background = Color.Black;
        private static readonly Color Surface = Color.FromArgb(25, 25, 25);
        private static readonly Color Muted = Color.FromArgb(145, 154, 154);
        private static readonly Color Accent = Color.Yellow;
        private static readonly Color Failure = Color.FromArgb(255, 76, 76);

        private readonly Label statusLabel;
        private readonly Label detailLabel;
        private readonly Button installButton;
        private readonly Button openButton;
        private readonly Button copyButton;
        private readonly TextBox logBox;
        private readonly ProgressBar progress;
        private RingProgress ringProgress;
        private CheckBox driverCheckBox;
        private Process setupProcess;
        private bool rebootPending;
        private bool installComplete;
        private string failureDetail;

        internal SetupForm()
        {
            Text = "blackshard setup";
            ClientSize = new Size(760, 520);
            MinimumSize = new Size(776, 559);
            MaximumSize = new Size(776, 559);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            BackColor = Background;
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 9F);

            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 68,
                BackColor = Color.FromArgb(19, 22, 22)
            };
            Controls.Add(header);

            var mark = new Label
            {
                Text = "B",
                Font = new Font("Consolas", 20F, FontStyle.Bold),
                ForeColor = Background,
                BackColor = Accent,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(18, 16),
                Size = new Size(36, 36)
            };
            header.Controls.Add(mark);

            header.Controls.Add(new Label
            {
                Text = "blackshard // VM SETUP",
                Font = new Font("Consolas", 15F, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(68, 13)
            });
            header.Controls.Add(new Label
            {
                Text = "FULL PROTECTION INSTALLER  |  DEVELOPMENT VM ONLY",
                Font = new Font("Consolas", 8.5F),
                ForeColor = Muted,
                AutoSize = true,
                Location = new Point(70, 41)
            });

            var accentLine = new Panel
            {
                BackColor = Accent,
                Height = 1,
                Dock = DockStyle.Top
            };
            Controls.Add(accentLine);
            accentLine.BringToFront();

            statusLabel = new Label
            {
                Text = "READY TO INSTALL",
                Font = new Font("Consolas", 13F, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(22, 87)
            };
            Controls.Add(statusLabel);

            detailLabel = new Label
            {
                Text = "Installs the UI, LocalSystem engine, minifilter, quarantine, and real-time protection.",
                ForeColor = Muted,
                AutoSize = true,
                Location = new Point(24, 116)
            };
            Controls.Add(detailLabel);

            installButton = CreateButton("INSTALL FULL PROTECTION", new Point(24, 184), new Size(225, 38), true);
            installButton.Enabled = false;
            installButton.Click += StartSetup;
            Controls.Add(installButton);
            UpdateInstallButtonAvailability();

            openButton = CreateButton("OPEN blackshard", new Point(260, 184), new Size(180, 38), false);
            openButton.Enabled = false;
            openButton.Click += OpenProduct;
            Controls.Add(openButton);

            copyButton = CreateButton("COPY LOG", new Point(451, 184), new Size(120, 38), false);
            copyButton.Click += delegate
            {
                if (!string.IsNullOrWhiteSpace(logBox.Text)) Clipboard.SetText(logBox.Text);
            };
            Controls.Add(copyButton);

            progress = new ProgressBar
            {
                Location = new Point(24, 235),
                Size = new Size(712, 6),
                Style = ProgressBarStyle.Blocks,
                MarqueeAnimationSpeed = 24
            };
            Controls.Add(progress);

            var logHeader = new Label
            {
                Text = "INSTALLATION ACTIVITY",
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(22, 257)
            };
            Controls.Add(logHeader);

            logBox = new TextBox
            {
                Location = new Point(24, 282),
                Size = new Size(712, 178),
                BackColor = Surface,
                ForeColor = Color.FromArgb(210, 218, 218),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5F),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = true
            };
            Controls.Add(logBox);

            Controls.Add(new Label
            {
                Text = "Unsigned development installer | Never use on a physical or personal Windows installation",
                ForeColor = Muted,
                AutoSize = true,
                Location = new Point(24, 481)
            });

            ApplyModernLayout();
            FormClosing += OnFormClosing;
            AppendLog("Ready to install. No system changes have been made.");
        }

        private void ApplyModernLayout()
        {
            Controls.Clear();
            WindowState = FormWindowState.Maximized;
            FormBorderStyle = FormBorderStyle.None;
            MinimumSize = Size.Empty;
            MaximumSize = Size.Empty;
            BackColor = Color.Black;
            KeyPreview = true;
            Padding = new Padding(42);

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 2,
                RowCount = 1
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45F));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55F));
            Controls.Add(layout);

            var left = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 1,
                RowCount = 2,
                Padding = new Padding(10, 0, 55, 0)
            };
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 24F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 76F));
            layout.Controls.Add(left, 0, 0);
            left.Controls.Add(BuildInstallerBrand(), 0, 0);

            ringProgress = new RingProgress
            {
                Dock = DockStyle.Fill,
                ProgressValue = 0,
                RingColor = Accent,
                Margin = new Padding(30, 12, 30, 12)
            };
            left.Controls.Add(ringProgress, 0, 1);

            var right = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(25, 40, 30, 28)
            };
            right.RowCount = 4;
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 23F));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 60F));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 10F));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 7F));
            layout.Controls.Add(right, 1, 0);

            var actions = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 2,
                RowCount = 1,
                Padding = new Padding(20, 35, 20, 35)
            };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48F));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52F));
            right.Controls.Add(actions, 0, 0);

            installButton.Text = "install";
            installButton.Dock = DockStyle.Fill;
            installButton.Margin = new Padding(0, 0, 38, 0);
            installButton.Font = FontResolver.CreateDisplay(28F, FontStyle.Regular);
            installButton.FlatAppearance.BorderSize = 0;
            ApplyRoundedButton(installButton, 30);
            actions.Controls.Add(installButton, 0, 0);

            copyButton.Text = "copy log";
            copyButton.Dock = DockStyle.Fill;
            copyButton.Margin = new Padding(0);
            copyButton.Font = FontResolver.CreateDisplay(28F, FontStyle.Regular);
            copyButton.BackColor = Color.White;
            copyButton.ForeColor = Color.Black;
            copyButton.FlatAppearance.BorderSize = 0;
            ApplyRoundedButton(copyButton, 30);
            actions.Controls.Add(copyButton, 1, 0);

            openButton.Visible = false;
            progress.Visible = false;

            var logSurface = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                Padding = new Padding(24),
                Margin = new Padding(0, 0, 0, 18)
            };
            right.Controls.Add(logSurface, 0, 1);
            logBox.Dock = DockStyle.Fill;
            logBox.BackColor = Surface;
            logBox.ForeColor = Color.White;
            logBox.BorderStyle = BorderStyle.None;
            logBox.Font = FontResolver.CreateMono(10.5F, FontStyle.Regular);
            logSurface.Controls.Add(logBox);

            var statusArea = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 1,
                RowCount = 2
            };
            statusArea.RowStyles.Add(new RowStyle(SizeType.Percent, 45F));
            statusArea.RowStyles.Add(new RowStyle(SizeType.Percent, 55F));
            statusLabel.Text = "ready to install";
            statusLabel.Dock = DockStyle.Fill;
            statusLabel.AutoSize = false;
            statusLabel.TextAlign = ContentAlignment.BottomLeft;
            statusLabel.Font = FontResolver.CreateMono(12F, FontStyle.Bold);
            statusArea.Controls.Add(statusLabel, 0, 0);
            detailLabel.Text = DriverlessDescription;
            detailLabel.Dock = DockStyle.Fill;
            detailLabel.AutoSize = false;
            detailLabel.TextAlign = ContentAlignment.TopLeft;
            detailLabel.Font = FontResolver.CreateDisplay(10F, FontStyle.Regular);
            statusArea.Controls.Add(detailLabel, 0, 1);
            right.Controls.Add(statusArea, 0, 2);

            // The driver is test-signed, so installing it means turning on Windows test-signing
            // and restarting. That is only acceptable on a disposable VM, and setup refuses
            // anywhere else.
            driverCheckBox = new CheckBox
            {
                Text = "also install the kernel driver (disposable VMs only: enables test-signing and restarts Windows)",
                Dock = DockStyle.Fill,
                ForeColor = Muted,
                BackColor = Color.Black,
                Font = FontResolver.CreateDisplay(10F, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            driverCheckBox.CheckedChanged += delegate
            {
                detailLabel.Text = driverCheckBox.Checked ? DriverDescription : DriverlessDescription;
            };
            right.Controls.Add(driverCheckBox, 0, 3);

            KeyDown += delegate(object sender, KeyEventArgs eventArgs)
            {
                if (eventArgs.KeyCode == Keys.Escape)
                {
                    Close();
                }
            };
            UpdateInstallButtonAvailability();
        }

        private const string DriverlessDescription =
            "Installs the protection service, script scanning (AMSI), quarantine, and on-demand scans. No restart needed.";
        private const string DriverDescription =
            "Also installs the test-signed kernel minifilter. Windows restarts once and setup resumes automatically.";

        private static Control BuildInstallerBrand()
        {
            var brand = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 2,
                RowCount = 1
            };
            brand.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170F));
            brand.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            var logoPath = Path.Combine(EmbeddedPayload.Root, "logo.png");
            if (File.Exists(logoPath))
            {
                try
                {
                    using (var source = Image.FromFile(logoPath))
                    {
                        brand.Controls.Add(new PictureBox
                        {
                            Image = new Bitmap(source),
                            Dock = DockStyle.Fill,
                            SizeMode = PictureBoxSizeMode.Zoom,
                            BackColor = Color.Black,
                            Margin = new Padding(0, 0, 20, 0)
                        }, 0, 0);
                    }
                }
                catch
                {
                }
            }
            var text = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 1,
                RowCount = 2
            };
            text.RowStyles.Add(new RowStyle(SizeType.Percent, 62F));
            text.RowStyles.Add(new RowStyle(SizeType.Percent, 38F));
            text.Controls.Add(new Label
            {
                Text = "blackshard",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                TextAlign = ContentAlignment.BottomLeft,
                Font = FontResolver.CreateMono(35F, FontStyle.Bold)
            }, 0, 0);
            text.Controls.Add(new Label
            {
                Text = "prototype",
                Dock = DockStyle.Fill,
                ForeColor = Failure,
                TextAlign = ContentAlignment.TopLeft,
                Font = FontResolver.CreateMono(21F, FontStyle.Bold)
            }, 0, 1);
            brand.Controls.Add(text, 1, 0);
            return brand;
        }

        private static void ApplyRoundedButton(Button button, int radius)
        {
            EventHandler reshape = delegate
            {
                if (button.Width <= 0 || button.Height <= 0)
                {
                    return;
                }
                using (var path = RoundedRectangle(
                    new Rectangle(0, 0, button.Width, button.Height),
                    radius
                ))
                {
                    var previous = button.Region;
                    button.Region = new Region(path);
                    if (previous != null)
                    {
                        previous.Dispose();
                    }
                }
            };
            button.Resize += reshape;
            reshape(button, EventArgs.Empty);
        }

        private static GraphicsPath RoundedRectangle(Rectangle bounds, int radius)
        {
            var diameter = radius * 2;
            var path = new GraphicsPath();
            path.AddArc(bounds.Left, bounds.Top, diameter, diameter, 180F, 90F);
            path.AddArc(bounds.Right - diameter, bounds.Top, diameter, diameter, 270F, 90F);
            path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0F, 90F);
            path.AddArc(bounds.Left, bounds.Bottom - diameter, diameter, diameter, 90F, 90F);
            path.CloseFigure();
            return path;
        }

        private static Button CreateButton(string text, Point location, Size size, bool primary)
        {
            var button = new Button
            {
                Text = text,
                Location = location,
                Size = size,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                BackColor = primary ? Accent : Surface,
                ForeColor = primary ? Background : Color.White
            };
            button.FlatAppearance.BorderColor = primary ? Accent : Color.FromArgb(65, 72, 72);
            button.FlatAppearance.BorderSize = 1;
            return button;
        }

        private void UpdateInstallButtonAvailability()
        {
            var enabled = setupProcess == null && !rebootPending;
            installButton.Enabled = enabled;
            if (driverCheckBox != null) driverCheckBox.Enabled = enabled;
            installButton.BackColor = enabled ? Accent : Color.FromArgb(48, 48, 48);
            installButton.ForeColor = enabled ? Background : Muted;
            installButton.FlatAppearance.BorderColor = enabled ? Accent : Color.FromArgb(48, 48, 48);
        }

        private void StartSetup(object sender, EventArgs eventArgs)
        {
            if (setupProcess != null) return;
            rebootPending = false;
            installComplete = false;
            failureDetail = null;
            openButton.Enabled = false;
            installButton.Enabled = false;
            installButton.BackColor = Surface;
            installButton.ForeColor = Muted;
            installButton.FlatAppearance.BorderColor = Color.FromArgb(65, 72, 72);
            progress.Style = ProgressBarStyle.Marquee;
            ringProgress.ProgressValue = 5;
            ringProgress.RingColor = Accent;
            if (driverCheckBox != null) driverCheckBox.Enabled = false;
            SetStatus("initializing", "Preparing the protected installer payload.", Accent);
            AppendLog("Starting elevated blackshard setup engine...");

            var script = Path.Combine(EmbeddedPayload.Root, "vm-setup.ps1");
            if (!File.Exists(script))
            {
                FinishSetup(2, "The embedded setup script is missing.");
                return;
            }
            try
            {
                EmbeddedPayload.Verify();
            }
            catch (Exception error)
            {
                FinishSetup(2, error.Message);
                return;
            }

            var powerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            var start = new ProcessStartInfo
            {
                FileName = powerShell,
                Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\" -UiMode" + (driverCheckBox != null && driverCheckBox.Checked ? " -WithDriver" : ""),
                WorkingDirectory = EmbeddedPayload.Root,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            try
            {
                setupProcess = new Process { StartInfo = start, EnableRaisingEvents = true };
                setupProcess.OutputDataReceived += delegate(object o, DataReceivedEventArgs e) { if (e.Data != null) HandleOutput(e.Data, false); };
                setupProcess.ErrorDataReceived += delegate(object o, DataReceivedEventArgs e) { if (e.Data != null) HandleOutput(e.Data, true); };
                setupProcess.Exited += delegate
                {
                    setupProcess.WaitForExit();
                    var code = setupProcess.ExitCode;
                    BeginInvoke((Action)(() => FinishSetup(code, null)));
                };
                setupProcess.Start();
                setupProcess.BeginOutputReadLine();
                setupProcess.BeginErrorReadLine();
            }
            catch (Exception error)
            {
                setupProcess = null;
                FinishSetup(2, error.Message);
            }
        }

        private void HandleOutput(string line, bool error)
        {
            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => HandleOutput(line, error)));
                return;
            }
            if (line.StartsWith("blackshard_ui:STATUS:", StringComparison.Ordinal))
            {
                var message = line.Substring("blackshard_ui:STATUS:".Length);
                SetStatus("installing", message, Accent);
                AppendLog(message);
                return;
            }
            if (line.StartsWith("blackshard_ui:PROGRESS:", StringComparison.Ordinal))
            {
                var payload = line.Substring("blackshard_ui:PROGRESS:".Length);
                var separator = payload.IndexOf(':');
                int value;
                if (separator > 0 && int.TryParse(payload.Substring(0, separator), out value))
                {
                    ringProgress.ProgressValue = value;
                    var message = payload.Substring(separator + 1).Trim();
                    SetStatus("installing", message, Accent);
                    AppendLog(message);
                }
                return;
            }
            if (line == "blackshard_ui:REBOOT_PENDING")
            {
                rebootPending = true;
                ringProgress.ProgressValue = Math.Max(ringProgress.ProgressValue, 25);
                SetStatus("reboot scheduled", "Windows will restart and setup will resume automatically.", Accent);
                AppendLog("Restart scheduled. Setup will continue as LocalSystem during boot.");
                return;
            }
            if (line == "blackshard_ui:INSTALL_COMPLETE")
            {
                installComplete = true;
                AppendLog("All components installed and verified.");
                return;
            }
            if (line.StartsWith("blackshard_ui:ERROR:", StringComparison.Ordinal))
            {
                failureDetail = line.Substring("blackshard_ui:ERROR:".Length).Trim();
                ringProgress.RingColor = Failure;
                SetStatus("installation failed", "The setup engine reported an error. See the activity log below.", Failure);
                AppendLog("ERROR: " + failureDetail);
                return;
            }
            AppendLog((error ? "ERROR: " : "") + line);
        }

        private void FinishSetup(int exitCode, string immediateError)
        {
            if (setupProcess != null)
            {
                setupProcess.Dispose();
                setupProcess = null;
            }
            progress.Style = ProgressBarStyle.Blocks;
            progress.Value = 0;

            if (exitCode == 0 && (installComplete || File.Exists(@"C:\Program Files\blackshard\blackshard-ui.exe")) && !rebootPending)
            {
                ringProgress.ProgressValue = 100;
                SetStatus("protection online", "Installation and verification completed.", Accent);
                AppendLog("Opening the blackshard completion experience.");
                LaunchCompletionExperience();
                Close();
                return;
            }
            else if (exitCode == 0 && rebootPending)
            {
                SetStatus("restart required", "Windows must restart before installation can continue.", Accent);
                PromptForRestart();
            }
            else
            {
                ringProgress.RingColor = Failure;
                var detail = !string.IsNullOrWhiteSpace(immediateError)
                    ? immediateError
                    : !string.IsNullOrWhiteSpace(failureDetail)
                        ? "The setup engine reported an error. Review and copy the activity log below."
                        : "Setup exited with code " + exitCode + ". Review and copy the activity log below.";
                SetStatus("installation failed", detail, Failure);
                AppendLog("Setup failed. Persistent logs: %TEMP%\\blackshard-setup.log and C:\\ProgramData\\blackshard-development-installer\\setup.log");
                installButton.Text = "retry";
            }
            UpdateInstallButtonAvailability();
        }

        private void PromptForRestart()
        {
            using (var prompt = new RestartPromptForm())
            {
                if (prompt.ShowDialog(this) != DialogResult.OK)
                {
                    SetStatus("restart postponed", "Restart Windows when ready. Installation will resume automatically.", Accent);
                    AppendLog("Restart postponed. Installation will resume automatically after the next restart.");
                    return;
                }
            }

            try
            {
                var restart = Process.Start(new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "shutdown.exe"),
                    Arguments = "/r /t 10 /d p:2:4 /c \"blackshard setup must restart Windows to continue.\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                if (restart == null)
                {
                    throw new InvalidOperationException("Windows did not start the restart request.");
                }
                restart.WaitForExit();
                if (restart.ExitCode != 0)
                {
                    throw new InvalidOperationException("Windows refused the restart request.");
                }
                SetStatus("restarting", "We'll be right back. Installation will continue automatically.", Accent);
                AppendLog("Windows restart scheduled. Installation will resume automatically.");
            }
            catch (Exception error)
            {
                rebootPending = false;
                SetStatus("restart required", "Restart Windows manually to continue installation.", Failure);
                AppendLog("ERROR: " + error.Message);
            }
        }

        private void SetStatus(string status, string detail, Color color)
        {
            statusLabel.Text = status;
            statusLabel.ForeColor = color;
            detailLabel.Text = detail;
        }

        private void AppendLog(string line)
        {
            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => AppendLog(line)));
                return;
            }
            logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + line + Environment.NewLine);
            logBox.SelectionStart = logBox.TextLength;
            logBox.ScrollToCaret();
        }

        private static void LaunchCompletionExperience()
        {
            var script = @"C:\ProgramData\blackshard-development-installer\vm-setup.ps1";
            if (!File.Exists(script)) return;

            var powerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            Process.Start(new ProcessStartInfo
            {
                FileName = powerShell,
                Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\" -CompleteForUser",
                WorkingDirectory = Path.GetDirectoryName(script),
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }

        private void OpenProduct(object sender, EventArgs eventArgs)
        {
            const string ui = @"C:\Program Files\blackshard\blackshard-ui.exe";
            if (!File.Exists(ui))
            {
                MessageBox.Show("The installed blackshard executable was not found.", "blackshard setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            Process.Start(new ProcessStartInfo("explorer.exe", "\"" + ui + "\"") { UseShellExecute = true });
        }

        private void OnFormClosing(object sender, FormClosingEventArgs eventArgs)
        {
            if (setupProcess == null) return;
            var result = MessageBox.Show(
                "Setup is still running. Closing this window could leave installation incomplete. Close anyway?",
                "blackshard setup",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (result != DialogResult.Yes) eventArgs.Cancel = true;
        }
    }

    internal sealed class RingProgress : Control
    {
        private int progressValue;
        private Color ringColor = Color.Yellow;

        internal int ProgressValue
        {
            get { return progressValue; }
            set
            {
                progressValue = Math.Max(0, Math.Min(100, value));
                Invalidate();
            }
        }

        internal Color RingColor
        {
            get { return ringColor; }
            set
            {
                ringColor = value;
                Invalidate();
            }
        }

        internal RingProgress()
        {
            DoubleBuffered = true;
            BackColor = Color.Black;
            ForeColor = Color.White;
            Size = new Size(330, 330);
        }

        protected override void OnPaint(PaintEventArgs eventArgs)
        {
            base.OnPaint(eventArgs);
            eventArgs.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var inset = 20;
            var diameter = Math.Min(ClientSize.Width, ClientSize.Height) - inset * 2;
            var bounds = new Rectangle(
                (ClientSize.Width - diameter) / 2,
                (ClientSize.Height - diameter) / 2,
                diameter,
                diameter
            );
            using (var track = new Pen(Color.FromArgb(35, 35, 35), 18F))
            using (var ring = new Pen(ringColor, 18F))
            using (var font = FontResolver.CreateDisplay(48F, FontStyle.Regular))
            using (var brush = new SolidBrush(ForeColor))
            using (var format = new StringFormat
            {
                Alignment = StringAlignment.Center,
                LineAlignment = StringAlignment.Center
            })
            {
                track.StartCap = LineCap.Round;
                track.EndCap = LineCap.Round;
                ring.StartCap = LineCap.Round;
                ring.EndCap = LineCap.Round;
                eventArgs.Graphics.DrawArc(track, bounds, -90F, 360F);
                if (progressValue > 0)
                {
                    eventArgs.Graphics.DrawArc(ring, bounds, -90F, 360F * progressValue / 100F);
                }
                var text = progressValue + "%";
                eventArgs.Graphics.DrawString(
                    text,
                    font,
                    brush,
                    bounds,
                    format
                );
            }
        }
    }

    internal sealed class RestartPromptForm : Form
    {
        internal RestartPromptForm()
        {
            Text = "blackshard setup";
            ClientSize = new Size(680, 370);
            MinimumSize = new Size(680, 370);
            MaximumSize = new Size(680, 370);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            BackColor = Color.Black;
            ForeColor = Color.White;
            Padding = new Padding(46, 38, 46, 38);

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 1,
                RowCount = 3
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 34F));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 38F));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 28F));
            Controls.Add(layout);

            layout.Controls.Add(new Label
            {
                Text = "we'll be right back",
                Dock = DockStyle.Fill,
                ForeColor = Color.Yellow,
                TextAlign = ContentAlignment.MiddleLeft,
                Font = FontResolver.CreateDisplay(34F, FontStyle.Regular)
            }, 0, 0);

            layout.Controls.Add(new Label
            {
                Text = "Windows needs to restart to activate the blackshard development driver. Installation will continue automatically when the computer starts again.",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                TextAlign = ContentAlignment.MiddleLeft,
                Font = FontResolver.CreateDisplay(13F, FontStyle.Regular)
            }, 0, 1);

            var actions = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ColumnCount = 2,
                RowCount = 1,
                Padding = new Padding(0, 16, 0, 0)
            };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            layout.Controls.Add(actions, 0, 2);

            var restart = CreateButton("restart now", Color.Yellow, Color.Black);
            restart.DialogResult = DialogResult.OK;
            actions.Controls.Add(restart, 0, 0);

            var postpone = CreateButton("not now", Color.White, Color.Black);
            postpone.DialogResult = DialogResult.Cancel;
            actions.Controls.Add(postpone, 1, 0);

            AcceptButton = restart;
            CancelButton = postpone;
        }

        private static Button CreateButton(string text, Color background, Color foreground)
        {
            var button = new Button
            {
                Text = text,
                Dock = DockStyle.Fill,
                Margin = new Padding(8, 0, 8, 0),
                FlatStyle = FlatStyle.Flat,
                BackColor = background,
                ForeColor = foreground,
                Font = FontResolver.CreateDisplay(14F, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            button.FlatAppearance.BorderSize = 0;
            return button;
        }
    }

    internal static class FontResolver
    {
        private static readonly PrivateFontCollection Fonts = new PrivateFontCollection();
        private static readonly string FontDirectory = Path.Combine(
            Path.GetTempPath(),
            "blackshard-fonts-" + Guid.NewGuid().ToString("N")
        );
        private static FontFamily DisplayFamily;
        private static FontFamily MonoFamily;

        static FontResolver()
        {
            try
            {
                Directory.CreateDirectory(FontDirectory);
                Load("blackshard.fonts.Inter.Regular.ttf", "Inter-Regular.ttf");
                Load("blackshard.fonts.Inter.Bold.ttf", "Inter-Bold.ttf");
                Load("blackshard.fonts.JetBrainsMono.Regular.ttf", "JetBrainsMono-Regular.ttf");
                Load("blackshard.fonts.JetBrainsMono.Bold.ttf", "JetBrainsMono-Bold.ttf");
                DisplayFamily = Find("Inter");
                MonoFamily = Find("JetBrains Mono");
                AppDomain.CurrentDomain.ProcessExit += delegate { Cleanup(); };
            }
            catch
            {
                Cleanup();
            }
        }

        internal static Font CreateDisplay(float size, FontStyle style)
        {
            return Create(DisplayFamily, "Arial", size, style);
        }

        internal static Font CreateMono(float size, FontStyle style)
        {
            return Create(MonoFamily, "Consolas", size, style);
        }

        private static Font Create(FontFamily family, string fallback, float size, FontStyle style)
        {
            if (family != null && family.IsStyleAvailable(style))
            {
                return new Font(family, size, style, GraphicsUnit.Point);
            }
            return new Font(fallback, size, style, GraphicsUnit.Point);
        }

        private static void Load(string resourceName, string fileName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (var stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    throw new InvalidOperationException("Embedded font resource is missing: " + resourceName);
                }
                var path = Path.Combine(FontDirectory, fileName);
                using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.CopyTo(output);
                }
                Fonts.AddFontFile(path);
            }
        }

        private static FontFamily Find(string name)
        {
            foreach (var family in Fonts.Families)
            {
                if (family.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return family;
                }
            }
            return null;
        }

        private static void Cleanup()
        {
            try
            {
                Fonts.Dispose();
            }
            catch
            {
            }
            try
            {
                if (Directory.Exists(FontDirectory))
                {
                    Directory.Delete(FontDirectory, true);
                }
            }
            catch
            {
            }
        }
    }

    internal sealed class ResumeMonitorForm : Form
    {
        private static readonly Color Background = Color.Black;
        private static readonly Color Surface = Color.FromArgb(25, 25, 25);
        private static readonly Color Accent = Color.Yellow;
        private static readonly Color Failure = Color.FromArgb(255, 55, 55);
        private static readonly string StageRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "blackshard-development-installer"
        );
        private static readonly string LogPath = Path.Combine(StageRoot, "setup.log");
        private static readonly string SuccessPath = Path.Combine(StageRoot, "installed.txt");
        private static readonly string FailurePath = Path.Combine(StageRoot, "failed.txt");

        private readonly RingProgress ring;
        private readonly Label stateLabel;
        private readonly TextBox logBox;
        private readonly Button copyButton;
        private readonly Button openLogButton;
        private readonly Timer monitorTimer;
        private readonly DateTime startedAt;
        private string displayedLog = "";
        private bool terminal;

        internal ResumeMonitorForm()
        {
            Text = "blackshard installation";
            BackColor = Background;
            ForeColor = Color.White;
            FormBorderStyle = FormBorderStyle.None;
            WindowState = FormWindowState.Maximized;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            KeyPreview = true;
            Padding = new Padding(38);

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 2,
                RowCount = 1
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48F));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52F));
            Controls.Add(layout);

            var left = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(60, 5, 55, 5)
            };
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 23F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 22F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 47F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 8F));
            layout.Controls.Add(left, 0, 0);

            var title = new Label
            {
                Text = "installing",
                Dock = DockStyle.Fill,
                ForeColor = Accent,
                TextAlign = ContentAlignment.MiddleLeft,
                Font = FontResolver.CreateDisplay(76F, FontStyle.Regular)
            };
            left.Controls.Add(title, 0, 0);

            var brand = BuildBrand();
            left.Controls.Add(brand, 0, 1);

            ring = new RingProgress
            {
                Dock = DockStyle.Fill,
                ProgressValue = 5,
                RingColor = Accent,
                Margin = new Padding(40, 5, 40, 5)
            };
            left.Controls.Add(ring, 0, 2);

            stateLabel = new Label
            {
                Text = "Waiting for the installation worker...",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = FontResolver.CreateDisplay(14F, FontStyle.Regular)
            };
            left.Controls.Add(stateLabel, 0, 3);

            var rightShell = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                Padding = new Padding(28),
                Margin = new Padding(25, 22, 32, 22)
            };
            layout.Controls.Add(rightShell, 1, 0);

            var right = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                ColumnCount = 1,
                RowCount = 3
            };
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 42F));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 54F));
            rightShell.Controls.Add(right);

            right.Controls.Add(new Label
            {
                Text = "live installation log",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                Font = FontResolver.CreateMono(13F, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft
            }, 0, 0);

            logBox = new TextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                ForeColor = Color.White,
                BorderStyle = BorderStyle.None,
                Font = FontResolver.CreateMono(10.5F, FontStyle.Regular),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = true
            };
            right.Controls.Add(logBox, 0, 1);

            var actions = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 10, 0, 0)
            };
            copyButton = CreateMonitorButton("copy log");
            copyButton.Click += delegate
            {
                if (!string.IsNullOrWhiteSpace(logBox.Text))
                {
                    Clipboard.SetText(logBox.Text);
                }
            };
            actions.Controls.Add(copyButton);

            openLogButton = CreateMonitorButton("open log");
            openLogButton.Click += delegate
            {
                if (File.Exists(LogPath))
                {
                    Process.Start(new ProcessStartInfo("notepad.exe", "\"" + LogPath + "\"") { UseShellExecute = true });
                }
            };
            actions.Controls.Add(openLogButton);

            var closeButton = CreateMonitorButton("close");
            closeButton.Click += delegate { Close(); };
            actions.Controls.Add(closeButton);
            right.Controls.Add(actions, 0, 2);

            FormClosing += OnMonitorClosing;
            KeyDown += delegate(object sender, KeyEventArgs eventArgs)
            {
                if (eventArgs.KeyCode == Keys.Escape)
                {
                    Close();
                }
            };

            startedAt = DateTime.UtcNow;
            monitorTimer = new Timer { Interval = 500 };
            monitorTimer.Tick += MonitorInstallation;
            monitorTimer.Start();
            MonitorInstallation(this, EventArgs.Empty);
        }

        private static Control BuildBrand()
        {
            var brand = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 2,
                RowCount = 1
            };
            brand.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150F));
            brand.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            var logoPath = Path.Combine(StageRoot, "logo.png");
            if (File.Exists(logoPath))
            {
                try
                {
                    using (var source = Image.FromFile(logoPath))
                    {
                        brand.Controls.Add(new PictureBox
                        {
                            Image = new Bitmap(source),
                            Dock = DockStyle.Fill,
                            SizeMode = PictureBoxSizeMode.Zoom,
                            BackColor = Background,
                            Margin = new Padding(0, 0, 20, 0)
                        }, 0, 0);
                    }
                }
                catch
                {
                }
            }

            var text = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 1,
                RowCount = 2
            };
            text.RowStyles.Add(new RowStyle(SizeType.Percent, 62F));
            text.RowStyles.Add(new RowStyle(SizeType.Percent, 38F));
            text.Controls.Add(new Label
            {
                Text = "blackshard",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                TextAlign = ContentAlignment.BottomLeft,
                Font = FontResolver.CreateMono(34F, FontStyle.Bold)
            }, 0, 0);
            text.Controls.Add(new Label
            {
                Text = "prototype",
                Dock = DockStyle.Fill,
                ForeColor = Failure,
                TextAlign = ContentAlignment.TopLeft,
                Font = FontResolver.CreateMono(20F, FontStyle.Bold)
            }, 0, 1);
            brand.Controls.Add(text, 1, 0);
            return brand;
        }

        private static Button CreateMonitorButton(string text)
        {
            var button = new Button
            {
                Text = text,
                AutoSize = true,
                Height = 34,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(35, 35, 35),
                ForeColor = Color.White,
                Font = FontResolver.CreateMono(9F, FontStyle.Regular),
                Cursor = Cursors.Hand,
                Margin = new Padding(0, 0, 10, 0)
            };
            button.FlatAppearance.BorderColor = Color.FromArgb(70, 70, 70);
            return button;
        }

        private void MonitorInstallation(object sender, EventArgs eventArgs)
        {
            if (terminal)
            {
                return;
            }

            var log = ReadSharedText(LogPath);
            if (log != displayedLog)
            {
                displayedLog = log;
                var visible = log.Length > 60000 ? log.Substring(log.Length - 60000) : log;
                logBox.Text = visible;
                logBox.SelectionStart = logBox.TextLength;
                logBox.ScrollToCaret();
                ApplyLatestProgress(log);
            }

            if (File.Exists(FailurePath))
            {
                ShowFailure(ReadSharedText(FailurePath));
                return;
            }
            if (File.Exists(SuccessPath))
            {
                ShowSuccess();
                return;
            }
            if ((DateTime.UtcNow - startedAt).TotalMinutes >= 16)
            {
                ShowFailure("The installation task did not produce a completion marker within 16 minutes.");
            }
        }

        private void ApplyLatestProgress(string log)
        {
            var matches = Regex.Matches(
                log,
                @"blackshard_ui:PROGRESS:(\d{1,3}):([^\r\n]+)",
                RegexOptions.CultureInvariant
            );
            if (matches.Count > 0)
            {
                var match = matches[matches.Count - 1];
                int value;
                if (int.TryParse(match.Groups[1].Value, out value))
                {
                    ring.ProgressValue = value;
                }
                stateLabel.Text = match.Groups[2].Value.Trim();
                return;
            }

            var statuses = Regex.Matches(
                log,
                @"blackshard_ui:STATUS:([^\r\n]+)",
                RegexOptions.CultureInvariant
            );
            if (statuses.Count > 0)
            {
                stateLabel.Text = statuses[statuses.Count - 1].Groups[1].Value.Trim();
            }
        }

        private void ShowFailure(string detail)
        {
            terminal = true;
            monitorTimer.Stop();
            ring.RingColor = Failure;
            stateLabel.ForeColor = Failure;
            stateLabel.Text = "Installation failed. The complete diagnostic log is shown on the right.";
            if (!string.IsNullOrWhiteSpace(detail) && displayedLog.IndexOf(detail, StringComparison.Ordinal) < 0)
            {
                logBox.AppendText(Environment.NewLine + Environment.NewLine + detail.Trim());
                logBox.SelectionStart = logBox.TextLength;
                logBox.ScrollToCaret();
            }
        }

        private void ShowSuccess()
        {
            terminal = true;
            monitorTimer.Stop();
            ring.ProgressValue = 100;
            ring.RingColor = Accent;
            stateLabel.ForeColor = Color.White;
            stateLabel.Text = "Installation verified. Opening the blackshard welcome screen...";
            var completionTimer = new Timer { Interval = 900 };
            completionTimer.Tick += delegate
            {
                completionTimer.Stop();
                LaunchCompletionExperience();
                Close();
            };
            completionTimer.Start();
        }

        private static string ReadSharedText(string path)
        {
            if (!File.Exists(path))
            {
                return "";
            }
            try
            {
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(stream, Encoding.UTF8, true))
                {
                    return reader.ReadToEnd();
                }
            }
            catch (IOException error)
            {
                return "Waiting for the installation log..." + Environment.NewLine + error.Message;
            }
            catch (UnauthorizedAccessException error)
            {
                return "The installation log is not readable yet." + Environment.NewLine + error.Message;
            }
        }

        private static void LaunchCompletionExperience()
        {
            var script = Path.Combine(StageRoot, "vm-setup.ps1");
            if (!File.Exists(script))
            {
                return;
            }
            var powerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            Process.Start(new ProcessStartInfo
            {
                FileName = powerShell,
                Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\" -CompleteForUser",
                WorkingDirectory = StageRoot,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }

        private void OnMonitorClosing(object sender, FormClosingEventArgs eventArgs)
        {
            if (terminal)
            {
                return;
            }
            var result = MessageBox.Show(
                "blackshard is still installing in the background. Close the progress window?",
                "blackshard setup",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );
            if (result != DialogResult.Yes)
            {
                eventArgs.Cancel = true;
            }
        }
    }

    internal static class EmbeddedPayload
    {
        private static readonly string[] FileNames =
        {
            "blackshard-setup-ui.exe",
            "blackshard-service.exe",
            "blackshard-ui.exe",
            "blackshard.sys",
            "blackshard-amsi-x64.dll",
            "blackshard-amsi-x86.dll",
            "version.txt",
            "install.ps1",
            "uninstall.ps1",
            "verify.ps1",
            "enable-test-signing.ps1",
            "disable-test-signing.ps1",
            "vm-setup.ps1",
            "oobe.png",
            "logo.png",
            "blackshard.ico"
        };

        public static string Root { get; private set; }

        // SHA-256 of each extracted file, taken from the embedded resource as it was written out.
        private static readonly Dictionary<string, string> Digests =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static void Prepare()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.ManifestModule.ModuleVersionId.ToString("N");
            var parent = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "blackshard-vm-bootstrap"
            );
            var root = Path.Combine(parent, version);
            // ProgramData lets any user create folders, and both names are predictable from the
            // public installer. A standard user who created them first would own them and could
            // swap vm-setup.ps1 before it runs elevated, so neither is used unless an administrator
            // owns it, and both get an ACL standard users cannot write through.
            CreateProtectedDirectory(parent);
            if (Directory.Exists(root))
            {
                RejectReparsePoint(root);
                Directory.Delete(root, true);
            }
            CreateProtectedDirectory(root);

            Digests.Clear();
            foreach (var fileName in FileNames)
            {
                var resourceName = "blackshard.payload." + fileName;
                using (var input = assembly.GetManifestResourceStream(resourceName))
                {
                    if (input == null)
                    {
                        throw new InvalidOperationException("The installer payload is incomplete: " + fileName);
                    }

                    var destination = Path.Combine(root, fileName);
                    var temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
                    try
                    {
                        using (var hash = SHA256.Create())
                        using (var output = new FileStream(
                            temporary,
                            FileMode.CreateNew,
                            FileAccess.Write,
                            FileShare.None,
                            131072,
                            FileOptions.WriteThrough
                        ))
                        {
                            var buffer = new byte[131072];
                            int read;
                            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                hash.TransformBlock(buffer, 0, read, null, 0);
                                output.Write(buffer, 0, read);
                            }
                            hash.TransformFinalBlock(buffer, 0, 0);
                            output.Flush(true);
                            Digests[fileName] = BitConverter.ToString(hash.Hash);
                        }
                        File.Move(temporary, destination);
                    }
                    finally
                    {
                        if (File.Exists(temporary))
                        {
                            File.Delete(temporary);
                        }
                    }
                }
            }
            Root = root;
        }

        /// <summary>
        /// Re-hashes every extracted file against what was embedded, right before anything runs
        /// elevated from the folder.
        /// </summary>
        public static void Verify()
        {
            foreach (var fileName in FileNames)
            {
                var path = Path.Combine(Root, fileName);
                RejectReparsePoint(path);
                string expected;
                if (!Digests.TryGetValue(fileName, out expected))
                {
                    throw new InvalidOperationException("The installer payload was never extracted: " + fileName);
                }
                using (var hash = SHA256.Create())
                using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (BitConverter.ToString(hash.ComputeHash(input)) != expected)
                    {
                        throw new InvalidOperationException("The installer payload changed after it was extracted: " + fileName);
                    }
                }
            }
        }

        private static void CreateProtectedDirectory(string path)
        {
            if (Directory.Exists(path))
            {
                RejectReparsePoint(path);
                var owner = Directory.GetAccessControl(path, AccessControlSections.Owner)
                    .GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                if (!IsTrustedOwner(owner))
                {
                    throw new InvalidOperationException(
                        path + " already exists and is owned by " + owner
                            + ", not an administrator. Delete it and run setup again."
                    );
                }
            }
            else
            {
                Directory.CreateDirectory(path);
                RejectReparsePoint(path);
            }
            // Applied to a folder that already existed too: one an older build made inherited
            // ProgramData's ACL, which lets users add files beside the payload.
            Directory.SetAccessControl(path, ProtectedSecurity());
        }

        private static DirectorySecurity ProtectedSecurity()
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(sid, null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow
                ));
            }
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow
            ));
            return security;
        }

        private static bool IsTrustedOwner(SecurityIdentifier owner)
        {
            if (owner == null) return false;
            if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) return true;
            if (owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) return true;
            // This process is elevated, so a folder it created under its own account is its own.
            using (var identity = WindowsIdentity.GetCurrent())
            {
                return owner.Equals(identity.User);
            }
        }

        private static void RejectReparsePoint(string path)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Installer payload paths must not be reparse points: " + path);
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length == 1 && args[0].Equals("--resume-monitor", StringComparison.OrdinalIgnoreCase))
            {
                Application.Run(new ResumeMonitorForm());
            }
            else
            {
                if (!EnsureElevated())
                {
                    return;
                }
                try
                {
                    EmbeddedPayload.Prepare();
                }
                catch (Exception error)
                {
                    MessageBox.Show(
                        "blackshard setup could not prepare its verified payload."
                            + Environment.NewLine + Environment.NewLine + error.Message,
                        "blackshard setup",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }
                Application.Run(new SetupForm());
            }
        }

        private static bool EnsureElevated()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    return true;
                }
            }

            try
            {
                var elevated = Process.Start(new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                    UseShellExecute = true,
                    Verb = "runas"
                });
                if (elevated == null)
                {
                    throw new InvalidOperationException("Windows did not start the elevated installer.");
                }
                elevated.WaitForExit();
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "blackshard setup needs administrator approval to install its protection service and driver."
                        + Environment.NewLine + Environment.NewLine + error.Message,
                    "blackshard setup",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            return false;
        }
    }
}
