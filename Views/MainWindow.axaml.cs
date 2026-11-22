using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
namespace AntiDumpTool.Views;
public partial class MainWindow : Window
{
    private readonly TextBox _path = new() { Watermark = "Game build folder (drag & drop here or click Browse...)", Background = new SolidColorBrush(Color.Parse("#1F0D11")), BorderBrush = new SolidColorBrush(Color.Parse("#7F1D1D")), Foreground = new SolidColorBrush(Color.Parse("#FEE2E2")) };
    private readonly ComboBox _mode = new() { ItemsSource = new[] { "Mode 1: Standalone PE Patcher (Inject .guard into GameAssembly.dll)", "Mode 2: Source Build (Encrypt metadata + MetadataLoader.cpp hook)" }, SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch, Background = new SolidColorBrush(Color.Parse("#1F0D11")), BorderBrush = new SolidColorBrush(Color.Parse("#7F1D1D")), Foreground = new SolidColorBrush(Color.Parse("#FEE2E2")) };
    private readonly CheckBox _cMeta = new() { Content = "Encrypt global-metadata.dat (strip 0xFAB11BAF magic)", IsChecked = true, Foreground = new SolidColorBrush(Color.Parse("#FECACA")) };
    private readonly CheckBox _cRand = new() { Content = "Generate unique random 64-bit key per build", IsChecked = true, Foreground = new SolidColorBrush(Color.Parse("#FECACA")) };
    private readonly CheckBox _cPe = new() { Content = "Scrub Rich header and PDB paths in GameAssembly.dll", IsChecked = true, Foreground = new SolidColorBrush(Color.Parse("#FECACA")) };
    private readonly CheckBox _cBak = new() { Content = "Create backup files (.bak) before patching", IsChecked = true, Foreground = new SolidColorBrush(Color.Parse("#FECACA")) };
    private readonly TextBox _log = new() { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas"), FontSize = 12.5, Background = new SolidColorBrush(Color.Parse("#1A0B0E")), BorderBrush = new SolidColorBrush(Color.Parse("#7F1D1D")), Foreground = new SolidColorBrush(Color.Parse("#FCA5A5")) };
    private byte[] _lastKey = { 0x5A, 0xC3, 0x19, 0x8F, 0x42, 0xE7, 0x6B, 0xD1 };

    public MainWindow()
    {
        InitializeComponent(); Application.Current!.RequestedThemeVariant = ThemeVariant.Dark;
        Title = "AntiDumpTool • Unity IL2CPP Protector"; Width = 800; Height = 560;
        Background = new SolidColorBrush(Color.Parse("#13090B")); Foreground = new SolidColorBrush(Color.Parse("#FEE2E2"));
        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DropEvent, (_, e) => { var f = e.DataTransfer.TryGetFiles()?.FirstOrDefault()?.Path.LocalPath; if (!string.IsNullOrEmpty(f)) { _path.Text = File.Exists(f) ? Path.GetDirectoryName(f) : f; Log($"Selected: {_path.Text}"); } });
        BuildUI();
    }

    private void BuildUI()
    {
        SolidColorBrush bg = new(Color.Parse("#991B1B")), br = new(Color.Parse("#DC2626"));
        var bBrowse = new Button { Content = "Browse...", Margin = new Thickness(8, 0, 0, 0), Background = bg, BorderBrush = br, Foreground = Brushes.White };
        bBrowse.Click += async (_, _) => { var r = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions()); if (r.Count > 0) { _path.Text = r.First().Path.LocalPath; Log($"Selected: {_path.Text}"); } };
        var row1 = new DockPanel { Margin = new Thickness(0, 8) }; DockPanel.SetDock(bBrowse, Dock.Right); row1.Children.Add(bBrowse); row1.Children.Add(_path);

        var bRun = new Button { Content = "PROTECT BUILD", FontWeight = FontWeight.Bold, Background = br, BorderBrush = new SolidColorBrush(Color.Parse("#F87171")), Foreground = Brushes.White, Padding = new Thickness(16, 8) }; bRun.Click += (_, _) => Protect();
        var bBak = new Button { Content = "Restore .bak", Padding = new Thickness(12, 8), Background = bg, BorderBrush = br, Foreground = Brushes.White }; bBak.Click += (_, _) => Restore();
        var bDec = new Button { Content = "Decrypt Metadata", Padding = new Thickness(12, 8), Background = bg, BorderBrush = br, Foreground = Brushes.White }; bDec.Click += (_, _) => DecryptMetadata();
        var bCpp = new Button { Content = "C++ Snippet (Mode 2)", Padding = new Thickness(12, 8), Background = bg, BorderBrush = br, Foreground = Brushes.White };
        bCpp.Click += (_, _) => Log($"MetadataLoader.cpp (Key={Convert.ToHexString(_lastKey)}):\nstatic const uint8_t k[]={{{string.Join(",", _lastKey.Select(x => $"0x{x:X2}"))}}};\nuint8_t* p=(uint8_t*)metadataBytes; int l=utils::MemoryMappedFile::GetLength(file);\nfor(int i=0;i<l;i++) p[i]^=(k[i%8]^((i*31)&0xFF));");

        var btns = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 10) }; btns.Children.Add(bRun); btns.Children.Add(bBak); btns.Children.Add(bDec); btns.Children.Add(bCpp);
        var top = new StackPanel { Spacing = 6 };
        top.Children.Add(new TextBlock { Text = "ANTI-DUMP TOOL • UNITY IL2CPP", FontSize = 18, FontWeight = FontWeight.Bold, Foreground = new SolidColorBrush(Color.Parse("#EF4444")) });
        top.Children.Add(row1); top.Children.Add(_mode); top.Children.Add(_cMeta); top.Children.Add(_cRand); top.Children.Add(_cPe); top.Children.Add(_cBak); top.Children.Add(btns);

        var root = new DockPanel { Margin = new Thickness(16) }; DockPanel.SetDock(top, Dock.Top); root.Children.Add(top); root.Children.Add(_log);
        Content = root; Log("Ready. Select protection mode and drag & drop your game build folder.");
    }

    private void Protect()
    {
        try
        {
            string dir = (_path.Text ?? "").Trim(), dll = Path.Combine(dir, "GameAssembly.dll");
            string? meta = Directory.Exists(dir) ? Directory.GetFiles(dir, "global-metadata.dat", SearchOption.AllDirectories).FirstOrDefault() : null;
            if (!File.Exists(dll) || meta == null) { Log("[Error] GameAssembly.dll or global-metadata.dat not found."); return; }
            byte[] key = _cRand.IsChecked == true ? RandomNumberGenerator.GetBytes(8) : new byte[] { 0x5A, 0xC3, 0x19, 0x8F, 0x42, 0xE7, 0x6B, 0xD1 };
            _lastKey = key;

            if (_cBak.IsChecked == true)
            {
                if (!File.Exists(meta + ".bak")) File.Copy(meta, meta + ".bak");
                if (!File.Exists(dll + ".bak")) File.Copy(dll, dll + ".bak");
                Log("[OK] Backup files (.bak) created.");
            }
            if (_cMeta.IsChecked == true)
            {
                byte[] b = File.ReadAllBytes(meta);
                if (b.Length >= 8 && BitConverter.ToUInt32(b, 0) == 0xFAB11BAF)
                {
                    for (int i = 0; i < b.Length; i++) b[i] ^= (byte)(key[i % 8] ^ ((i * 31) & 0xFF));
                    File.WriteAllBytes(meta, b); Log($"[OK] global-metadata.dat encrypted ({b.Length:N0} bytes, Key={Convert.ToHexString(key)}).");
                }
                else Log("[Info] Metadata already encrypted.");
            }
            if (_cPe.IsChecked == true)
            {
                byte[] pe = File.ReadAllBytes(dll);
                int r = Find(pe, Encoding.ASCII.GetBytes("Rich")), d = Find(pe, Encoding.ASCII.GetBytes("DanS"));
                if (d > 0 && r > d && r - d < 512) for (int i = d; i < r + 8; i++) pe[i] = 0;
                int p = Find(pe, Encoding.ASCII.GetBytes(".pdb"));
                if (p > 4) { int s = p; while (s > 0 && pe[s - 1] >= 32 && pe[s - 1] <= 126) s--; for (int i = s; i < p + 4; i++) pe[i] = 0; }
                File.WriteAllBytes(dll, pe); Log("[OK] Rich header & PDB scrubbed.");
            }
            if (_mode.SelectedIndex == 0)
            {
                var (ok, msg) = PeGuardInjector.InjectGuardSection(dll, meta, key);
                Log(ok ? $"[OK] {msg}" : $"[Error] {msg}");
                if (ok) Log("=== [DONE] Build protection completed successfully! ===");
            }
            else Log("=== [DONE] Mode 2 completed! Click 'C++ Snippet' for your key. ===");
        }
        catch (Exception ex) { Log($"[Error] {ex.Message}"); }
    }

    private void DecryptMetadata()
    {
        try
        {
            string dir = (_path.Text ?? "").Trim(), dll = Path.Combine(dir, "GameAssembly.dll");
            string? meta = Directory.Exists(dir) ? Directory.GetFiles(dir, "global-metadata.dat", SearchOption.AllDirectories).FirstOrDefault() : null;
            if (meta == null) { Log("[Error] global-metadata.dat not found."); return; }
            byte[] b = File.ReadAllBytes(meta);
            if (b.Length >= 8 && BitConverter.ToUInt32(b, 0) == 0xFAB11BAF) { Log("[Info] Metadata already decrypted."); return; }
            byte[] key = PeGuardInjector.ExtractEmbeddedKey(dll) ?? _lastKey;
            if (b.Length < 8 || BitConverter.ToUInt32(b, 0) != (0xFAB11BAF ^ (BitConverter.ToUInt32(key, 0) ^ 0x5D3E1F00u))) { Log("[Error] Key mismatch."); return; }
            for (int i = 0; i < b.Length; i++) b[i] ^= (byte)(key[i % 8] ^ ((i * 31) & 0xFF));
            File.WriteAllBytes(meta, b); Log($"[OK] Decrypted ({b.Length:N0} bytes) with key {Convert.ToHexString(key)}!");
        }
        catch (Exception ex) { Log($"[Error] {ex.Message}"); }
    }

    private void Restore()
    {
        try
        {
            string dir = (_path.Text ?? "").Trim(); if (!Directory.Exists(dir)) return;
            int n = 0; foreach (var f in Directory.GetFiles(dir, "*.bak", SearchOption.AllDirectories)) { File.Copy(f, f[..^4], true); n++; }
            Log(n > 0 ? $"[OK] Restored {n} file(s)." : "[Info] No .bak files found.");
        }
        catch (Exception ex) { Log($"[Error] Close the game first! ({ex.Message})"); }
    }

    private static int Find(byte[] a, byte[] b) { for (int i = 0; i <= a.Length - b.Length; i++) { bool ok = true; for (int j = 0; j < b.Length; j++) if (a[i + j] != b[j]) { ok = false; break; } if (ok) return i; } return -1; }
    private void Log(string m) => _log.Text += $"[{DateTime.Now:HH:mm:ss}] {m}\n";
}
