using BaumSecure.Services;

namespace BaumSecure;

static class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);

        // Check for updates silently before showing any UI.
        // If a newer release is found on GitHub, the installer is downloaded and
        // run automatically — the app exits here and relaunches at the new version.
        UpdateService.CheckAndApplyAsync().GetAwaiter().GetResult();

        Application.Run(new MainForm());
    }
}
