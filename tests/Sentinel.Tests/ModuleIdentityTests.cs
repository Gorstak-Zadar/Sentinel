using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ModuleIdentityTests
    {
        private const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        private const string Ceprkac = @"C:\Program Files\Ceprkac\Ceprkac.exe";
        private const string Svchost = @"C:\Windows\System32\svchost.exe";

        [Theory]
        [InlineData(@"C:\Windows\System32\kernel32.dll")]
        [InlineData(@"C:\Windows\SysWOW64\ntdll.dll")]
        [InlineData(@"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64\nvldumd.dll")]
        [InlineData(@"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll")]
        [InlineData(@"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Windows.Form\System.Windows.Forms.ni.dll")]
        [InlineData(@"C:\Windows\SystemApps\MicrosoftWindows.Client.Photon_cw5n1h2txyewy\Microsoft.UI.Xaml.dll")]
        [InlineData(@"C:\Windows\uus\AMD64\uusbrain.dll")]
        [InlineData(@"C:\Program Files\WindowsApps\Microsoft.WindowsStore_8wekyb3d8bbwe\WinStore.App.exe")]
        [InlineData(@"C:\Program Files\Microsoft\EdgeWebView\Application\151.0.4129.101\msedge.dll")]
        [InlineData(@"C:\Users\Admin\AppData\Roaming\Ceprkac\WebView2UserData\EBWebView\WidevineCdm\widevine.dll")]
        [InlineData(@"C:\Program Files\NVIDIA Corporation\nvapi64.dll")]
        public void KeepTrees_AreAllowed_InAnyProcess(string module)
        {
            var v = ModuleIdentity.Evaluate(Chrome, module, _ => false);
            Assert.True(v.Allowed, v.Reason + " for " + module);
        }

        [Fact]
        public void WindowsTemp_Sideload_IsDenied()
        {
            var v = ModuleIdentity.Evaluate(
                Svchost,
                @"C:\Windows\Temp\version.dll",
                _ => false);
            Assert.False(v.Allowed);
        }

        [Fact]
        public void ProcessImage_IsAlwaysAllowed()
        {
            var v = ModuleIdentity.Evaluate(Ceprkac, Ceprkac, _ => false);
            Assert.True(v.Allowed);
            Assert.Equal("process-image", v.Reason);
        }

        [Fact]
        public void AppDirectory_OwnDll_Unsigned_IsStillAllowed()
        {
            var v = ModuleIdentity.Evaluate(
                Chrome,
                @"C:\Program Files\Google\Chrome\Application\chrome_elf.dll",
                _ => false);
            Assert.True(v.Allowed, v.Reason);
            Assert.Equal("app-directory", v.Reason);
        }

        [Fact]
        public void AppDirectory_SideloadName_Unsigned_IsDenied()
        {
            var v = ModuleIdentity.Evaluate(
                Ceprkac,
                @"C:\Program Files\Ceprkac\version.dll",
                _ => false);
            Assert.False(v.Allowed);
            Assert.Equal("sideload-plant-in-appdir", v.Reason);
        }

        [Theory]
        [InlineData("dbghelp.dll")]
        [InlineData("version.dll")]
        [InlineData("winmm.dll")]
        [InlineData("winhttp.dll")]
        public void AppDirectory_HijackName_IsDenied_EvenIfMicrosoftSigned(string file)
        {
            var v = ModuleIdentity.Evaluate(
                Ceprkac,
                @"C:\Program Files\Ceprkac\" + file,
                _ => true);
            Assert.False(v.Allowed);
            Assert.Equal("sideload-plant-in-appdir", v.Reason);
        }

        [Fact]
        public void System32_Dbghelp_IsKeepTree_EvenForThirdPartyProcess()
        {
            var v = ModuleIdentity.Evaluate(
                Chrome,
                @"C:\Windows\System32\dbghelp.dll",
                _ => false);
            Assert.True(v.Allowed, v.Reason);
            Assert.Equal("keep-tree", v.Reason);
        }

        [Fact]
        public void ForeignPath_InjectDll_IsDenied()
        {
            var v = ModuleIdentity.Evaluate(
                Ceprkac,
                @"C:\Evil\helper.dll",
                _ => false);
            Assert.False(v.Allowed);
            Assert.Equal("foreign-path", v.Reason);
        }

        [Fact]
        public void TempDrop_IsDenied_EvenIfMicrosoftSigned()
        {
            var v = ModuleIdentity.Evaluate(
                Chrome,
                @"C:\Users\Admin\AppData\Local\Temp\version.dll",
                _ => true);
            Assert.False(v.Allowed);
        }

        [Fact]
        public void DownloadsDrop_IsDenied()
        {
            var v = ModuleIdentity.Evaluate(
                Ceprkac,
                @"C:\Users\Admin\Downloads\inject.dll",
                _ => false);
            Assert.False(v.Allowed);
            Assert.Equal("user-writable-drop", v.Reason);
        }

        [Fact]
        public void MicrosoftSigned_ProgramFiles_OutsideAppDir_IsAllowed()
        {
            var v = ModuleIdentity.Evaluate(
                Ceprkac,
                @"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\coreclr.dll",
                _ => true);
            Assert.True(v.Allowed, v.Reason);
        }

        [Fact]
        public void MicrosoftSigned_FromRandomFolder_IsDenied()
        {
            var v = ModuleIdentity.Evaluate(
                Svchost,
                @"C:\Evil\kernel32.dll",
                _ => true);
            Assert.False(v.Allowed);
        }

        [Fact]
        public void EmptyPath_IsDenied()
        {
            Assert.False(ModuleIdentity.IsAllowed(Ceprkac, null));
            Assert.False(ModuleIdentity.IsAllowed(Ceprkac, ""));
            Assert.False(ModuleIdentity.IsAllowed(Ceprkac, "   "));
        }

        [Fact]
        public void GpuIcd_ByFilename_IsAllowed()
        {
            var v = ModuleIdentity.Evaluate(
                Ceprkac,
                @"D:\SomeIcd\nvwgf2umx.dll",
                _ => false);
            Assert.True(v.Allowed);
            Assert.Equal("gpu-icd", v.Reason);
        }

        [Fact]
        public void NtLiteScratch_IsOsServicing()
        {
            Assert.True(ModuleIdentity.IsOsServicingPath(@"C:\Users\Admin\AppData\Local\Temp\NLTmpScratch\DismCorePS.dll"));
            var v = ModuleIdentity.Evaluate(
                @"C:\Windows\System32\Dism\DismHost.exe",
                @"C:\Users\Admin\AppData\Local\Temp\NLTmpScratch\DismCorePS.dll",
                _ => false);
            Assert.True(v.Allowed);
            Assert.Equal("os-servicing", v.Reason);
        }

        [Fact]
        public void Svchost_System32Module_IsKeepTree()
        {
            var v = ModuleIdentity.Evaluate(
                Svchost,
                @"C:\Windows\System32\cryptbase.dll",
                _ => false);
            Assert.True(v.Allowed);
        }

        [Fact]
        public void Svchost_InjectedFromUserProfile_IsDenied()
        {
            var v = ModuleIdentity.Evaluate(
                Svchost,
                @"C:\Users\Admin\AppData\Roaming\evil.dll",
                _ => false);
            Assert.False(v.Allowed);
        }
    }
}
