using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class SecurityFileScopeTests
    {
        [Theory]
        [InlineData(@"C:\Users\Admin\Downloads\payload.exe", true)]
        [InlineData(@"C:\Windows\Temp\evil.dll", true)]
        [InlineData(@"C:\Windows\System32\drivers\bad.sys", true)]
        [InlineData(@"C:\Users\Admin\Desktop\run.ps1", true)]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\cache.tmp", false)]
        [InlineData(@"C:\Users\Admin\Pictures\photo.jpg", false)]
        [InlineData("payload.exe", false)]
        [InlineData(null, false)]
        public void IsEtwFileEventRelevant_FiltersFirehose(string? path, bool expected)
        {
            Assert.Equal(expected, SecurityFileScope.IsEtwFileEventRelevant(path));
        }
    }
}
