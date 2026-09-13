using Microsoft.Win32; class C{void X(){var k=Registry.CurrentUser.CreateSubKey("Software\Microsoft\Windows\CurrentVersion\Run");k.SetValue("A","a.exe");}}
