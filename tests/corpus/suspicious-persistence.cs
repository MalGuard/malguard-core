class P { void Configure() {
  var key = Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
  key.SetValue("Helper", "helper.exe");
  Process.Start("helper.exe");
}}
