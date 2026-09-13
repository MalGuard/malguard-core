class U { void Go() {
  var wc = new WebClient();
  wc.DownloadFile("https://example.invalid/update.bin", "update.bin");
  Process.Start("update.bin");
}}
