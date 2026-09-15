class SyntheticFixture { void Inspect() {
  var commandText = "vssadmin delete shadows";
  var p = new ProcessStartInfo();
  p.FileName = "cmd.exe";
  p.Arguments = commandText;
}}
