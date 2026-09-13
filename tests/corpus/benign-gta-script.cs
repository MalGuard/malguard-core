using GTA;
public class Speedometer : Script {
  public Speedometer() { Tick += (s,e) => { var p = Game.Player.Character.Position; }; }
}
