using System;

public static class OrdinaryRandomness
{
    public static int SimulationStep() => Random.Shared.Next();
    public static double UiJitter() => new Random().NextDouble();
    public static Guid NewEntityId() => Guid.NewGuid();
    public static int NewToken() => Random.Shared.Next();

    public static int ResetAttemptCounter()
    {
        var resetAttempts = new Random().Next();
        return resetAttempts;
    }
}
