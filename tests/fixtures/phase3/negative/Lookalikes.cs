class Lookalikes
{
    void Review(string value)
    {
        Logger.ReadAllText(value);
        SafeScript.Evaluate(value);
        cache.Lookup(value);
    }
}

