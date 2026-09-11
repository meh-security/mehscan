using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

internal sealed class Disabled
{
    internal object Read(Stream input)
    {
        return new BinaryFormatter().Deserialize(input);
    }
}
