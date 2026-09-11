using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

internal sealed class Enabled
{
    internal object Read(Stream input)
    {
        return new BinaryFormatter().Deserialize(input);
    }
}
