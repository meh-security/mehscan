using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

sealed class DeserializationScope
{
    private FormatterLookalike formatter = new FormatterLookalike();

    object Review(Stream payload, BinaryFormatter importedFormatter)
    {
        {
            BinaryFormatter formatter = importedFormatter;
        }
        return formatter.Deserialize(payload);
    }
}

sealed class FormatterLookalike
{
    public object Deserialize(Stream payload) => payload;
}
