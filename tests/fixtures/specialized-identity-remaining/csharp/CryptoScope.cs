using System;

class CryptoScope
{
    object random;

    int CreateResetToken()
    {
        {
            Random random = null;
        }
        return random.Next();
    }
}
