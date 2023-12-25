using System.Security.Cryptography;

namespace CryptoChamp.Cli;

public class AesGcmCiphertext(byte[] nonce, byte[] tag, byte[] ciphertextBytes)
{
    public byte[] Nonce { get; } = nonce;
    public byte[] Tag { get; } = tag;
    public byte[] CiphertextBytes { get; } = ciphertextBytes;

    public static AesGcmCiphertext FromBase64String(string data)
    {
        var dataBytes = Convert.FromBase64String(data);
        return new AesGcmCiphertext(
            dataBytes.Take(AesGcm.NonceByteSizes.MaxSize).ToArray(),
            dataBytes[^AesGcm.TagByteSizes.MaxSize..],
            dataBytes[AesGcm.NonceByteSizes.MaxSize..^AesGcm.TagByteSizes.MaxSize]
        );
    }

    public override string ToString()
    {
        return Convert.ToBase64String(Nonce.Concat(CiphertextBytes).Concat(Tag).ToArray());
    }
}