using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace CryptoChamp.Cli;

public class CryptoUser
{
    readonly AsymmetricCipherKeyPair keyPair;
    readonly KyberKemGenerator generator;
    readonly Guid id;
    readonly IDictionary<Guid, byte[]> communicationCache;

    public CryptoUser()
    {
        id = Guid.NewGuid();
        communicationCache = new Dictionary<Guid, byte[]>();
        var random = new SecureRandom();
        var parameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber1024_aes);
        var keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.Init(parameters);
        keyPair = keyPairGenerator.GenerateKeyPair();
        generator = new KyberKemGenerator(random);
    }

    public byte[] GenerateEncapsulation(CryptoUser toUser)
    {
        var encapsulatedSecret = generator.GenerateEncapsulated(toUser.keyPair.Public);
        communicationCache[toUser.id] = encapsulatedSecret.GetSecret();
        return encapsulatedSecret.GetEncapsulation();
    }

    public void AcceptEncapsulation(CryptoUser fromUser, byte[] encapsulation)
    {
        var extractor = new KyberKemExtractor(keyPair.Private as KyberKeyParameters);
        communicationCache[fromUser.id] = extractor.ExtractSecret(encapsulation);
    }

    public string EncryptMessage(string message, CryptoUser toUser)
    {
        if (!communicationCache.TryGetValue(toUser.id, out var sharedKey))
        {
            throw new InvalidOperationException($"Please call {nameof(GenerateEncapsulation)} with the target user first!");
        }
        
        // Get bytes of plaintext string
        var plainBytes = Encoding.UTF8.GetBytes(message);

        // Get parameter sizes
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;
        var cipherSize = plainBytes.Length;

        // We write everything into one big array for easier encoding
        var encryptedDataLength = 4 + nonceSize + 4 + tagSize + cipherSize;
        var encryptedData = encryptedDataLength < 1024 ? stackalloc byte[encryptedDataLength] : new byte[encryptedDataLength].AsSpan();

        // Copy parameters
        BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), nonceSize);
        BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4), tagSize);
        var nonce = encryptedData.Slice(4, nonceSize);
        var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
        var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

        // Generate secure nonce
        RandomNumberGenerator.Fill(nonce);

        // Encrypt
        using var aes = new AesGcm(sharedKey, tagSize);
        aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, tag);

        // Encode for transmission
        return Convert.ToBase64String(encryptedData);
    }

    public string DecryptMessage(string message, CryptoUser fromUser)
    {
        if (!communicationCache.TryGetValue(fromUser.id, out var sharedKey))
        {
            throw new InvalidOperationException($"Please call {nameof(AcceptEncapsulation)} with fromUser first!");
        }
        
        // Decode
        var encryptedData = Convert.FromBase64String(message).AsSpan();

        // Extract parameter sizes
        var nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4));
        var tagSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4));
        var cipherSize = encryptedData.Length - 4 - nonceSize - 4 - tagSize;

        // Extract parameters
        var nonce = encryptedData.Slice(4, nonceSize);
        var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
        var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

        // Decrypt
        var plainBytes = cipherSize < 1024 ? stackalloc byte[cipherSize] : new byte[cipherSize];
        using var aes = new AesGcm(sharedKey, tagSize);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        // Convert plain bytes back into string
        return Encoding.UTF8.GetString(plainBytes);
    }
}