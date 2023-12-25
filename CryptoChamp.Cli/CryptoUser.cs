using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace CryptoChamp.Cli;

public class CryptoUser
{
    readonly AsymmetricCipherKeyPair keyPair;
    readonly KyberKemGenerator generator;
    Guid Id { get; init; }
    IDictionary<Guid, byte[]> comsCache { get; init; }

    public CryptoUser()
    {
        Id = Guid.NewGuid();
        comsCache = new Dictionary<Guid, byte[]>();
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
        comsCache[toUser.Id] = encapsulatedSecret.GetSecret();
        return encapsulatedSecret.GetEncapsulation();
    }

    public void AcceptEncapsulation(CryptoUser fromUser, byte[] encapsulation)
    {
        var extractor = new KyberKemExtractor(keyPair.Private as KyberKeyParameters);
        comsCache[fromUser.Id] = extractor.ExtractSecret(encapsulation);
    }

    public string EncryptMessage(string message, CryptoUser toUser)
    {
        var plainBytes = Encoding.UTF8.GetBytes(message);
        var iv = new byte[16];
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(comsCache[toUser.Id]), 128, iv, null);
        cipher.Init(true, parameters);
        var encryptedBytes = new byte[cipher.GetOutputSize(plainBytes.Length)];
        var outLen = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, encryptedBytes, 0);
        cipher.DoFinal(encryptedBytes, outLen);
        return Convert.ToBase64String(encryptedBytes);
    }

    public string DecryptMessage(string message, CryptoUser fromUser)
    {
        byte[] iv = new byte[16];
        var encryptedBytes = Convert.FromBase64String(message);
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(comsCache[fromUser.Id]), 128, iv, null);
        cipher.Init(false, parameters);
        var plainBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
        var retLen = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, plainBytes, 0);
        cipher.DoFinal(plainBytes, retLen);
        return Encoding.UTF8.GetString(plainBytes);
    }
}