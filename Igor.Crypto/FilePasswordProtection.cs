using System.IO;
using System.Security.Cryptography;

namespace Igor.Crypto {
	public static class FilePasswordProtection {

		private const int RFC_ITERATIONS = 10000;
		private const int SALT_SIZE = 16;


		public static void Setup(int iterationCount = RFC_ITERATIONS, int saltSizeLength = SALT_SIZE) {
			IterationsCount = iterationCount;
			SaltSizeLength = saltSizeLength;
		}

		public static int IterationsCount { get; private set; }
		public static int SaltSizeLength { get; private set; }

		private static AesCryptoServiceProvider GetProvider(Rfc2898DeriveBytes saltGen) {
			AesCryptoServiceProvider AESProvider = new AesCryptoServiceProvider();

			AESProvider.IV = saltGen.GetBytes(AESProvider.BlockSize / 8);
			AESProvider.Key = saltGen.GetBytes(AESProvider.KeySize / 8);
			AESProvider.Padding = PaddingMode.PKCS7;

			return AESProvider;
		}

		private static byte[] GetSaltSeed() {
			using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
				byte[] salt = new byte[SALT_SIZE];
				salt = new byte[SALT_SIZE];
				rng.GetBytes(salt);
				return salt;
			}
		}


		public static void Encrypt(byte[] password, FileInfo inputFile, string outputFilePath) {

			byte[] salt = GetSaltSeed();

			Rfc2898DeriveBytes saltGen = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);
			byte[] bytes = File.ReadAllBytes(inputFile.FullName);

			using (AesCryptoServiceProvider AESProvider = GetProvider(saltGen))
			using (ICryptoTransform enc = AESProvider.CreateEncryptor())
			using (FileStream fs = File.Create(outputFilePath)) {
				fs.Write(saltGen.Salt, 0, SALT_SIZE);
				using (CryptoStream cs = new CryptoStream(fs, enc, CryptoStreamMode.Write)) {
					cs.Write(bytes, 0, bytes.Length);
					cs.FlushFinalBlock();
				}
			}
		}

		public static void Encrypt(Rfc2898DeriveBytes derivedBytes, FileInfo inputFile, string outputFilePath) {
			byte[] bytes = File.ReadAllBytes(inputFile.FullName);

			using (AesCryptoServiceProvider AESProvider = GetProvider(derivedBytes))
			using (ICryptoTransform enc = AESProvider.CreateEncryptor())
			using (FileStream fs = File.Create(outputFilePath)) {
				fs.Write(derivedBytes.Salt, 0, SALT_SIZE);
				using (CryptoStream cs = new CryptoStream(fs, enc, CryptoStreamMode.Write)) {
					cs.Write(bytes, 0, bytes.Length);
					cs.FlushFinalBlock();
				}
			}
		}

		public static byte[] Encrypt(byte[] password, string inputFilePath) {

			byte[] salt = GetSaltSeed();

			Rfc2898DeriveBytes saltGen = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);
			byte[] bytes = File.ReadAllBytes(inputFilePath);

			using (AesCryptoServiceProvider AESProvider = GetProvider(saltGen))
			using (ICryptoTransform enc = AESProvider.CreateEncryptor())
			using (MemoryStream ms = new MemoryStream()) {
				ms.Write(saltGen.Salt, 0, SALT_SIZE);
				using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write)) {
					cs.Write(bytes, 0, bytes.Length);
					cs.FlushFinalBlock();
					ms.Seek(0, SeekOrigin.Begin);
				}
				return ms.ToArray();
			}
		}

		public static FileInfo EncryptFromMemory(byte[] password, byte[] data, string outputFilePath) {
			byte[] salt = GetSaltSeed();

			Rfc2898DeriveBytes saltGen = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);

			using (AesCryptoServiceProvider AESProvider = GetProvider(saltGen))
			using (ICryptoTransform enc = AESProvider.CreateEncryptor())
			using (MemoryStream ms = new MemoryStream()) {
				ms.Write(saltGen.Salt, 0, SALT_SIZE);
				using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write)) {
					try {
						cs.Write(data, 0, data.Length);
						cs.FlushFinalBlock();
						ms.Seek(0, SeekOrigin.Begin);
						using (FileStream fs = File.Create(outputFilePath)) {
							ms.CopyTo(fs);
						}
					}
					finally {
						cs.Close();
					}
				}
				return new FileInfo(outputFilePath);
			}
		}


		public static bool Decrypt(byte[] password, string inputFilePath, string outputFilePath) {
			using (FileStream fileStream = File.OpenRead(inputFilePath)) {
				byte[] salt = new byte[SALT_SIZE];
				fileStream.Read(salt, 0, SALT_SIZE);

				Rfc2898DeriveBytes saltGen = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);

				using (AesCryptoServiceProvider AESProvider = GetProvider(saltGen))
				using (ICryptoTransform decryptor = AESProvider.CreateDecryptor())
				using (FileStream output = File.Create(outputFilePath)) {
					try {
						using (CryptoStream cs = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Read)) {
							cs.CopyTo(output);
						}
					}
					catch (CryptographicException) {
						output.Close();
						output.Dispose();
						File.Delete(outputFilePath);
						return false;
					}
				}
				return true;
			}
		}

		public static bool Decrypt(byte[] password, string inputFilePath, out byte[] data) {
			using (FileStream fileStream = File.OpenRead(inputFilePath)) {
				byte[] salt = new byte[SALT_SIZE];
				fileStream.Read(salt, 0, SALT_SIZE);

				Rfc2898DeriveBytes saltGen = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);

				using (AesCryptoServiceProvider AESProvider = GetProvider(saltGen))
				using (ICryptoTransform decryptor = AESProvider.CreateDecryptor())
				using (MemoryStream ms = new MemoryStream()) {
					try {
						using (CryptoStream cs = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Read)) {
							cs.CopyTo(ms);
						}
						ms.Seek(0, SeekOrigin.Begin);
						data = ms.ToArray();
					}
					catch (CryptographicException) {
						data = null;
						return false;
					}
				}
				return true;
			}
		}
	}
}
