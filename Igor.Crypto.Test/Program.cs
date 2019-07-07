using System;
using System.IO;
using System.Text;

namespace Igor.Crypto.Test {
	class Program {
		static void Main(string[] args) {
			byte[] data = new byte[8] { 0, 1, 2, 3, 4, 5, 6, 7 };
			byte[] pass = Encoding.UTF8.GetBytes("Hello");
			FilePasswordProtection.EncryptFromMemory(pass, data, "out.enc");

			byte[] dataOut;

			FilePasswordProtection.Decrypt(pass, "out.enc", out dataOut);
			FilePasswordProtection.Decrypt(pass, "out.enc", "out.unenc");

			data = FilePasswordProtection.Encrypt(pass, "text.txt");
			File.WriteAllBytes("enc.txt", data);

			//FilePasswordProtection.Decrypt(pass, "enc.txt", out dataOut);
			FilePasswordProtection.Decrypt(pass, "enc.txt", "out.txt");

		}
	}
}
