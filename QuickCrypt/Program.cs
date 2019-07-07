using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace QuickCrypt {
	class Program {
		static void Main(string[] args) {
			if (args.Length != 1) return;

			Console.WriteLine("Password:");

			if (!args[0].EndsWith("_")) {
				IEnumerable<char> input = Input();
				byte[] pass = Encoding.UTF8.GetBytes(string.Join("", input));
				try {
					File.WriteAllBytes(args[0] + "_", Igor.Crypto.FilePasswordProtection.Encrypt(pass, args[0]));
					File.Delete(args[0]);
				}
				catch (Exception e) {
					Debugger.Break();
					Console.WriteLine("Unsuccessful! Press 'Return' to exit...");
					Console.ReadLine();
				}
			}
			else {
				IEnumerable<char> input = Input();
				byte[] pass = Encoding.UTF8.GetBytes(string.Join("", input));
				if (Igor.Crypto.FilePasswordProtection.Decrypt(pass, args[0], args[0].Remove(args[0].Length - 1, 1))) {
					File.Delete(args[0]);
				}
				else {
					Console.WriteLine("Unsuccessful! Press 'Return' to exit...");
					Console.ReadLine();
				}
			}
		}

		private static IEnumerable<char> Input() {
			List<char> chars = new List<char>();
			while (true) {
				ConsoleKeyInfo key = Console.ReadKey(true);
				if (key.Key == ConsoleKey.Enter)
					return chars;
				chars.Add(key.KeyChar);
			}
		}
	}
}
