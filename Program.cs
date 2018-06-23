using System;
using System.Linq;
using System.Security.Cryptography;
using static System.Text.Encoding;

namespace OnlyKeyQA
{
	internal class Program
	{
		public static void Main(string[] args)
		{
			Console.WriteLine("This application demonstrates 3 problems with the OnlyKey.\n" +
			                  "Please insert an OnlyKey, and put it in configuration mode.\n" +
			                  "RSA Key #4, and the lables for several keys will be overwritten.\n" +
			                  "Press ENTER when ready.");
			Console.ReadLine();
			var onlyKey = new OnlyKey();
			
			Console.WriteLine("Generating first RSA 2048 key... ");
			var rsa1 = new RSACryptoServiceProvider(2048);
			var key1 = rsa1.ExportParameters(true);
			Console.WriteLine("Done");
			
			
			Console.WriteLine("\n\nDemonstrating problem #1: Cannot set RSA Key labels" +
			                  "\n===================================================");
			Console.WriteLine("Attempting to set values using 25-29");
			Console.WriteLine("first... ");
			var response = onlyKey.SetField(SlotId.RsaKey1, Field.Label, "first");
			Console.WriteLine(response);
			Console.WriteLine("second...");
			response = onlyKey.SetField(SlotId.RsaKey2, Field.Label, "second");
			Console.WriteLine(response);
			Console.WriteLine("third...");
			response = onlyKey.SetField(SlotId.RsaKey3, Field.Label, "third");
			Console.WriteLine(response);
			Console.WriteLine("fourth...");
			response = onlyKey.SetField(SlotId.RsaKey4, Field.Label, "fourth");
			Console.WriteLine(response);
			Console.WriteLine("ecc...");
			response = onlyKey.SetField(SlotId.EccKey1, Field.Label, "ecc");
			Console.WriteLine(response);
			var keyLabels = onlyKey.GetKeyLabels();
			foreach (var key in keyLabels)
			{
				Console.WriteLine($"\t{key.Key}: {key.Value}");
			}
			
			Console.WriteLine("Attempting to set values using 1-4");
			Console.WriteLine("first... ");
			response = onlyKey.SetField((SlotId) 1, Field.Label, "first");
			Console.WriteLine(response);
			Console.WriteLine("second...");
			response = onlyKey.SetField((SlotId) 2, Field.Label, "second");
			Console.WriteLine(response);
			Console.WriteLine("third...");
			response = onlyKey.SetField((SlotId) 3, Field.Label, "third");
			Console.WriteLine(response);
			Console.WriteLine("fourth...");
			response = onlyKey.SetField((SlotId) 4, Field.Label, "fourth");
			Console.WriteLine(response);
			keyLabels = onlyKey.GetKeyLabels();
			foreach (var key in keyLabels)
			{
				Console.WriteLine($"\t{key.Key}: {key.Value}");
			}
			
			
			Console.WriteLine("\n\nDemonstrating problem #2: OnlyKey's internal buffer is not cleared in timely manner after decrypting" +
			                  "\n====================================================================================================");
			Console.WriteLine("Writing RSA Key 1 to slot 4... ");
			response = onlyKey.SetPrivateKey(SlotId.RsaKey4, KeyFeatures.Decryption, key1);
			Console.WriteLine(response);
			
			var testMessageA = "Decryption successful A";
			var testMessageB = "Decryption successful B";
			Console.WriteLine($"Encrypting \"{testMessageA}\" with RSA public key 1... ");
			var encryptedA = rsa1.Encrypt(ASCII.GetBytes(testMessageA), false);
			Console.WriteLine("Done");
			
			Console.WriteLine($"Encrypting \"{testMessageB}\" with RSA public key 1... ");
			var encryptedB = rsa1.Encrypt(ASCII.GetBytes(testMessageB), false);
			Console.WriteLine("Done");
			
			Console.WriteLine("Asking OnlyKey to decrypt message A...");
			var decrypted = onlyKey.DecryptString(SlotId.RsaKey4, encryptedA);
			Console.WriteLine("OnlyKey says: " + decrypted +
			                  "\n Is it the same? " + decrypted == testMessageA);
			
			Console.WriteLine("Asking OnlyKey for key labels...");
			keyLabels = onlyKey.GetKeyLabels();
			foreach (var key in keyLabels)
			{
				Console.WriteLine($"\t{key.Key}: {key.Value}");
			}
			
			Console.WriteLine("Asking OnlyKey `` decrypt message B...");
			decrypted = onlyKey.DecryptString(SlotId.RsaKey4, encryptedB);
			Console.WriteLine("OnlyKey says: " + decrypted +
			                  "\n Is it the same? " + decrypted == testMessageB);
			
			
			Console.WriteLine("\nDemonstrating problem #1: Cannot set key after decryption without removing and re-inserting device, otherwise the returned public key is incorrect" +
			                  "\n================================================================================================================================================");
			Console.WriteLine("Generating second RSA 2048 key... ");
			var rsa2 = new RSACryptoServiceProvider(2048);
			var key2 = rsa2.ExportParameters(true);
			Console.WriteLine("Done");
			
			Console.WriteLine("Writing RSA Key 2 to slot 4... ");
			response = onlyKey.SetPrivateKey(SlotId.RsaKey4, KeyFeatures.Decryption, key2);
			Console.WriteLine(response);
			
			Console.WriteLine("Asking OnlyKey for RSA public from slot 4... ");
			var publicRepro = onlyKey.GetPublicRsaKey(SlotId.RsaKey4, rsa1.KeySize / 8);
			Console.WriteLine("Done");
			Console.WriteLine("The real public key is " + string.Join(", ", key2.Modulus) +
			                  "\nOnlyKey says the public key is " + string.Join(", ", publicRepro.Modulus) +
			                  $"\nAre they the same? {publicRepro.Modulus.SequenceEqual(key2.Modulus)}");
			
			
			Console.WriteLine("\n\nUnit tests complete. Press Enter to quit.");
			Console.ReadLine();
		}
	}
}