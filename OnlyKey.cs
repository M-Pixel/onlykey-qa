using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using HidSharp;
using static System.Text.Encoding;

namespace OnlyKeyQA
{
	public class OnlyKey
	{
		/*# Constants #*/
		/// <summary>
		/// Keys are Vendor IDs, values are Product IDs
		/// </summary>
		public static readonly ReadOnlyDictionary<int, int[]> DeviceIds = new ReadOnlyDictionary<int, int[]>(new Dictionary<int, int[]>
		{
			[5824] = new[] {1158},
			[7504] = new[] {24828}
		});
		
		// TODO: Use `#if` to change this value on non-Windows systems
		private const int MaxInputReportSize = 65;

		private static readonly byte[] MessageHeader = {0, 255, 255, 255, 255};

		private const int MaxPayloadSize = 64 - 4 /* header */ - 1 /* message */ - 1 /* size */;

		private const int MaxPayloadChunkSize = MaxPayloadSize - 1;

		private readonly HidStream _deviceCommunicationStream;

		public OnlyKey()
		{
			var localDeviceList = DeviceList.Local;

			var okDevice = localDeviceList.GetHidDevices().FirstOrDefault((possibleDevice) =>
				DeviceIds.ContainsKey(possibleDevice.VendorID) &&
				DeviceIds[possibleDevice.VendorID].Contains(possibleDevice.ProductID) &&
				possibleDevice.GetMaxInputReportLength() == MaxInputReportSize);

			if (okDevice == null)
			{
				Console.WriteLine("OnlyKey not currently plugged in. Exiting.");
				Console.ReadLine();
				Environment.Exit(1);
			}
			Console.WriteLine("OnlyKey found. Opening communication stream...");
			while (!okDevice.TryOpen(out _deviceCommunicationStream))
			{
				Console.WriteLine("Failed to open communication stream. Trying again in 1 second.");
				Thread.Sleep(1000);
			}
			Console.WriteLine("Communication stream opened successfully.");
		}

		~OnlyKey()
		{
			_deviceCommunicationStream?.Close();
		}
		
		public string DecryptString(SlotId slotId, byte[] encrypted)
		{
			var bytes = Decrypt(slotId, encrypted);
			var length = bytes.Length;
			Console.WriteLine($"Decrypt message received back {length} bytes.");
			while (length > 0 && bytes[length - 1] == 0)
				--length;
			Console.WriteLine($"Excluding tailing zeroes, the message's length is actually {length} bytes.");
			return ASCII.GetString(bytes, 0, length);
		}

		public byte[] Decrypt(SlotId slotId, byte[] encrypted, bool trim = false)
		{
			var prettyPrintEncrypted = string.Join(", ", encrypted);
			Console.WriteLine($"Will attempt to decrypt {prettyPrintEncrypted} using key in slot {slotId}");
			var slotAsByte = RsaSlotIdToNumber(slotId);

			var correctPinEntered = false;
			var decryptedPos = 0;
			var decrypted = new byte[encrypted.Length];
			while (!correctPinEntered)
			{
				SendCryptoMessage(message: Message.Decrypt, slotNumber: slotAsByte, payload: encrypted);

				ChallengePin(encrypted);

				// Retrieve decrypted content

				// OnlyKey will send ENTER when PIN has been entered
				while (Console.ReadKey(true).Key != ConsoleKey.Enter)
				{
				}

				Console.WriteLine("PIN entered");
				Thread.Sleep(500);

				var chunk = new byte[65];
				// -1 came from incorrect pin entry as a way of escaping this while so that decrypt is re-run
				if (decryptedPos == -1)
					decryptedPos = 0;
				while (decryptedPos == 0)
				{
					// Decryption can take a while
					try
					{
						// TODO: OnlyKey firmware needs to be changed to include runlength if we want to avoid leveraging timeout for end detection when end falls on a 64th byte
						while (true)
						{
							_deviceCommunicationStream.Read(chunk);
							Console.WriteLine("Read bytes from HID: " + string.Join(", ", chunk));
							
							var messageLength = Array.IndexOf(array: chunk, value: (byte) 0, startIndex: 1) - 1;
							
							if (messageLength == -2)
								messageLength = 64;

							correctPinEntered = true;
							Array.Copy(sourceArray: chunk, sourceIndex: 1, destinationArray: decrypted,
								destinationIndex: decryptedPos, length: Math.Min(messageLength, decrypted.Length - decryptedPos));

							decryptedPos += messageLength;
							if (messageLength < 64)
								break;
						}
					}
					catch (TimeoutException)
					{
					}
				}
			}

			if (trim)
			{
				var trimmed = new byte[decryptedPos];
				Array.Copy(decrypted, trimmed, decryptedPos);
				decrypted = trimmed;
			}

			return decrypted;
		}

		private void SendCryptoMessage(Message message, byte slotNumber, byte[] payload)
		{
			var payloadPrettyPrint = string.Join(", ", payload);
			Console.WriteLine($"Sending long message:\n" +
			                  $"\tMessage: {message}\n" +
			                  $"\tSlot #: {slotNumber}\n" +
			                  $"\tPayload: {payloadPrettyPrint}");
			
			var remainingPayloadLength = payload.Length;
			var payloadPos = 0;

			var chunk = new byte[MaxPayloadSize]; 
			while (remainingPayloadLength != 0)
			{
				var chunkSize = Math.Min(MaxPayloadChunkSize, remainingPayloadLength);
				remainingPayloadLength -= chunkSize;
				var lengthByte = (byte) (chunkSize == MaxPayloadChunkSize ? 255 : chunkSize);
				chunk[0] = lengthByte;
				Array.Copy(sourceArray: payload, sourceIndex: payloadPos, destinationArray: chunk, destinationIndex: 1,
					length: chunkSize);
				payloadPos += chunkSize;
				SendMessage(message: message, slotNumber: slotNumber, payload: chunk, payloadLength: chunkSize + 1);
			}
		}
		
		private void SendMessage(byte[] payload = null, int payloadLength = -1, Message message = Message.Null,
			byte slotNumber = 0, Field field = Field.Null)
		{
			var payloadPrettyPrint = payload == null ? "null" : string.Join(", ", payload.Take(payloadLength));
			Console.WriteLine($"Sending Message:\n" +
			                  $"\tMessage: {message}\n" +
			                  $"\tSlot #: {slotNumber}\n" +
			                  $"\tField: {field}\n" +
			                  $"\tPayload: {payloadPrettyPrint}");
			var buffer = new byte[MaxInputReportSize];
			var bufferPos = MessageHeader.Length;
			Array.Copy(sourceArray: MessageHeader, destinationArray: buffer, length: bufferPos);

			if (message != Message.Null)
				buffer[bufferPos++] = (byte) message;

			if (slotNumber != 0)
				buffer[bufferPos++] = slotNumber;

			if (field != Field.Null)
				buffer[bufferPos++] = (byte) field;

			if (payload != null)
			{
				if (payloadLength == -1)
					payloadLength = payload.Length;

				Array.Copy(sourceArray: payload, sourceIndex: 0, destinationArray: buffer,
					destinationIndex: bufferPos, length: payloadLength);
			}
			Console.WriteLine("Writing bytes to HID: " + string.Join(", ", buffer));
			_deviceCommunicationStream.Write(buffer);
		}
		
		private void ChallengePin(byte[] encrypted)
		{
			// Calculate challenge pin using the same algorithm that the device's firmware uses
			var hashSlingingSlasher = SHA256.Create();
			var hash = hashSlingingSlasher.ComputeHash(encrypted);
			Console.WriteLine($"Enter the challenge pin: ({GetButton(hash[0])}) ({GetButton(hash[15])}) ({GetButton(hash[31])})");
		}
		
		private int GetButton(byte character)
		{
			if (character < 6)
				return 1;
			return character % 5 + 1;
		}
		
		// I think there's some significance to the 25+ index for key slots,
		// but the SETPRIV function in OnlyKey's firmware uses a range of 1-4 for RSA key slot identifiers
		private const int RsaEnumOffset = (byte) SlotId.RsaKey1 - 1;
		private byte RsaSlotIdToNumber(SlotId slotId) => (byte) (slotId - RsaEnumOffset);
		
		
		public string SetPrivateKey(SlotId slotId, KeyFeatures features, RSAParameters key)
		{
			var keyLengthInBytes = key.Modulus.Length;
			var halfKeyLengthInBytes = key.Q.Length;
			var keyLengthInKibibits = keyLengthInBytes / 128; // 1024 bits is 128 bytes
			var slotNumber = RsaSlotIdToNumber(slotId);
			
			// payload is p then q
			var payload = new byte[MaxPayloadSize];
			payload[0] = (byte) ((int) features | keyLengthInKibibits);
			var keyPos = 0;
			while (keyPos < keyLengthInBytes)
			{
				int length;
				if (keyPos < halfKeyLengthInBytes)
				{
					// Deal with the fact that 57 is not evenly divisible into 128
					length = Math.Min(halfKeyLengthInBytes - keyPos, MaxPayloadChunkSize);
					
					Array.Copy(sourceArray: key.Q, sourceIndex: keyPos, destinationArray: payload, destinationIndex: 1,
						length: length);
					
					// If the end of Q was reached, start copying from P
					if (length != MaxPayloadChunkSize)
					{
						Array.Copy(sourceArray: key.P, sourceIndex: 0, destinationArray: payload,
							destinationIndex: 1 + length, length: MaxPayloadChunkSize - length);
						length = MaxPayloadChunkSize;
					}
				}
				else
				{
					var pPos = keyPos - halfKeyLengthInBytes;
					length = Math.Min(halfKeyLengthInBytes - pPos, MaxPayloadChunkSize);
					Array.Copy(sourceArray: key.P, sourceIndex: pPos, destinationArray: payload, destinationIndex: 1,
						length: length);
				}

				keyPos += MaxPayloadChunkSize;

				SendMessage(message: Message.SetPrivateKey, slotNumber: slotNumber, payload: payload,
					payloadLength: length + 1);
			}

			return ReadString();
		}
		
		private string ReadString()
		{
			var buffer = _deviceCommunicationStream.Read();
			Console.WriteLine("Read from HID: " + string.Join(", ", buffer));
			return ASCII.GetString(buffer, index: 1, count: Array.IndexOf(buffer, (byte) 0, startIndex: 1) + 1);
		}
		
		public RSAParameters GetPublicRsaKey(SlotId slotId, int lengthInBytes = -1)
		{
			SendMessage(message: Message.GetPublicKey, slotNumber: RsaSlotIdToNumber(slotId));
			Thread.Sleep(1500);
			
			var publicKey = new byte[lengthInBytes == -1 ? 4096/8 : lengthInBytes];
			var chunk = new byte[65];
			var position = 0;
			while (position < lengthInBytes)
			{
				try
				{
					_deviceCommunicationStream.Read(chunk);
				}
				catch (TimeoutException)
				{
					if (lengthInBytes == -1)
					{
						publicKey = publicKey.Take(position).ToArray();
						break;
					}
					throw new ArgumentOutOfRangeException($"The public key in slot {slotId} is less than the specified {lengthInBytes} bytes.");
				}

				Array.Copy(sourceArray: chunk, sourceIndex: 1, destinationArray: publicKey, destinationIndex: position,
					length: 64);
				position += 64;
			}

			return new RSAParameters {Modulus = publicKey, Exponent = new byte[] {1, 0, 1}};
		}
		
		public Dictionary<SlotId, string> GetKeyLabels()
		{
			SendMessage(message: Message.GetLabels, slotNumber: 107 /* ASCII for 'k' as in "key" */);
			var results = new Dictionary<SlotId, string>();
			for (int labelIndex = 0; labelIndex < 36; labelIndex++)
			{
				var data = _deviceCommunicationStream.Read();
				if (data[2] != 124 /* `|` */)
				{
					throw new Exception(ASCII.GetString(data));
				}
				// [0, slot #, '|', label..., ' ', ' ', ' ', ' ', 0...]
				results.Add((SlotId) data[1], ASCII.GetString(data, 3, Array.IndexOf(data, (byte) 0, 3) + 1 - 4));
			}

			return results;
		}
		
		public string SetField(SlotId slotId, Field field, string contents) =>
			SetField(slotId, field, ASCII.GetBytes(contents));
		
		public string SetField(SlotId slotId, Field field, byte[] contents, int contentLength = -1)
		{
			if (contentLength == -1)
			{
				contentLength = contents.Length;
				
				// too-long contents will cause exception
				// in order to allow API consumer to give a byte array that is bigger than limit, but which doesn't
				// actually contain data that fills the whole thing, calculate the length excluding trailing 0s
				while (contentLength != 0 && contents[contentLength - 1] == 0)
					--contentLength;
				
				// automatically calculate length if only start-index is provided
				contentLength = Math.Max(1, contentLength);
			}

			SendMessage(message: Message.SetSlot, slotNumber: (byte) slotId, field: field,
				payload: contents, payloadLength: contentLength);
			return ReadString();
		}

	}
	
	public enum SlotId : byte
	{
		Slot1A = 1,
		Slot2A = 2,
		Slot3A = 3,
		Slot4A = 4,
		Slot5A = 5,
		Slot6A = 6,
		Slot1B = 7,
		Slot2B = 8,
		Slot3B = 9,
		Slot4B = 16,
		Slot5B = 17,
		Slot6B = 18,
		RsaKey1 = 25,
		RsaKey2 = 26,
		RsaKey3 = 27,
		RsaKey4 = 28,
		EccKey1 = 29,
		EccKey2 = 30,
		EccKey3 = 31,
		EccKey4 = 32,
		EccKey5 = 33,
		EccKey6 = 34,
		EccKey7 = 35,
		EccKey8 = 36,
		EccKey9 = 37,
		EccKey10 = 38,
		EccKey11 = 39,
		EccKey12 = 40,
		EccKey13 = 41,
		EccKey14 = 42,
		EccKey15 = 43,
		EccKey16 = 44,
		EccKey17 = 45,
		EccKey18 = 46,
		EccKey19 = 47,
		EccKey20 = 48,
		EccKey21 = 49,
		EccKey22 = 50,
		EccKey23 = 51,
		EccKey24 = 52,
		EccKey25 = 53,
		EccKey26 = 54,
		EccKey27 = 55,
		EccKey28 = 56,
		EccKey29 = 57,
		EccKey30 = 58,
		EccKey31 = 59,
		EccKey32 = 60,
	}
	
	internal enum Message : byte
	{
		Null = 0,
		SetPin = 225,
		SetSelfDestructPin = 226,
		SetPlausibleDeniabilityPin = 227,
		SetTime = 228,
		GetLabels = 229,
		SetSlot = 230,
		WipeSlot = 231,
		SetU2FPrivate = 232,
		WipeU2FPrivate = 233,
		SetU2FCert = 234,
		WipeU2FCert = 235,
		GetPublicKey = 236,
		SignChallenge = 237,
		WipePrivate = 238,
		SetPrivateKey = 239,
		Decrypt = 240,
		Restore = 241
	}
	public enum Field : byte
	{
		Null = 0,
		Label = 1,
		Url = 15,
		Delay1 = 17,
		NextKey4 = 18,
		UserName = 2,
		NextKey1 = 16,
		NextKey2 = 3,
		Delay2 = 4,
		Password = 5,
		NextKey3 = 6,
		Delay3 = 7,
		NextKey5 = 19,
		TfaType = 8,
		TotpKey = 9,
		YubiAuth = 10,
		IdleTimeout = 11,
		WipeMode = 12,
		KeyTypeSpeed = 13,
		KeyLayout = 14
	}
	[Flags]
	public enum KeyFeatures : byte
	{
		Authentication = 1 << 4,
		Decryption = 1 << 5,
		Signature = 1 << 6,
		Backup = 1 << 7
	}
}