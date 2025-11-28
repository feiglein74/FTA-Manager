using System;
using System.Security.Cryptography;
using System.Text;

namespace SetFTA
{
    /// <summary>
    /// Computes the UserChoice hash that Windows requires for file type associations.
    /// Based on reverse engineering by Christoph Kolbicz (SetUserFTA) and PS-SFTA.
    /// </summary>
    public static class UserChoiceHash
    {
        private const string UserExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}";

        /// <summary>
        /// Computes the UserChoice hash for a file type or protocol association.
        /// </summary>
        /// <param name="extension">File extension (e.g., ".pdf") or protocol (e.g., "http")</param>
        /// <param name="userSid">Current user's SID</param>
        /// <param name="progId">Program identifier (e.g., "AcroExch.Document.DC")</param>
        /// <param name="timestamp">Hex timestamp from GetHexDateTime()</param>
        /// <returns>Base64-encoded hash string</returns>
        public static string ComputeHash(string extension, string userSid, string progId, string timestamp)
        {
            string baseInfo = $"{extension}{userSid}{progId}{timestamp}{UserExperience}".ToLowerInvariant();
            return GetHash(baseInfo);
        }

        /// <summary>
        /// Gets the current timestamp in the format Windows expects.
        /// </summary>
        public static string GetHexDateTime()
        {
            var now = DateTime.Now;
            var roundedTime = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0);
            long fileTime = roundedTime.ToFileTime();
            return fileTime.ToString("x16");
        }

        /// <summary>
        /// Gets the current user's SID.
        /// </summary>
        public static string GetUserSid()
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
        }

        private static string GetHash(string baseInfo)
        {
            // Convert to UTF-16LE with null terminator
            byte[] bytesBaseInfo = Encoding.Unicode.GetBytes(baseInfo);
            byte[] bytesWithNull = new byte[bytesBaseInfo.Length + 2];
            Array.Copy(bytesBaseInfo, bytesWithNull, bytesBaseInfo.Length);

            // Compute MD5
            byte[] bytesMD5;
            using (var md5 = MD5.Create())
            {
                bytesMD5 = md5.ComputeHash(bytesWithNull);
            }

            int lengthBase = (baseInfo.Length * 2) + 2;
            int length = ((lengthBase & 4) <= 1 ? 1 : 0) + (ShiftRight(lengthBase, 2)) - 1;

            if (length <= 1)
            {
                return "";
            }

            // First pass
            long[] result1 = FirstPass(bytesWithNull, bytesMD5, length);

            // Second pass
            long[] result2 = SecondPass(bytesWithNull, bytesMD5, length);

            // Combine results
            long hashValue1 = result2[0] ^ result1[0];
            long hashValue2 = result2[1] ^ result1[1];

            byte[] outHashBase = new byte[8];
            Array.Copy(BitConverter.GetBytes((int)hashValue1), 0, outHashBase, 0, 4);
            Array.Copy(BitConverter.GetBytes((int)hashValue2), 0, outHashBase, 4, 4);

            return Convert.ToBase64String(outHashBase);
        }

        private static long[] FirstPass(byte[] bytesBaseInfo, byte[] bytesMD5, int length)
        {
            long cache = 0;
            long outhash1 = 0;
            long outhash2 = 0;
            int pdata = 0;

            long md51 = (GetLong(bytesMD5, 0) | 1) + 0x69FB0000L;
            long md52 = (GetLong(bytesMD5, 4) | 1) + 0x13DB0000L;
            int counter = (ShiftRight(length - 2, 1)) + 1;

            while (counter > 0)
            {
                long r0 = ConvertInt32((GetLong(bytesBaseInfo, pdata) + outhash1));
                long r1_0 = ConvertInt32(GetLong(bytesBaseInfo, pdata + 4));
                pdata += 8;

                long r2_0 = ConvertInt32((r0 * md51) - (0x10FA9605L * ShiftRight(r0, 16)));
                long r2_1 = ConvertInt32((0x79F8A395L * r2_0) + (0x689B6B9FL * ShiftRight(r2_0, 16)));
                long r3 = ConvertInt32((0xEA970001L * r2_1) - (0x3C101569L * ShiftRight(r2_1, 16)));
                long r4_0 = ConvertInt32(r3 + r1_0);
                long r5_0 = ConvertInt32(cache + r3);
                long r6_0 = ConvertInt32((r4_0 * md52) - (0x3CE8EC25L * ShiftRight(r4_0, 16)));
                long r6_1 = ConvertInt32((0x59C3AF2DL * r6_0) - (0x2232E0F1L * ShiftRight(r6_0, 16)));

                outhash1 = ConvertInt32((0x1EC90001L * r6_1) + (0x35BD1EC9L * ShiftRight(r6_1, 16)));
                outhash2 = ConvertInt32(r5_0 + outhash1);
                cache = outhash2;
                counter--;
            }

            return new long[] { outhash1, outhash2 };
        }

        private static long[] SecondPass(byte[] bytesBaseInfo, byte[] bytesMD5, int length)
        {
            long cache = 0;
            long outhash1 = 0;
            long outhash2 = 0;
            int pdata = 0;

            long md51 = GetLong(bytesMD5, 0) | 1;
            long md52 = GetLong(bytesMD5, 4) | 1;
            int counter = (ShiftRight(length - 2, 1)) + 1;

            while (counter > 0)
            {
                long r0 = ConvertInt32(GetLong(bytesBaseInfo, pdata) + outhash1);
                pdata += 8;

                long r1_0 = ConvertInt32(r0 * md51);
                long r1_1 = ConvertInt32((0xB1110000L * r1_0) - (0x30674EEFL * ShiftRight(r1_0, 16)));
                long r2_0 = ConvertInt32((0x5B9F0000L * r1_1) - (0x78F7A461L * ShiftRight(r1_1, 16)));
                long r2_1 = ConvertInt32((0x12CEB96DL * ShiftRight(r2_0, 16)) - (0x46930000L * r2_0));
                long r3 = ConvertInt32((0x1D830000L * r2_1) + (0x257E1D83L * ShiftRight(r2_1, 16)));
                long r4_0 = ConvertInt32(md52 * (r3 + GetLong(bytesBaseInfo, pdata - 4)));
                long r4_1 = ConvertInt32((0x16F50000L * r4_0) - (0x5D8BE90BL * ShiftRight(r4_0, 16)));
                long r5_0 = ConvertInt32((0x96FF0000L * r4_1) - (0x2C7C6901L * ShiftRight(r4_1, 16)));
                long r5_1 = ConvertInt32((0x2B890000L * r5_0) + (0x7C932B89L * ShiftRight(r5_0, 16)));

                outhash1 = ConvertInt32((0x9F690000L * r5_1) - (0x405B6097L * ShiftRight(r5_1, 16)));
                outhash2 = ConvertInt32(outhash1 + cache + r3);
                cache = outhash2;
                counter--;
            }

            return new long[] { outhash1, outhash2 };
        }

        private static int ShiftRight(long value, int count)
        {
            if ((value & 0x80000000) != 0)
            {
                return (int)((value >> count) ^ 0xFFFF0000);
            }
            return (int)(value >> count);
        }

        private static int GetLong(byte[] bytes, int index)
        {
            if (index + 4 > bytes.Length)
            {
                return 0;
            }
            return BitConverter.ToInt32(bytes, index);
        }

        private static int ConvertInt32(long value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            return BitConverter.ToInt32(bytes, 0);
        }
    }
}
