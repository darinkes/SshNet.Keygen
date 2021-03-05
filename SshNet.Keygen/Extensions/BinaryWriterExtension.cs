﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SshNet.Keygen.Extensions
{
    internal static class BinaryWriterExtension
    {

#if NET40
        public static void EncodeEcKey(this BinaryWriter writer, ECDsaCng ecdsa)
        {
            byte[] qx;
            byte[] qy;

            var publicBytes = ecdsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            using (var br = new BinaryReader(new MemoryStream(publicBytes)))
            {
                    _ = br.ReadInt32();
                    var coordSize = br.ReadInt32();
                    qx = br.ReadBytes(coordSize);
                    qy = br.ReadBytes(coordSize);
            }

            EncodeString(writer, ecdsa.EcCurveNameSshCompat());
            EncodeString(writer, EcdsaExtension.UncompressedCoords(qx, qy, ecdsa.EcCoordsLength()));
        }
#else
        public static void EncodeEcKey(this BinaryWriter writer, ECDsa ecdsa, bool includePrivate)
        {
            var ecdsaParameters = ecdsa.ExportParameters(includePrivate);
            EncodeString(writer, ecdsa.EcCurveNameSshCompat());
            EncodeString(writer, ecdsaParameters.UncompressedCoords(ecdsa.EcCoordsLength()));
            if (includePrivate)
                EncodeBignum2(writer, ecdsaParameters.D.ToBigInteger2().ToByteArray().Reverse());
        }
#endif

        public static void EncodeNullTerminatedString(this BinaryWriter writer, string str)
        {
            writer.Write(Encoding.ASCII.GetBytes(str));
            writer.Write('\0');
        }

        public static void EncodeString(this BinaryWriter writer, string str)
        {
            EncodeString(writer, Encoding.ASCII.GetBytes(str));
        }

        public static void EncodeString(this BinaryWriter writer, MemoryStream str)
        {
            EncodeString(writer, str.GetBuffer(), 0, (int)str.Length);
        }

        public static void EncodeString(this BinaryWriter writer, byte[] str)
        {
            EncodeUInt(writer, (uint)str.Length);
            writer.Write(str);
        }

        public static void EncodeString(this BinaryWriter writer, byte[] str, int offset, int length)
        {
            EncodeUInt(writer, (uint)length);
            writer.Write(str, offset, length);
        }

        public static void EncodeBignum2(this BinaryWriter writer, byte[] data)
        {
            EncodeUInt(writer, (uint)data.Length);
            writer.Write(data);
        }

        public static void EncodeUInt(this BinaryWriter writer, uint i)
        {
            var data = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            writer.Write(data);
        }

        public static void EncodeInt(this BinaryWriter writer, int i)
        {
            var data = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            writer.Write(data);
        }
    }
}