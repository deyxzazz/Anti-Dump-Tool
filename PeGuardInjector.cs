using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
namespace AntiDumpTool;
public static class PeGuardInjector
{
    public static (bool ok, string msg) InjectGuardSection(string dllPath, string metaPath, byte[] key)
    {
        try
        {
            byte[] pe = File.ReadAllBytes(dllPath); uint mSz = File.Exists(metaPath) ? (uint)new FileInfo(metaPath).Length : 0;
            int lfa = BitConverter.ToInt32(pe, 0x3C); if (lfa <= 0 || lfa + 0x108 > pe.Length) return (false, "Invalid PE header.");
            if (BitConverter.ToUInt16(pe, lfa + 4) != 0x8664) return (false, "Only x64 GameAssembly.dll supported.");
            ushort nSec = BitConverter.ToUInt16(pe, lfa + 6), optSz = BitConverter.ToUInt16(pe, lfa + 20);
            int opt = lfa + 24, secTbl = opt + optSz;
            uint secAl = BitConverter.ToUInt32(pe, opt + 32), fileAl = BitConverter.ToUInt32(pe, opt + 36), hdrSz = BitConverter.ToUInt32(pe, opt + 60);
            for (int i = 0; i < nSec; i++)
            {
                int s = secTbl + i * 40;
                if (Encoding.ASCII.GetString(pe, s, 8).TrimEnd('\0') == ".guard")
                {
                    int rp = (int)BitConverter.ToUInt32(pe, s + 20);
                    Array.Copy(key, 0, pe, rp + 0x10, 8); BitConverter.GetBytes(mSz).CopyTo(pe, rp + 0x2C);
                    uint nm = 0xFAB11BAF ^ (BitConverter.ToUInt32(key, 0) ^ 0x5D3E1F00u);
                    for (int k = 0; k < 0x140; k++) if (BitConverter.ToUInt16(pe, rp + k) == 0x3B81) { BitConverter.GetBytes(nm).CopyTo(pe, rp + k + 2); break; }
                    File.WriteAllBytes(dllPath, pe); return (true, $"Updated .guard key ({Convert.ToHexString(key)}).");
                }
            }
            int newHdr = secTbl + nSec * 40; if (newHdr + 40 > hdrSz) return (false, "No space in PE header.");
            uint impRva = BitConverter.ToUInt32(pe, opt + 120), iatMap = FindIat(pe, secTbl, nSec, impRva, "MapViewOfFile"), iatVp = FindIat(pe, secTbl, nSec, impRva, "VirtualProtect");
            if (iatMap == 0 || iatVp == 0) return (false, "IAT imports not found.");
            int last = secTbl + (nSec - 1) * 40;
            uint newVa = Align(BitConverter.ToUInt32(pe, last + 12) + Math.Max(BitConverter.ToUInt32(pe, last + 8), BitConverter.ToUInt32(pe, last + 16)), secAl);
            uint newRaw = Align(BitConverter.ToUInt32(pe, last + 20) + BitConverter.ToUInt32(pe, last + 16), fileAl);
            byte[] buf = new byte[0x150]; Encoding.ASCII.GetBytes("ANTIDUMP_GUARD_1").CopyTo(buf, 0); Array.Copy(key, 0, buf, 0x10, 8); BitConverter.GetBytes(mSz).CopyTo(buf, 0x2C);
            uint hkRva = newVa + 0x30, epRva = newVa + 0xB0, origEp = BitConverter.ToUInt32(pe, opt + 16);
            var hk = new List<byte> { 0x53, 0x56, 0x57, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24, 0x78, 0x48, 0x89, 0x44, 0x24, 0x20, 0xFF, 0x15 };
            hk.AddRange(BitConverter.GetBytes((int)(newVa + 0x18) - (int)(hkRva + (uint)hk.Count + 4)));
            hk.AddRange(new byte[] { 0x48, 0x89, 0xC3, 0x48, 0x85, 0xDB }); int jz = hk.Count; hk.AddRange(new byte[] { 0x74, 0x00 });
            uint magic = 0xFAB11BAF ^ (BitConverter.ToUInt32(key, 0) ^ 0x5D3E1F00u);
            hk.AddRange(new byte[] { 0x81, 0x3B }); hk.AddRange(BitConverter.GetBytes(magic)); int jne = hk.Count; hk.AddRange(new byte[] { 0x75, 0x00 });
            hk.AddRange(new byte[] { 0x8B, 0x3D }); hk.AddRange(BitConverter.GetBytes((int)(newVa + 0x2C) - (int)(hkRva + (uint)hk.Count + 4)));
            hk.AddRange(new byte[] { 0x85, 0xFF }); int jzS = hk.Count; hk.AddRange(new byte[] { 0x74, 0x00 });
            hk.AddRange(new byte[] { 0x48, 0x89, 0xD9, 0x89, 0xFA, 0x41, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D });
            hk.AddRange(BitConverter.GetBytes((int)(newVa + 0x20) - (int)(hkRva + (uint)hk.Count + 4)));
            hk.AddRange(new byte[] { 0xFF, 0x15 }); hk.AddRange(BitConverter.GetBytes((int)iatVp - (int)(hkRva + (uint)hk.Count + 4)));
            hk.AddRange(new byte[] { 0x48, 0x8D, 0x35 }); hk.AddRange(BitConverter.GetBytes((int)(newVa + 0x10) - (int)(hkRva + (uint)hk.Count + 4)));
            hk.AddRange(new byte[] { 0x31, 0xC9 }); int lp = hk.Count;
            hk.AddRange(new byte[] { 0x89, 0xC8, 0x83, 0xE0, 0x07, 0x0F, 0xB6, 0x14, 0x06, 0x89, 0xC8, 0x6B, 0xC0, 0x1F, 0x31, 0xC2, 0x30, 0x14, 0x0B, 0xFF, 0xC1, 0x39, 0xF9 });
            hk.AddRange(new byte[] { 0x7C, (byte)(lp - (hk.Count + 2)) });
            int ex = hk.Count; hk[jz + 1] = (byte)(ex - (jz + 2)); hk[jne + 1] = (byte)(ex - (jne + 2)); hk[jzS + 1] = (byte)(ex - (jzS + 2));
            hk.AddRange(new byte[] { 0x48, 0x89, 0xD8, 0x48, 0x83, 0xC4, 0x38, 0x5F, 0x5E, 0x5B, 0xC3 }); Array.Copy(hk.ToArray(), 0, buf, 0x30, hk.Count);
            var ep = new List<byte> { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x80, 0x78, 0x02, 0x00, 0x74, 0x01, 0xCC, 0x83, 0x3D };
            ep.AddRange(BitConverter.GetBytes((int)(newVa + 0x28) - (int)(epRva + (uint)ep.Count + 5))); ep.Add(0);
            int jnz = ep.Count; ep.AddRange(new byte[] { 0x75, 0x00, 0xC7, 0x05 });
            ep.AddRange(BitConverter.GetBytes((int)(newVa + 0x28) - (int)(epRva + (uint)ep.Count + 8))); ep.AddRange(BitConverter.GetBytes(1));
            ep.AddRange(new byte[] { 0x51, 0x52, 0x41, 0x50, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05 }); ep.AddRange(BitConverter.GetBytes((int)iatMap - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0x48, 0x89, 0x05 }); ep.AddRange(BitConverter.GetBytes((int)(newVa + 0x18) - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0x48, 0x8D, 0x0D }); ep.AddRange(BitConverter.GetBytes((int)iatMap - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0xBA, 0x08, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D }); ep.AddRange(BitConverter.GetBytes((int)(newVa + 0x20) - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0xFF, 0x15 }); ep.AddRange(BitConverter.GetBytes((int)iatVp - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0x48, 0x8D, 0x05 }); ep.AddRange(BitConverter.GetBytes((int)hkRva - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0x48, 0x89, 0x05 }); ep.AddRange(BitConverter.GetBytes((int)iatMap - (int)(epRva + (uint)ep.Count + 4)));
            ep.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28, 0x41, 0x58, 0x5A, 0x59 }); ep[jnz + 1] = (byte)(ep.Count - (jnz + 2));
            ep.Add(0xE9); ep.AddRange(BitConverter.GetBytes((int)origEp - (int)(epRva + (uint)ep.Count + 4))); Array.Copy(ep.ToArray(), 0, buf, 0xB0, ep.Count);
            uint rawSz = Align((uint)buf.Length, fileAl), virtSz = Align((uint)buf.Length, secAl);
            byte[] outPe = new byte[newRaw + rawSz]; Array.Copy(pe, outPe, pe.Length);
            Encoding.ASCII.GetBytes(".guard\0\0").CopyTo(outPe, newHdr); BitConverter.GetBytes((uint)buf.Length).CopyTo(outPe, newHdr + 8); BitConverter.GetBytes(newVa).CopyTo(outPe, newHdr + 12);
            BitConverter.GetBytes(rawSz).CopyTo(outPe, newHdr + 16); BitConverter.GetBytes(newRaw).CopyTo(outPe, newHdr + 20); BitConverter.GetBytes(0xE0000020u).CopyTo(outPe, newHdr + 36);
            BitConverter.GetBytes((ushort)(nSec + 1)).CopyTo(outPe, lfa + 6); BitConverter.GetBytes(epRva).CopyTo(outPe, opt + 16); BitConverter.GetBytes(newVa + virtSz).CopyTo(outPe, opt + 56);
            Array.Copy(buf, 0, outPe, newRaw, buf.Length); File.WriteAllBytes(dllPath, outPe);
            return (true, $"Injected .guard (Entry=0x{epRva:X}, Key={Convert.ToHexString(key)}).");
        }
        catch (Exception ex) { return (false, $"PE Error: {ex.Message}"); }
    }
    public static byte[]? ExtractEmbeddedKey(string dllPath)
    {
        try
        {
            if (!File.Exists(dllPath)) return null; byte[] pe = File.ReadAllBytes(dllPath); int lfa = BitConverter.ToInt32(pe, 0x3C); if (lfa <= 0 || lfa + 0x108 > pe.Length) return null;
            ushort nSec = BitConverter.ToUInt16(pe, lfa + 6), optSz = BitConverter.ToUInt16(pe, lfa + 20); int secTbl = lfa + 24 + optSz;
            for (int i = 0; i < nSec; i++) { int s = secTbl + i * 40; if (Encoding.ASCII.GetString(pe, s, 8).TrimEnd('\0') == ".guard") { int rp = (int)BitConverter.ToUInt32(pe, s + 20); if (rp + 0x18 <= pe.Length && Encoding.ASCII.GetString(pe, rp, 16) == "ANTIDUMP_GUARD_1") { byte[] k = new byte[4 * 2]; Array.Copy(pe, rp + 0x10, k, 0, 8); return k; } } }
        }
        catch { }
        return null;
    }
    private static uint FindIat(byte[] pe, int secTbl, int nSec, uint impRva, string fn)
    {
        int off = RvaOff(pe, secTbl, nSec, impRva); if (off < 0) return 0;
        for (int i = 0; ; i++) { int d = off + i * 20; if (d + 20 > pe.Length) break; uint oft = BitConverter.ToUInt32(pe, d), nr = BitConverter.ToUInt32(pe, d + 12), ft = BitConverter.ToUInt32(pe, d + 16); if (nr == 0 && ft == 0) break; int lo = RvaOff(pe, secTbl, nSec, oft != 0 ? oft : ft); if (lo < 0) continue; for (int f = 0; ; f++) { int eo = lo + f * 8; if (eo + 8 > pe.Length) break; ulong th = BitConverter.ToUInt64(pe, eo); if (th == 0) break; if ((th & 0x8000000000000000UL) != 0) continue; int ho = RvaOff(pe, secTbl, nSec, (uint)(th & 0x7FFFFFFF)); if (ho < 0 || ho + 2 + fn.Length >= pe.Length) continue; int e = ho + 2; while (e < pe.Length && pe[e] != 0) e++; if (Encoding.ASCII.GetString(pe, ho + 2, e - (ho + 2)) == fn) return ft + (uint)(f * 8); } }
        return 0;
    }
    private static int RvaOff(byte[] pe, int secTbl, int nSec, uint rva)
    {
        for (int i = 0; i < nSec; i++) { int s = secTbl + i * 40; uint va = BitConverter.ToUInt32(pe, s + 12), sz = Math.Max(BitConverter.ToUInt32(pe, s + 8), BitConverter.ToUInt32(pe, s + 16)); if (rva >= va && rva < va + sz) return (int)(BitConverter.ToUInt32(pe, s + 20) + (rva - va)); }
        return -1;
    }
    private static uint Align(uint v, uint a) => (v + a - 1) & ~(a - 1);
}
