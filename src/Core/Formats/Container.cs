using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>One member of an archive or disk image.</summary>
    public sealed class Entry
    {
        public string Name = "";            // path inside the container, '/' separated
        public long Size = -1;              // uncompressed size, -1 if unknown
        public long CompressedSize = -1;
        public bool IsDirectory;
        public bool IsDeleted;              // recovered deleted file (FAT)
        public bool IsEncrypted;
        public string Method = "";
        public DateTime? Time;
        public Func<DataSource> Open;       // may throw FormatException2 / UnsupportedException
        public string Note;                 // e.g. "partial: continued in next volume"
        public override string ToString() { return Name; }
    }

    /// <summary>An archive, disk image or file system that contains entries.</summary>
    public abstract class Container : IDisposable
    {
        public abstract string FormatName { get; }
        public string Description = "";
        public readonly List<string> Warnings = new List<string>();
        /// <summary>Entries in order. For solid/sequential formats Open() must be called before advancing.</summary>
        public abstract IEnumerable<Entry> Entries();
        public virtual void Dispose() { }
        /// <summary>Names of sibling volume files consumed by this container (multi-volume sets).</summary>
        public readonly List<string> ConsumedVolumes = new List<string>();
    }

    /// <summary>Provides sibling files (other volumes of a multi-volume set) by name.</summary>
    public interface ISiblingProvider
    {
        /// <summary>Returns the sibling data or null. Name matching is case-insensitive.</summary>
        DataSource GetSibling(string name);
        /// <summary>All sibling names (same folder or same parent container).</summary>
        IEnumerable<string> SiblingNames { get; }
    }

    public enum FormatKind { Unknown, Archive, Image, Executable }

    /// <summary>Archives found inside other data; each one is exposed as an entry.</summary>
    public sealed class CarvedContainer : Container
    {
        readonly DataSource src; readonly List<KeyValuePair<long, long>> spans; readonly string ext, kind;
        public CarvedContainer(DataSource src, List<KeyValuePair<long, long>> spans, string kind, string ext)
        { this.src = src; this.spans = spans; this.ext = ext; this.kind = kind; Description = spans.Count + " embedded " + kind; }
        public override string FormatName { get { return "embedded " + kind; } }
        public override IEnumerable<Entry> Entries()
        {
            foreach (var sp in spans)
            {
                long off = sp.Key, len = Math.Min(sp.Value, src.Length - sp.Key);
                yield return new Entry { Name = "@" + off.ToString("X8") + ext, Size = len, Method = "embedded", Open = () => src.Slice(off, len) };
            }
        }
    }

    public sealed class FormatInfo
    {
        public FormatKind Kind;
        public string Id = "";
        public string Description = "";
        public bool Supported = true;       // false: recognized but cannot be opened
        public string UnsupportedReason;
        public long PayloadOffset;          // for self-extracting archives: where the archive starts
        public bool ScanSelf;               // also scan the outer file itself for debug info (data around embedded archives)
        public Func<DataSource, string, ISiblingProvider, Container> Open;
        public override string ToString() { return Id + " (" + Description + ")"; }
    }

    public static class PathUtil
    {
        public static string Clean(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";
            var s = name.Replace('\\', '/');
            while (s.StartsWith("/")) s = s.Substring(1);
            if (s.Length >= 2 && s[1] == ':') s = s.Substring(2).TrimStart('/');
            return s;
        }
        public static string FileName(string path)
        {
            var s = path.Replace('\\', '/');
            int i = s.LastIndexOf('/');
            return i >= 0 ? s.Substring(i + 1) : s;
        }
        public static string Ext(string path)
        {
            var f = FileName(path);
            int i = f.LastIndexOf('.');
            return i >= 0 ? f.Substring(i).ToLowerInvariant() : "";
        }
        public static string Dir(string path)
        {
            var s = path.Replace('\\', '/');
            int i = s.LastIndexOf('/');
            return i >= 0 ? s.Substring(0, i) : "";
        }
    }
}
