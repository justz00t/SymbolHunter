using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    public sealed class Hit
    {
        public List<string> Chain = new List<string>();   // top-level file, then names inside containers
        public string FileType = "";
        public string Packer;
        public long FileSize;
        public bool Deleted;
        public Finding Finding;
        public string InnerPath { get { return string.Join(" > ", Chain.Skip(1)); } }
        public string FullPath { get { return string.Join(" > ", Chain); } }
        public string FileName { get { return Chain.Count > 0 ? PathUtil.FileName(Chain[Chain.Count - 1]) : ""; } }
    }

    public sealed class Problem
    {
        public string Where = "";
        public string Kind = "";       // unsupported, corrupt, encrypted, missing-volume, crc, error, timeout
        public string Message = "";
        public override string ToString() { return Where + ": " + Message; }
    }

    public enum ItemStatus { Pending, Scanning, Done, PartOfSet, Error, TimedOut, Skipped }

    /// <summary>Result for one file directly under the scanned folder (usually an archive or disk image).</summary>
    public sealed class ItemResult
    {
        public string FullPath = "", RelPath = "";
        public long Size;
        public string Format = "";
        public ItemStatus Status = ItemStatus.Pending;
        public string Note = "";
        public readonly List<Hit> Hits = new List<Hit>();
        public readonly List<Problem> Problems = new List<Problem>();
        public readonly List<string> Volumes = new List<string>();   // extra volumes consumed (multi-volume sets)
        public int FilesExamined, ContainersOpened, ImagesOpened;
        public TimeSpan Elapsed;

        public Strength Best { get { lock (Hits) return Hits.Count == 0 ? Strength.None : Hits.Max(h => h.Finding.Strength); } }

        public IEnumerable<Hit> HitsAtLeast(Strength s) { lock (Hits) return Hits.Where(h => h.Finding.Strength >= s).ToList(); }

        /// <summary>Distinct finding labels, strongest first.</summary>
        public List<string> KindLabels(Strength min)
        {
            lock (Hits)
                return Hits.Where(h => h.Finding.Strength >= min)
                           .GroupBy(h => h.Finding.Label)
                           .OrderByDescending(g => g.Max(h => h.Finding.Strength)).ThenBy(g => g.Key)
                           .Select(g => g.Key).ToList();
        }

        public Hit BestHit(Strength min)
        {
            lock (Hits) return Hits.Where(h => h.Finding.Strength >= min).OrderByDescending(h => h.Finding.Strength).ThenBy(h => h.Chain.Count).FirstOrDefault();
        }
    }

    public sealed class ScanStats
    {
        public int TopItems, TopDone, Files, Containers, Hits, Problems;
        public long BytesTop, BytesDone;
        public string Current = "";
        public int Folders;                 // folders listed so far
        public volatile bool Discovering;   // still walking the folder tree
        public string DiscoverDir = "";
    }
}
