// SPDX-License-Identifier: MIT
// cpp-locks-watch — Linux file-lock monitor (/proc/locks)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o locks-watch
// Usage: ./locks-watch [--type FLOCK|POSIX] [--mode READ|WRITE] [--mandatory]
//                      [--pid PID] [--top N] [--watch N] [--byte-range]
//                      [--json] [--demo] [--file PATH] [--no-color] [--selftest]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
#include <dirent.h>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static std::string upto(std::string s, std::size_t n) {
  return s.size() <= n ? s : s.substr(0, n);
}

// ─────────────────────────────────────────────────────────────────────────────
// File-lock model (one entry in /proc/locks)
// ─────────────────────────────────────────────────────────────────────────────
struct FileLock {
  long long id = 0;          // lock id (first field)
  std::string type;          // FLOCK | POSIX | OFDLCK
  std::string mode;          // ADVISORY | MANDATORY
  std::string access = "??"; // READ | WRITE
  pid_t pid = -1;            // owner
  std::string dev;           // 08:01
  long long inode = 0;
  long long start = 0;
  long long end = -1;        // -1 = EOF (whole file); else explicit byte offset

  bool is_eof() const { return end < 0; }
};

struct Snapshot {
  long long ts = 0;
  std::vector<FileLock> locks;
  std::map<pid_t, std::string> procs;

  std::size_t count_type(const std::string& t) const {
    return static_cast<std::size_t>(std::count_if(
      locks.begin(), locks.end(), [&](const FileLock& l) { return l.type == t; }));
  }
  std::size_t count_access(const std::string& a) const {
    return static_cast<std::size_t>(std::count_if(
      locks.begin(), locks.end(), [&](const FileLock& l) { return l.access == a; }));
  }
  std::size_t count_mandatory() const {
    return static_cast<std::size_t>(std::count_if(
      locks.begin(), locks.end(), [&](const FileLock& l) { return l.mode == "MANDATORY"; }));
  }
  std::size_t count_range() const {
    return static_cast<std::size_t>(std::count_if(
      locks.begin(), locks.end(), [&](const FileLock& l) { return !l.is_eof(); }));
  }
  std::set<pid_t> pids() const {
    std::set<pid_t> s;
    for (const auto& l : locks) s.insert(l.pid);
    return s;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static long long now_secs() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::optional<long long> parse_ll(std::string_view s, int base = 10) {
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc()) return std::nullopt;
  if (ptr != s.data() + s.size()) return std::nullopt;
  return v;
}

static std::optional<long long> parse_hex(std::string_view s) {
  // hex inode column: "7424305" or "1ce" (base detection = skip leading zeros)
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  bool has_alpha = false;
  for (char c : s) if (std::isxdigit(static_cast<unsigned char>(c)) && !std::isdigit(static_cast<unsigned char>(c))) has_alpha = true;
  if (has_alpha) return parse_ll(s, 16);
  return parse_ll(s, 10);
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return std::string(s);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// /proc/locks line format:
//   id: TYPE  MODE  ACCESS PID DEV:INODE START END
//   1: FLOCK  ADVISORY  WRITE 1129 08:01:7424305 0 EOF
//   2: POSIX  ADVISORY  READ  1129 08:01:7425601 128 128
//  (EOF = end of file, i.e. unlimited; "0 EOF" is the whole file)
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_locks_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    auto comma = line.find(':');
    if (comma == std::string::npos) continue;
    auto idv = parse_ll(std::string_view(line).substr(0, comma));
    if (!idv) continue;
    auto toks = split_ws(std::string_view(line).substr(comma + 1));
    if (toks.size() < 7) continue;
    FileLock l;
    l.id     = *idv;
    l.type   = toks[0];
    l.mode   = toks[1];
    l.access = toks[2];
    if (auto p = parse_ll(toks[3])) l.pid = static_cast<pid_t>(*p);
    std::string devino = toks[4];           // "MAJ:MIN:INODE"
    auto last_colon = devino.rfind(':');
    if (last_colon != std::string::npos) {
      l.dev = devino.substr(0, last_colon); // "MAJ:MIN"
      if (auto ino = parse_hex(std::string_view(devino).substr(last_colon + 1))) l.inode = *ino;
    }
    if (auto st = parse_ll(toks[5])) l.start = *st;
    if (toks.size() > 6)
      l.end = (toks[6] == "EOF") ? -1 : parse_ll(toks[6]).value_or(-1);
    snap.locks.push_back(std::move(l));
  }
  std::sort(snap.locks.begin(), snap.locks.end(),
            [](const FileLock& a, const FileLock& b) { return a.id < b.id; });
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// pid -> comm resolution (tolerant to permission errors)
// ─────────────────────────────────────────────────────────────────────────────
static std::string read_comm(pid_t pid) {
  std::string path = "/proc/" + std::to_string(pid) + "/comm";
  std::ifstream f(path);
  if (!f) return "";
  std::string s;
  std::getline(f, s);
  return trim(s);
}

static void resolve_procs(Snapshot& snap) {
  for (pid_t p : snap.pids()) {
    std::string comm = read_comm(p);
    if (!comm.empty()) snap.procs[p] = std::move(comm);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo: synthetic mixed load (database + web + browser + cron flock)
// ─────────────────────────────────────────────────────────────────────────────
static bool demo_load_file(const std::string& path, Snapshot& snap) {
  std::string demo =
    " 1: FLOCK  ADVISORY  WRITE 4132 08:01:9310177 0 EOF\n"
    " 2: POSIX  ADVISORY  READ  4132 08:01:9310177 128 128\n"
    " 3: POSIX  ADVISORY  READ  4132 08:01:9310177 1073741826 1073742335\n"
    " 4: POSIX  ADVISORY  WRITE 5133 00:33:1022411 0 EOF\n"
    " 5: POSIX  ADVISORY  READ  5133 00:33:1022411 128 128\n"
    " 6: POSIX  ADVISORY  READ  5133 00:33:1022411 1073741826 1073742335\n"
    " 7: POSIX  ADVISORY  WRITE 5214 08:01:9310177 0 EOF\n"
    " 8: POSIX  ADVISORY  READ  5214 08:01:9310177 128 128\n"
    " 9: POSIX  ADVISORY  READ  5214 08:01:9310177 1073741826 1073742335\n"
    "10: POSIX  ADVISORY  READ  5321 08:01:9310177 64 64\n"
    "11: FLOCK  ADVISORY  WRITE 2115 00:33:9822214 0 EOF\n"
    "12: POSIX  ADVISORY  WRITE 1082 00:33:1133888 0 EOF\n"
    "13: POSIX  ADVISORY  READ  2213 00:33:1133888 0 EOF\n"
    "14: FLOCK  ADVISORY  WRITE 2115 00:33:9933115 0 EOF\n"
    "15: POSIX  ADVISORY  WRITE 3315 08:01:1205517 0 EOF\n"
    "16: POSIX  ADVISORY  WRITE 3316 08:01:1205517 0 EOF\n"
    "17: POSIX  ADVISORY  WRITE 3317 08:01:1205517 0 EOF\n"
    "18: POSIX  ADVISORY  WRITE 3318 08:01:1205517 0 EOF\n"
    "19: POSIX  ADVISORY  WRITE 3319 08:01:1205517 0 EOF\n"
    "20: POSIX  ADVISORY  WRITE 6120 08:01:1488371 0 EOF\n"
    "21: POSIX  ADVISORY  WRITE 6222 08:01:1488371 0 EOF\n"
    "22: POSIX  ADVISORY  WRITE 6331 08:01:1488371 0 EOF\n"
    "23: POSIX  ADVISORY  WRITE 6440 08:01:1488371 0 EOF\n"
    "24: POSIX  ADVISORY  READ  6120 08:01:1488371 96 255\n"
    "25: POSIX  ADVISORY  READ  7011 08:01:1488371 96 255\n"
    "26: FLOCK  ADVISORY  WRITE 7011 08:01:7424305 0 EOF\n"
    "27: POSIX  ADVISORY  WRITE 3133 08:01:7424305 0 EOF\n"
    "28: FLOCK  ADVISORY  WRITE 9021 08:01:7425601 0 EOF\n"
    "29: POSIX  ADVISORY  READ  7115 08:01:1612206 0 EOF\n"
    "30: POSIX  ADVISORY  WRITE 7115 08:01:1612206 1048576 1048807\n"
    "31: FLOCK  ADVISORY  WRITE 9022 08:01:7425601 0 EOF\n"
    "32: POSIX  ADVISORY  WRITE 4123 08:01:9310177 0 EOF\n";
  { std::ofstream f(path); f << demo; }   // flush + close BEFORE parsing below
  snap.procs = {
    {1082, "node"},       {2115, "crond"},      {2213, "sshd"},
    {3133, "postgres"},   {3315, "node"},       {3316, "node"},
    {3317, "node"},       {3318, "node"},       {3319, "node"},
    {4123, "postgres"},   {4132, "postgres"},   {5133, "nginx"},
    {5214, "nginx"},      {5321, "nginx"},      {6120, "java"},
    {6222, "java"},       {6331, "java"},       {6440, "java"},
    {7011, "chrome"},     {7115, "firefox"},    {9021, "python3"},
    {9022, "python3"},
  };
  return parse_locks_file(path, snap);
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON rendering (always valid — quoted keys, escaped backticks)
// ─────────────────────────────────────────────────────────────────────────────
static std::string json_esc(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
    else if (c == '\n') { out += "\\n"; }
    else { out.push_back(c); }
  }
  return out;
}

static void render_json(std::ostream& os, const Snapshot& s, bool demo) {
  os << "{\n";
  os << "  \"summary\": {\n";
  os << "    \"ts\": " << s.ts << ",\n";
  os << "    \"total\": " << s.locks.size() << ",\n";
  os << "    \"flock\": " << s.count_type("FLOCK") << ",\n";
  os << "    \"posix\": " << s.count_type("POSIX") << ",\n";
  os << "    \"read\": " << s.count_access("READ") << ",\n";
  os << "    \"write\": " << s.count_access("WRITE") << ",\n";
  os << "    \"mandatory\": " << s.count_mandatory() << ",\n";
  os << "    \"byte_range\": " << s.count_range() << ",\n";
  os << "    \"pids\": " << s.pids().size() << ",\n";
  os << "    \"demo\": " << (demo ? "true" : "false") << "\n";
  os << "  },\n";
  os << "  \"locks\": [\n";
  bool first = true;
  for (const auto& l : s.locks) {
    if (!first) os << ",\n";
    first = false;
    os << "    {\n";
    os << "      \"id\": " << l.id << ",\n";
    os << "      \"type\": \"" << l.type << "\",\n";
    os << "      \"mode\": \"" << l.mode << "\",\n";
    os << "      \"access\": \"" << l.access << "\",\n";
    os << "      \"pid\": " << l.pid << ",\n";
    os << "      \"comm\": \"" << json_esc(s.procs.contains(l.pid) ? s.procs.at(l.pid) : "") << "\",\n";
    os << "      \"dev\": \"" << l.dev << "\",\n";
    os << "      \"inode\": " << l.inode << ",\n";
    os << "      \"start\": " << l.start << ",\n";
    os << "      \"end\": " << l.end << ",\n";
    os << "      \"eof\": " << (l.is_eof() ? "true" : "false") << "\n";
    os << "    }";
  }
  os << "\n  ]\n";
  os << "}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Human rendering
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  std::string type;
  std::string access;
  bool mandatory_only = false;
  pid_t pid = -1;
  int top = 0;
  int watch = 0;
  int sort = 0; // 0=id 1=pid 2=inode
  bool byte_range = false;
  bool demo = false;
  bool json = false;
  bool color = true;
  bool resolve = true;
  std::string file;
};

static bool passes(const FileLock& l, const Filters& f) {
  if (!f.type.empty() && l.type != f.type) return false;
  if (!f.access.empty() && l.access != f.access) return false;
  if (f.mandatory_only && l.mode != "MANDATORY") return false;
  if (f.pid >= 0 && l.pid != f.pid) return false;
  if (f.byte_range && l.is_eof()) return false;
  return true;
}

static std::string range_str(const FileLock& l) {
  if (l.is_eof()) return "0-EOF";
  if (l.end == l.start) return std::to_string(l.start);
  return std::to_string(l.start) + "-" + std::to_string(l.end);
}

static void render_snapshot(const Snapshot& s, const Filters& f, bool watch_mode) {
  std::string src = f.demo ? "demo (synthetic)" : (f.file.empty() ? "/proc/locks" : f.file);
  std::cout << C_BOLD << C_CYAN << "  Linux File-Lock Monitor  /proc/locks" << C_RESET << "\n";
  std::cout << C_DIM << "  Source: " << src << "  ·  Snapshot: " << s.ts << C_RESET << "\n";
  std::cout << "  " << std::string(76, '-') << "\n\n";

  long long r = 0;
  for (const auto& l : s.locks) if (passes(l, f)) ++r;
  std::cout << "  " << C_BOLD << r << C_RESET << " locks   "
            << C_CYAN << s.count_type("FLOCK") << " FLOCK   "
            << C_GREEN << s.count_type("POSIX") << " POSIX   "
            << C_YELLOW << s.count_access("READ") << " read   "
            << C_RED << s.count_access("WRITE") << " write   "
            << C_MAGENTA << s.count_mandatory() << " mandatory   "
            << C_DIM << s.count_range() << " byte-range" << C_RESET << "\n";
  std::cout << "  " << C_DIM << "pids: " << s.pids().size() << C_RESET << "\n\n";

  std::cout << C_BOLD
            << "  ID    TYPE    MODE      ACCESS  PID   DEV       INODE       RANGE\n"
            << "  " << std::string(76, '-')
            << C_RESET << "\n";

  std::vector<const FileLock*> rows;
  for (const auto& l : s.locks) if (passes(l, f)) rows.push_back(&l);
  if (f.sort == 1) std::sort(rows.begin(), rows.end(), [](const FileLock* a, const FileLock* b) { return a->pid < b->pid; });
  else if (f.sort == 2) std::sort(rows.begin(), rows.end(), [](const FileLock* a, const FileLock* b) { return a->inode < b->inode; });
  if (f.top > 0 && static_cast<int>(rows.size()) > f.top) rows.resize(static_cast<std::size_t>(f.top));

  for (const auto* lp : rows) {
    const FileLock& l = *lp;
    std::string type = l.type;
    std::string acc = l.access;
    std::string mod = l.mode;
    if (f.color) {
      type = (l.type == "FLOCK") ? (C_MAGENTA + l.type + C_RESET)
             : (l.type == "POSIX") ? (C_GREEN + l.type + C_RESET)
             : (C_BLUE + l.type + C_RESET);
      acc = (l.access == "READ") ? (C_YELLOW + l.access + C_RESET)
            : (l.access == "WRITE") ? (C_RED + l.access + C_RESET)
            : (C_DIM + l.access + C_RESET);
      mod = (l.mode == "MANDATORY") ? (C_RED + l.mode + C_RESET) : (C_DIM + l.mode + C_RESET);
    }
    std::string comm = s.procs.contains(l.pid) && f.resolve ? s.procs.at(l.pid) : "";
    std::string pidcol = comm.empty() ? std::to_string(l.pid) : std::to_string(l.pid) + " " + C_DIM + upto(comm, 10) + C_RESET;
    if (!f.color) pidcol = comm.empty() ? std::to_string(l.pid) : std::to_string(l.pid) + " " + upto(comm, 10);
    std::cout << "  " << C_DIM << l.id << C_RESET
              << "    " << type
              << "  " << mod
              << "   " << acc
              << "   " << pidcol
              << "  " << l.dev
              << "  " << l.inode
              << "  " << range_str(l) << "\n";
  }
  std::cout << "\n" << C_DIM << "  hint: --type FLOCK|POSIX · --access READ|WRITE · --byte-range · --watch N · --json" << C_RESET << "\n\n";
  if (!watch_mode && !f.json) {
    std::cout << "  $ ./locks-watch --type FLOCK      # flock(2) locks only\n";
    std::cout << "  $ ./locks-watch --watch 2         # refresh with deltas\n";
    std::cout << "  $ ./locks-watch --json | python3 -m json.tool\n";
    std::cout << C_GREEN << "  $ ./locks-watch --demo          # synthetic busy host\n" << C_RESET << "\n";
  }
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  auto key = [](const FileLock& l) {
    return std::to_string(l.id) + "|" + l.type + "|" + l.access + "|" +
           std::to_string(l.pid) + "|" + std::to_string(l.inode);
  };
  std::set<std::string> prev_ids, cur_ids;
  for (const auto& l : prev.locks) if (passes(l, f)) prev_ids.insert(key(l));
  for (const auto& l : cur.locks)  if (passes(l, f)) cur_ids.insert(key(l));
  std::vector<std::string> added, removed;
  for (const auto& k : cur_ids)  if (!prev_ids.contains(k)) added.push_back(k);
  for (const auto& k : prev_ids) if (!cur_ids.contains(k)) removed.push_back(k);
  std::cout << C_DIM << "  delta vs previous snapshot: "
            << C_GREEN << "+" << added.size() << " new   "
            << C_RED << "-" << removed.size() << " gone   "
            << C_CYAN << "total " << cur.locks.size() << C_RESET
            << (added.empty() && removed.empty() ? "  (stable)" : "") << "\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest (ad-hoc truth for this binary)
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
  if (ok) { ++g_pass; } else { ++g_fail; std::cout << "    FAIL  " << what << "\n"; }
}

static bool dump_to_file(const std::string& path, const std::string& content) {
  std::ofstream f(path);
  if (!f) return false;
  f << content;
  return true;
}

static int selftest() {
  std::cout << "== parse helpers ==\n";
  check(parse_ll("  42") == 42LL, "parse_ll trims spaces");
  check(!parse_ll("12a").has_value(), "parse_ll trailing garbage -> nullopt");
  check(parse_hex("7424305") == 7424305LL, "parse_hex numeric inode decimal");
  check(parse_hex("1ce") == 0x1ceLL, "parse_hex alpha inode -> hex");

  std::cout << "== /proc/locks parser ==\n";
  {
    Snapshot s;
    check(parse_locks_file("/proc/locks", s), "opens real /proc/locks");
    check(s.ts == 0, "ts not set by parser (set by caller)");
    if (!s.locks.empty()) {
      const auto& l0 = s.locks.front();
      check(l0.type == "FLOCK" || l0.type == "POSIX" || l0.type == "OFDLCK", "real type valid: " + l0.type);
      check(l0.mode == "ADVISORY" || l0.mode == "MANDATORY", "real mode valid");
      check(l0.access == "READ" || l0.access == "WRITE", "real access valid");
    }
    std::string dump =
      " 1: FLOCK  ADVISORY  WRITE 1129 08:01:7424305 0 EOF\n"
      " 2: POSIX  ADVISORY  READ  1129 08:01:7425601 128 128\n"
      " 3: POSIX  ADVISORY  READ  705 08:01:11534517 1073741826 1073742335\n"
      " 4: FLOCK  MANDATORY  WRITE 700 08:01:7423442 512 1023\n"
      " 5: OFDLCK ADVISORY  WRITE 900 00:33:1022411 0 EOF\n"
      "# comment line tolerated\n"
      " 6: POSIX  ADVISORY  READ  705 08:01:11534517 0 0  # trailing annotation\n";
    Snapshot s2;
    std::string path = "/tmp/locks-selftest.table";
    if (dump_to_file(path, dump)) check(parse_locks_file(path, s2), "parses synthetic dump");
    else check(false, "cannot write dump");
    check(s2.locks.size() == 6, "6 locks parsed (comments skipped)");
    if (s2.locks.size() == 6) {
      check(s2.locks[0].type == "FLOCK" && s2.locks[0].access == "WRITE" && s2.locks[0].pid == 1129,
            "locks[0] FLOCK WRITE pid 1129");
      check(s2.locks[0].dev == "08:01" && s2.locks[0].inode == 7424305LL, "locks[0] dev+inode");
      check(s2.locks[0].start == 0 && s2.locks[0].is_eof(), "locks[0] 0-EOF (whole file)");
      check(s2.locks[1].start == 128 && s2.locks[1].end == 128, "locks[1] single-byte 128");
      check(s2.locks[2].start == 1073741826LL && s2.locks[2].end == 1073742335LL, "locks[2] range");
      check(s2.locks[3].mode == "MANDATORY", "locks[3] MANDATORY parsed");
      check(s2.locks[4].type == "OFDLCK", "locks[4] OFDLCK");
      check(s2.locks[5].start == 0 && s2.locks[5].end == 0 && !s2.locks[5].is_eof(),
            "locks[5] explicit 0 0 = not EOF");
      check(std::is_sorted(s2.locks.begin(), s2.locks.end(),
                           [](const FileLock& a, const FileLock& b) { return a.id < b.id; }),
            "locks sorted by id");
    }
    std::remove(path.c_str());
  }

  std::cout << "== filters ==\n";
  {
    Snapshot s;
    demo_load_file("/tmp/locks-demo.table", s);
    Filters f;
    f.type = "FLOCK";
    int n = 0;
    for (const auto& l : s.locks) if (passes(l, f)) ++n;
    check(n == 6, "demo FLOCK count == 6");
    f = Filters{};
    f.access = "READ";
    n = 0;
    for (const auto& l : s.locks) if (passes(l, f)) ++n;
    check(n == 11, "demo READ count == 11");
    f = Filters{};
    f.mandatory_only = true;
    n = 0;
    for (const auto& l : s.locks) if (passes(l, f)) ++n;
    check(n == 0, "demo has no mandatory locks");
    f = Filters{};
    f.pid = 3315;
    n = 0;
    for (const auto& l : s.locks) if (passes(l, f)) ++n;
    check(n == 1, "demo pid 3315 -> 1 lock");
    f = Filters{};
    f.byte_range = true;
    n = 0;
    for (const auto& l : s.locks) if (passes(l, f)) ++n;
    check(n == 10, "demo byte-range count == 10");
    std::remove("/tmp/locks-demo.table");
  }

  std::cout << "== demo snapshot ==\n";
  {
    Snapshot s;
    s.locks.clear(); s.procs.clear();
    demo_load_file("/tmp/locks-demo2.table", s);
    check(s.locks.size() == 32, "demo has 32 locks");
    check(s.count_type("FLOCK") == 6, "demo 6 FLOCK");
    check(s.count_type("POSIX") == 26, "demo 26 POSIX");
    check(s.count_type("OFDLCK") == 0, "demo 0 OFDLCK");
    check(s.count_access("READ") == 11 && s.count_access("WRITE") == 21, "demo 11 read / 21 write");
    check(s.count_range() == 10, "demo 10 non-EOF ranges");
    check(s.pids().size() == 22, "demo 22 distinct pids");
    check(s.procs.contains(3133) && s.procs.at(3133) == "postgres", "demo comm postgres");
    std::remove("/tmp/locks-demo2.table");
  }

  std::cout << "== JSON validity ==\n";
  {
    Snapshot s;
    s.ts = 1785117430;
    s.locks.clear(); s.procs.clear();
    demo_load_file("/tmp/locks-demo3.table", s);
    std::ostringstream os;
    render_json(os, s, true);
    std::string j = os.str();
    check(j.starts_with("{\n  \"summary\": {"), "json starts with quoted summary key");
    check(j.find("\"locks\": [") != std::string::npos, "json has quoted locks array");
    check(j.find("\"type\": \"FLOCK\"") != std::string::npos, "json type quoted");
    check(j.find("\"comm\": \"postgres\"") != std::string::npos, "json comm quoted");
    check(std::count(j.begin(), j.end(), '{') == std::count(j.begin(), j.end(), '}'),
          "json braces balanced");
    check(j.rfind("}") == j.size() - 2, "json ends with closing brace");
    std::remove("/tmp/locks-demo3.table");
  }

  std::cout << "== real /proc + comm resolution ==\n";
  {
    Snapshot s;
    check(parse_locks_file("/proc/locks", s), "reads real /proc/locks");
    s.ts = now_secs();
    resolve_procs(s);
    if (!s.locks.empty()) {
      bool any_comm = false;
      for (const auto& [pid, comm] : s.procs) if (!comm.empty()) { any_comm = true; break; }
      check(any_comm, "at least one pid resolved to a comm");
      // The pid of the first lock must resolve to a real process dir
      pid_t first_pid = s.locks.front().pid;
      bool dir_ok = std::filesystem::exists("/proc/" + std::to_string(first_pid));
      check(dir_ok, "first lock's pid exists in /proc: " + std::to_string(first_pid));
    } else {
      std::cout << "  INFO  host has 0 file locks\n";
      check(true, "sparse host tolerated");
    }
  }

  std::cout << "\nRESULT: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void usage() {
  std::cout <<
    "Usage: ./locks-watch [options]\n"
    "  Linux file-lock monitor — /proc/locks\n"
    "\n"
    "  --type TYPE          filter by lock type: FLOCK | POSIX | OFDLCK\n"
    "  --access MODE        filter by access: READ | WRITE\n"
    "  --mandatory          only MANDATORY locks (posix mandatory locking)\n"
    "  --pid PID            only locks held by that pid\n"
    "  --top N              show only the first N locks\n"
    "  --sort KEY           sort by: id (default) | pid | inode\n"
    "  --watch N            refresh every N seconds, printing deltas\n"
    "  --byte-range         only locks with a finite byte range (not EOF)\n"
    "  --json               machine-readable JSON output\n"
    "  --demo               synthetic 32-lock demo (busy DB + web + browser host)\n"
    "  --file PATH          parse a dump file instead of /proc (tolerates # comments)\n"
    "  --no-resolve         skip pid -> process name resolution\n"
    "  --no-color           disable ANSI colors (0 escapes in pipes)\n"
    "  --selftest           run self-tests\n"
    "  -h, --help           show this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next_val = [&](const char* flag) -> std::optional<std::string> {
      if (i + 1 < argc) { ++i; return std::string(argv[i]); }
      std::cerr << "Missing value for " << flag << "\n";
      return std::nullopt;
    };
    if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (a == "--selftest")     { return selftest(); }
    else if (a == "--no-color")     { f.color = false; disable_color(); }
    else if (a == "--no-resolve")   { f.resolve = false; }
    else if (a == "--json")         { f.json = true; }
    else if (a == "--demo")         { f.demo = true; }
    else if (a == "--mandatory")    { f.mandatory_only = true; }
    else if (a == "--byte-range")   { f.byte_range = true; }
    else if (a == "--type") {
      auto v = next_val("--type"); if (!v) return 2;
      std::string up = *v;
      std::transform(up.begin(), up.end(), up.begin(),
                     [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
      if (up != "FLOCK" && up != "POSIX" && up != "OFDLCK") { std::cerr << "Bad --type (FLOCK|POSIX|OFDLCK)\n"; return 2; }
      f.type = up;
    }
    else if (a == "--access") {
      auto v = next_val("--access"); if (!v) return 2;
      std::string up = *v;
      std::transform(up.begin(), up.end(), up.begin(),
                     [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
      if (up != "READ" && up != "WRITE") { std::cerr << "Bad --access (READ|WRITE)\n"; return 2; }
      f.access = up;
    }
    else if (a == "--pid") {
      auto v = next_val("--pid"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.pid = static_cast<pid_t>(*n); else { std::cerr << "Bad --pid\n"; return 2; }
    }
    else if (a == "--top") {
      auto v = next_val("--top"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.top = static_cast<int>(*n); else { std::cerr << "Bad --top\n"; return 2; }
    }
    else if (a == "--sort") {
      auto v = next_val("--sort"); if (!v) return 2;
      if (*v == "pid") f.sort = 1;
      else if (*v == "inode") f.sort = 2;
      else if (*v == "id") f.sort = 0;
      else { std::cerr << "Bad --sort (id|pid|inode)\n"; return 2; }
    }
    else if (a == "--watch") {
      auto v = next_val("--watch"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.watch = static_cast<int>(*n); else { std::cerr << "Bad --watch\n"; return 2; }
      if (f.watch <= 0) f.watch = 0;
    }
    else if (a == "--file") {
      auto v = next_val("--file"); if (!v) return 2;
      f.file = *v;
    }
    else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 2; }
  }

  if (f.watch > 0) {
    Snapshot prev, cur;
    auto load = [&](Snapshot& s) {
      s.locks.clear(); s.procs.clear();
      bool ok = f.demo ? demo_load_file("/tmp/locks-watch-demo.table", s)
                       : f.file.empty() ? parse_locks_file("/proc/locks", s)
                                        : parse_locks_file(f.file, s);
      if (ok) { s.ts = now_secs(); if (f.resolve) resolve_procs(s); }
      return ok;
    };
    load(prev);
    for (;;) {
      load(cur);
      render_snapshot(cur, f, true);
      render_delta(prev, cur, f);
      prev = std::move(cur);
      std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned>(f.watch)));
    }
  }

  Snapshot s;
  s.ts = now_secs();
  if (f.demo) {
    if (!demo_load_file("/tmp/locks-watch-demo.table", s)) { std::cerr << "Cannot write demo table\n"; return 1; }
  } else if (!f.file.empty()) {
    if (!parse_locks_file(f.file, s)) { std::cerr << "Cannot open " << f.file << "\n"; return 1; }
  } else {
    if (!parse_locks_file("/proc/locks", s)) { std::cerr << "Cannot open /proc/locks\n"; return 1; }
  }
  if (f.resolve) resolve_procs(s);
  if (f.json) render_json(std::cout, s, f.demo);
  else        render_snapshot(s, f, false);
  return 0;
}