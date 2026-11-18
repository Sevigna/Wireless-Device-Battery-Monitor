// EXPERIMENTAL: MCHOSE L7 Ultra+ support (receiver 5253:1020).
//
// The L7 Ultra+ answers the L7's inverted-payload status query (report 0x12) only with an
// all-zero payload, which the L7 driver reports as "asleep". Its receiver also exposes an
// FF0B:0104 collection that the L7 Ultra does not have, which looks like the interface of
// the new MCHOSE family (mchose_modern.cpp: 64-byte report 0x4D, device-info command 0x0900).
// This driver probes both protocols on both vendor collections (FF01:0001, FF0B:0104) and
// logs every exchange to %TEMP%\WirelessBattery-mchose.txt (overwritten each poll) so the
// protocol can be identified from a paste of that file. It only ever sends read-only battery
// queries, exactly like the two drivers it borrows from, and claims the device only when a
// probe is answered; otherwise the L7 driver handles the receiver as before.
//
// Candidate upstream patch once verified; the log lines disappear then.
#include "drivers.h"

#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

const USHORT kVid = 0x5253;
const USHORT kPid = 0x1020;

std::string Hex(const std::vector<BYTE>& b) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    for (BYTE x : b) {
        if (s.size() >= 480) {
            s += "...";
            break;
        }
        s += d[x >> 4];
        s += d[x & 15];
    }
    return s;
}

std::string CollTag(const HidColl& c) {
    char b[64];
    snprintf(b, sizeof(b), "[%04X:%04X in %u out %u feat %u] ", c.page(), c.usage(), (unsigned)c.inLen(), (unsigned)c.outLen(),
             (unsigned)c.featLen());
    return b;
}

// One log line; ASCII only. Windows: %TEMP%\WirelessBattery-mchose.txt (recreated each poll).
void LogProbe(const std::string& s) {
#ifdef _WIN32
    wchar_t dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, dir);
    std::wstring path = std::wstring(dir) + L"WirelessBattery-mchose.txt";
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(f, s.data(), (DWORD)s.size(), &w, nullptr);
    CloseHandle(f);
#else
    FILE* f = fopen("/tmp/WirelessBattery-mchose.txt", "w");
    if (!f) return;
    fwrite(s.data(), 1, s.size(), f);
    fclose(f);
#endif
}

BYTE XorRange(const std::vector<BYTE>& b, size_t from, size_t to) {  // both ends inclusive
    BYTE x = 0;
    for (size_t i = from; i <= to && i < b.size(); i++) x ^= b[i];
    return x;
}

// The "modern" device-info frame (mchose_modern.cpp), with the vid field left open:
// this family reports 3837 / 41E4 there, the 5253 dongles may report 5253.
// Returns 1 = battery read, 0 = valid frame but mouse not linked, -1 = no valid answer.
int ParseModern(const std::vector<BYTE>& r, int& percent, bool& charging) {
    const size_t kData = 8;
    if (r.size() < kData + 2 || r[0] != 0x4D) return -1;
    if ((USHORT)(r[4] | (r[5] << 8)) != 0x0900) return -1;
    const size_t len = r[3];
    if (kData + len >= r.size()) return -1;
    if (len < 14) return 0;  // header only: mouse off or not linked
    if (r[kData + len] != XorRange(r, 2, 7 + len)) return -1;
    USHORT vid = (USHORT)(r[kData] | (r[kData + 1] << 8));
    if (vid != kVid && vid != 0x41E4 && vid != 0x3837) return -1;
    if (r[kData + 10] == 0) return 0;  // not linked
    if (r[kData + 12] > 100) return -1;
    percent = r[kData + 12];
    charging = r[kData + 11] == 1;
    return 1;
}

// The L7 family's inverted-payload status reply (mchose.cpp), vid field open for the same reason.
int ParseOld(const std::vector<BYTE>& r, int& level, bool& charging) {
    if (r.size() < 13 || r[0] != 0x12 || r[1] != (BYTE)(0x06 ^ 0xFF)) return -1;
    BYTE p[11] = {};
    for (int i = 0; i < 11 && 2 + i < r.size(); i++) p[i] = r[2 + i] ^ 0xFF;
    bool allZero = true;
    for (BYTE b : p)
        if (b) {
            allZero = false;
            break;
        }
    if (allZero) return 0;  // echo with empty payload: mouse asleep or protocol variant
    USHORT vid = (USHORT)(p[0] | (p[1] << 8));
    if (vid != kVid && vid != 0x41E4 && vid != 0x3837) return -1;
    level = p[9];
    charging = p[10] != 0;
    return level <= 100 ? 1 : -1;
}

int ProbeModern(HidDev& d, std::string& log, int& percent, bool& charging) {
    const size_t kData = 8;
    std::vector<BYTE> req(d.coll().outLen(), 0);
    if (req.size() < 16) return -1;
    req[0] = 0x4D;
    req[1] = 0x01;  // read
    req[4] = 0x00;  // command 0x0900: device info
    req[5] = 0x09;
    req[kData] = XorRange(req, 2, 7);
    log += "modern " + CollTag(d.coll()) + "req: " + Hex(req) + "\n";
    int state = -1;
    for (int attempt = 0; attempt < 2 && state < 0; attempt++) {
        if (attempt) Sleep(150);
        d.Flush();
        if (!d.Write(req)) {
            // no interrupt OUT pipe: send via the control pipe, first input report back
            std::vector<BYTE> r;
            if (d.SetOutputAndRead(req, r, 600) > 0) {
                log += "modern " + CollTag(d.coll()) + "reply(setoutput): " + Hex(r) + "\n";
                state = ParseModern(r, percent, charging);
                if (state >= 0) break;
            } else {
                log += "modern " + CollTag(d.coll()) + "no reply (output pipe unusable)\n";
                break;
            }
        } else {
            ULONGLONG end = GetTickCount64() + 600;
            for (;;) {
                LONGLONG left = (LONGLONG)end - (LONGLONG)GetTickCount64();
                if (left <= 0) break;
                std::vector<BYTE> r;
                int n = d.Read(r, (int)left);
                if (n < 0) break;
                log += "modern " + CollTag(d.coll()) + "reply: " + Hex(r) + "\n";
                state = ParseModern(r, percent, charging);
                if (state >= 0) break;
            }
        }
    }
    if (state < 0) log += "modern " + CollTag(d.coll()) + "no valid reply\n";
    return state;
}

int ProbeOld(HidDev& d, std::string& log, int& level, bool& charging) {
    std::vector<BYTE> req(d.coll().featLen(), 0xFF);  // inverted zero padding
    req[0] = 0x12;
    req[1] = 0x06 ^ 0xFF;
    int state = -1;
    for (int attempt = 0; attempt < 3 && state != 1; attempt++) {
        if (attempt) Sleep(100);
        std::vector<BYTE> r;
        if (!d.SetFeature(req)) {
            log += "old " + CollTag(d.coll()) + "SetFeature failed\n";
            break;
        }
        Sleep(120);
        if (!d.GetFeature(0x12, r)) {
            log += "old " + CollTag(d.coll()) + "GetFeature failed\n";
            continue;
        }
        log += "old " + CollTag(d.coll()) + "reply: " + Hex(r) + "\n";
        int st = ParseOld(r, level, charging);
        if (st > state) state = st;
    }
    return state;
}

}  // namespace

void PollMchoseUltraPlus(PollContext& ctx) {
    if (ctx.IsClaimed(kVid, kPid)) return;
    std::vector<const HidColl*> vendor = ctx.Find(kVid, kPid, [](const HidColl& c) { return c.page() == 0xFF01 || c.page() == 0xFF0B; });
    if (vendor.empty()) return;
    std::string log = "--- MCHOSE L7 Ultra+ probe (overwritten every poll) ---\n";
    int state = -1, percent = -1, level = -1;
    bool charging = false;
    std::wstring name;

    // A) the modern device-info protocol, on every bidirectional vendor collection
    for (const HidColl* c : vendor) {
        if (c->outLen() < 21 || c->inLen() < 21) continue;
        HidDev d;
        if (!d.Open(*c)) {
            log += "modern " + CollTag(*c) + "open failed\n";
            continue;
        }
        int st = ProbeModern(d, log, percent, charging);
        if (st >= 0) {
            state = st;
            name = HidProduct(*c);
            break;
        }
    }
    // B) the old inverted-payload protocol, on vendor collections with feature reports
    if (state < 0) {
        for (const HidColl* c : vendor) {
            if (c->featLen() < 13) continue;
            HidDev d;
            if (!d.OpenFeatureOnly(*c)) {
                log += "old " + CollTag(*c) + "open failed\n";
                continue;
            }
            int lv = -1;
            bool ch = false;
            int st = ProbeOld(d, log, lv, ch);
            if (st >= 0) {
                state = st;
                level = lv;
                charging = ch;
                name = HidProduct(*c);
                break;
            }
        }
    }
    LogProbe(log);
    if (state < 0) return;  // nothing answered: the L7 driver keeps the receiver as before

    DeviceStatus s;
    s.key = L"mchose-ultraplus:" + Hex4(kPid);
    s.name = name.empty() ? L"MCHOSE mouse" : name;
    s.kind = DeviceKind::Mouse;
    s.via = L"2.4 GHz receiver";
    s.graceSec = 1800;
    if (state == 1) {
        s.percent = Clamp100(percent >= 0 ? percent : level);
        s.charging = charging;
    } else {
        s.asleep = true;
    }
    ctx.Add(s, kVid, kPid);
}
