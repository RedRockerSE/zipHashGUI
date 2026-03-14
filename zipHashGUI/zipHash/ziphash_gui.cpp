// ziphash_gui.cpp — Windows drag-and-drop file hash calculator
// Build: cl ziphash_gui.cpp /std:c++17 /O2 /W3 /EHsc /link bcrypt.lib comctl32.lib shell32.lib dwmapi.lib comdlg32.lib user32.lib gdi32.lib /SUBSYSTEM:WINDOWS
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <filesystem>
#include <chrono>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "comdlg32.lib")
// Ensure the app is linked as a Windows GUI application so no console window is created.
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

#undef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define CHUNK_SIZE (256 * 1024)

// ── Control IDs ──────────────────────────────────────────────────────────────
enum {
    IDC_RADIO_MD5 = 101,
    IDC_RADIO_SHA256,
    IDC_HASH_EDIT,
    IDC_COPY_BTN,
    IDC_PROGRESS,
    IDC_BROWSE_BTN,
};

// ── Custom messages ───────────────────────────────────────────────────────────
#define WM_HASH_DONE     (WM_USER + 1)   // lParam = HashResult* (caller must delete)
#define WM_HASH_PROGRESS (WM_USER + 2)   // wParam = percent 0-100

// ── Layout constants ──────────────────────────────────────────────────────────
static const int MARGIN  = 16;
static const int DROP_H  = 152;
static const int CTRL_H  = 26;
static const int LABEL_H = 20;
static const int GAP     = 8;
static const int PBAR_H  = 6;

// ── Dark-theme colour palette ────────────────────────────────────────────────
static const COLORREF C_BG      = RGB(24,  24,  30);
static const COLORREF C_PANEL   = RGB(36,  36,  46);
static const COLORREF C_BORDER  = RGB(65,  65,  85);
static const COLORREF C_TEXT    = RGB(210, 210, 220);
static const COLORREF C_DIM     = RGB(120, 120, 140);
static const COLORREF C_ACCENT  = RGB(88,  142, 228);
static const COLORREF C_SUCCESS = RGB(70,  196, 110);
static const COLORREF C_ERROR   = RGB(218, 78,  78);

// ── Data types ────────────────────────────────────────────────────────────────
struct HashResult {
    std::wstring filename, alg, hash, err;
    long long ms = 0;
    bool ok      = false;
};

struct Layout {
    RECT drop, radMD5, radSHA, prog;
    RECT fileRow, algRow, timeRow;
    RECT hashEdit, copyBtn, browseBtn;
};

// ── App globals ───────────────────────────────────────────────────────────────
static HWND g_hwnd;
static HWND g_hwndRadMD5, g_hwndRadSHA256;
static HWND g_hwndHashEdit, g_hwndCopyBtn, g_hwndBrowseBtn;
static HWND g_hwndProgress;
static HFONT  g_fNormal, g_fSemi, g_fMono;
static HBRUSH g_brBg, g_brPanel;
static std::atomic<bool> g_busy{false};
static bool       g_hasResult = false;
static HashResult g_result;
static std::wstring g_currentPath;

// ── Helpers ───────────────────────────────────────────────────────────────────
static std::wstring BytesToHex(const std::vector<BYTE>& v) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (auto b : v) ss << std::setw(2) << (int)b;
    return ss.str();
}

// Some build configurations (console subsystem) expect a `main` symbol.
// Provide a minimal `main` that forwards to `wWinMain` so linking succeeds
// regardless of subsystem selection.
int main() {
    return wWinMain(GetModuleHandle(NULL), NULL, GetCommandLineW(), SW_SHOWNORMAL);
}

static void CopyToClipboard(HWND hwnd, const std::wstring& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hg) { memcpy(GlobalLock(hg), text.c_str(), bytes); GlobalUnlock(hg); SetClipboardData(CF_UNICODETEXT, hg); }
    CloseClipboard();
}

// ── Hash thread ───────────────────────────────────────────────────────────────
static void HashThread(HWND hwnd, std::wstring path, std::wstring alg) {
    HashResult* r = new HashResult();
    r->filename = std::filesystem::path(path).filename().wstring();
    r->alg      = alg;

    LPCWSTR algId = (alg == L"md5") ? BCRYPT_MD5_ALGORITHM : BCRYPT_SHA256_ALGORITHM;

    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    DWORD cbObj = 0, cbHash = 0, cbData = 0;

    st = BCryptOpenAlgorithmProvider(&hAlg, algId, NULL, 0);
    if (!NT_SUCCESS(st)) { r->err = L"BCryptOpenAlgorithmProvider failed"; goto post; }

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObj,  sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,   (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);

    {
        std::vector<BYTE> obj(cbObj), hash(cbHash);
        st = BCryptCreateHash(hAlg, &hHash, obj.data(), cbObj, NULL, 0, 0);
        if (!NT_SUCCESS(st)) { r->err = L"BCryptCreateHash failed"; BCryptCloseAlgorithmProvider(hAlg, 0); goto post; }

        // Declare variables up-front so a later `goto cleanup` cannot skip their initialization
        LONGLONG done = 0;
        std::vector<BYTE> buf(CHUNK_SIZE);
        DWORD n = 0;
        bool ok = true;
        std::chrono::high_resolution_clock::time_point t0;

        HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hf == INVALID_HANDLE_VALUE) { r->err = L"Cannot open file"; goto cleanup; }

        LARGE_INTEGER sz; GetFileSizeEx(hf, &sz);
        t0 = std::chrono::high_resolution_clock::now();

        while (ReadFile(hf, buf.data(), (DWORD)buf.size(), &n, NULL) && n > 0) {
            if (!NT_SUCCESS(BCryptHashData(hHash, buf.data(), n, 0))) {
                ok = false; r->err = L"BCryptHashData failed"; break;
            }
            done += n;
            if (sz.QuadPart > 0)
                PostMessage(hwnd, WM_HASH_PROGRESS, (WPARAM)((done * 100) / sz.QuadPart), 0);
        }
        CloseHandle(hf);

        if (ok && NT_SUCCESS(BCryptFinishHash(hHash, hash.data(), cbHash, 0))) {
            r->hash = BytesToHex(hash);
            r->ms   = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::high_resolution_clock::now() - t0).count();
            r->ok   = true;

            // Write the calculated hash to a text file in the same folder as the checked file.
            // Naming convention: <checked_stem>_calculated-hash.txt
            try {
                std::filesystem::path inPath(path);
                std::wstring outName = inPath.stem().wstring() + L"_calculated-hash.txt";
                std::filesystem::path outPath = inPath.parent_path() / outName;

                // Build metadata content (wide string)
                std::wstring content = L"Filename: " + inPath.filename().wstring() + L"\r\n";
                content += L"Algorithm: ";
                content += (alg == L"md5") ? L"MD5" : L"SHA-256";
                content += L"\r\n";
                content += L"Hash: ";
                content += r->hash;
                content += L"\r\n";
                content += L"Time: ";
                content += std::to_wstring(r->ms) + L" ms\r\n";

                // Convert to UTF-8
                int needed = WideCharToMultiByte(CP_UTF8, 0, content.c_str(), -1, nullptr, 0, nullptr, nullptr);
                if (needed > 0) {
                    std::string outUtf8(needed - 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, content.c_str(), -1, outUtf8.data(), needed, nullptr, nullptr);

                    HANDLE hfOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                               FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hfOut != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        WriteFile(hfOut, outUtf8.data(), (DWORD)outUtf8.size(), &written, NULL);
                        CloseHandle(hfOut);
                    } else {
                        r->err = L"Failed to create hash output file";
                    }
                }
            } catch (...) {
                // ignore filesystem exceptions; don't fail the hash because of logging failure
            }
        } else if (ok) r->err = L"BCryptFinishHash failed";

    cleanup:
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
post:
    PostMessage(hwnd, WM_HASH_DONE, 0, (LPARAM)r);
}

static void StartHash(const std::wstring& path) {
    if (g_busy) return;
    g_busy       = true;
    g_hasResult  = false;

    std::wstring alg = (SendMessage(g_hwndRadMD5, BM_GETCHECK, 0, 0) == BST_CHECKED)
                       ? L"md5" : L"sha256";

    SendMessage(g_hwndProgress, PBM_SETPOS, 0, 0);
    ShowWindow(g_hwndProgress, SW_SHOW);
    ShowWindow(g_hwndHashEdit,  SW_HIDE);
    ShowWindow(g_hwndCopyBtn,   SW_HIDE);
    SetWindowText(g_hwndHashEdit, L"");
    InvalidateRect(g_hwnd, NULL, TRUE);

    std::thread(HashThread, g_hwnd, path, alg).detach();
}

// ── Layout ───────────────────────────────────────────────────────────────────
static Layout CalcLayout(int W, int H) {
    Layout l = {};
    int x = MARGIN, w = W - 2 * MARGIN, y = MARGIN;

    l.drop   = {x, y, x + w, y + DROP_H};            y += DROP_H + MARGIN;
    l.radMD5 = {x, y, x + 75, y + 24};
    l.radSHA = {x + 85, y, x + 185, y + 24};          y += 24 + GAP;
    l.prog   = {x, y, x + w, y + PBAR_H};             y += PBAR_H + MARGIN;

    l.fileRow = {x, y, x + w, y + LABEL_H};           y += LABEL_H + GAP;
    l.algRow  = {x, y, x + w, y + LABEL_H};           y += LABEL_H + GAP;
    l.timeRow = {x, y, x + w, y + LABEL_H};           y += LABEL_H + GAP + 4;

    int cbW        = 92;
    l.hashEdit     = {x,            y, x + w - cbW - GAP, y + CTRL_H};
    l.copyBtn      = {x + w - cbW,  y, x + w,             y + CTRL_H};

    // Browse button sits inside the drop zone, bottom-centre
    int bw = 100, bh = 26;
    int bx = (l.drop.left + l.drop.right - bw) / 2;
    int by = l.drop.bottom - bh - 10;
    l.browseBtn = {bx, by, bx + bw, by + bh};

    return l;
}

// ── Drawing ───────────────────────────────────────────────────────────────────
static void DrawDropZone(HDC dc, const RECT& r, bool busy) {
    HBRUSH br = CreateSolidBrush(C_PANEL);
    FillRect(dc, &r, br);
    DeleteObject(br);

    // Dashed border
    HPEN pen = CreatePen(PS_DASH, 1, C_BORDER);
    HPEN op  = (HPEN)SelectObject(dc, pen);
    HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    SetBkMode(dc, OPAQUE);
    SetBkColor(dc, C_PANEL);
    RoundRect(dc, r.left + 1, r.top + 1, r.right - 1, r.bottom - 1, 14, 14);
    SelectObject(dc, op); SelectObject(dc, ob);
    DeleteObject(pen);

    SetBkMode(dc, TRANSPARENT);
    int cx = (r.left + r.right) / 2;
    int cy = r.top + (r.bottom - r.top) / 2 - 14;

    if (busy) {
        HFONT of = (HFONT)SelectObject(dc, g_fSemi);
        SetTextColor(dc, C_ACCENT);
        RECT tr = {r.left, cy - 10, r.right, cy + 14};
        DrawText(dc, L"Calculating\u2026", -1, &tr, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, of);
    } else {
        // Document icon (pentagon + fold corner)
        POINT doc[] = {
            {cx - 14, cy - 20}, {cx + 7,  cy - 20},
            {cx + 15, cy - 11}, {cx + 15, cy + 20},
            {cx - 14, cy + 20}
        };
        HBRUSH ib = CreateSolidBrush(C_DIM);
        HPEN   ip = CreatePen(PS_SOLID, 1, C_DIM);
        SelectObject(dc, ib); SelectObject(dc, ip);
        Polygon(dc, doc, 5);

        // Fold-corner overlay (background colour triangle to "cut" the corner)
        POINT fold[] = {{cx + 7, cy - 20}, {cx + 7, cy - 11}, {cx + 15, cy - 11}};
        HBRUSH fb = CreateSolidBrush(C_PANEL);
        SelectObject(dc, fb);
        Polygon(dc, fold, 3);
        DeleteObject(fb);

        // Fold crease lines
        SelectObject(dc, GetStockObject(NULL_BRUSH));
        MoveToEx(dc, cx + 7, cy - 11, NULL); LineTo(dc, cx + 15, cy - 11);
        MoveToEx(dc, cx + 7, cy - 20, NULL); LineTo(dc, cx + 7,  cy - 11);

        DeleteObject(ib); DeleteObject(ip);

        // Horizontal lines on the doc
        HPEN lp = CreatePen(PS_SOLID, 1, C_PANEL);
        SelectObject(dc, lp);
        for (int ly = cy - 6; ly <= cy + 14; ly += 7) {
            MoveToEx(dc, cx - 9, ly, NULL); LineTo(dc, cx + 10, ly);
        }
        DeleteObject(lp);

        HFONT of = (HFONT)SelectObject(dc, g_fSemi);
        SetTextColor(dc, C_TEXT);
        RECT t1 = {r.left, cy + 28, r.right, cy + 50};
        DrawText(dc, L"Drop a file here", -1, &t1, DT_CENTER | DT_SINGLELINE);
        SelectObject(dc, g_fNormal);
        SetTextColor(dc, C_DIM);
        RECT t2 = {r.left, cy + 52, r.right, cy + 70};
        DrawText(dc, L"Any file type \u2022 MD5 or SHA-256", -1, &t2, DT_CENTER | DT_SINGLELINE);
        SelectObject(dc, of);
    }
}

static void DrawRow(HDC dc, const RECT& row, const wchar_t* label, const wchar_t* value, COLORREF vc) {
    SetBkMode(dc, TRANSPARENT);
    RECT lr = {row.left,      row.top, row.left + 92, row.bottom};
    RECT vr = {row.left + 92, row.top, row.right,     row.bottom};
    SelectObject(dc, g_fNormal);
    SetTextColor(dc, C_DIM);
    DrawText(dc, label, -1, &lr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SetTextColor(dc, vc);
    DrawText(dc, value, -1, &vr, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
}

// ── Window proc ───────────────────────────────────────────────────────────────
LRESULT CALLBACK WndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {

    case WM_CREATE: {
        DragAcceptFiles(hw, TRUE);

        // Dark title bar (Windows 10 20H1+; try both known attribute IDs)
        BOOL dark = TRUE;
        if (FAILED(DwmSetWindowAttribute(hw, 20, &dark, sizeof(BOOL))))
            DwmSetWindowAttribute(hw, 19, &dark, sizeof(BOOL));

        g_fNormal = CreateFont(-13, 0,0,0, FW_NORMAL,   0,0,0, DEFAULT_CHARSET,0,0, CLEARTYPE_QUALITY, 0,              L"Segoe UI");
        g_fSemi   = CreateFont(-14, 0,0,0, FW_SEMIBOLD, 0,0,0, DEFAULT_CHARSET,0,0, CLEARTYPE_QUALITY, 0,              L"Segoe UI");
        g_fMono   = CreateFont(-13, 0,0,0, FW_NORMAL,   0,0,0, DEFAULT_CHARSET,0,0, CLEARTYPE_QUALITY, FIXED_PITCH|FF_MODERN, L"Consolas");

        g_brBg    = CreateSolidBrush(C_BG);
        g_brPanel = CreateSolidBrush(C_PANEL);

        HINSTANCE hi = (HINSTANCE)GetWindowLongPtr(hw, GWLP_HINSTANCE);

        g_hwndRadMD5    = CreateWindow(L"BUTTON", L"MD5",     WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|WS_GROUP, 0,0,0,0, hw, (HMENU)IDC_RADIO_MD5,    hi, NULL);
        g_hwndRadSHA256 = CreateWindow(L"BUTTON", L"SHA-256", WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,          0,0,0,0, hw, (HMENU)IDC_RADIO_SHA256, hi, NULL);
        g_hwndHashEdit  = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD|ES_READONLY|ES_AUTOHSCROLL, 0,0,0,0, hw, (HMENU)IDC_HASH_EDIT,   hi, NULL);
        g_hwndCopyBtn   = CreateWindow(L"BUTTON", L"Copy Hash",   WS_CHILD|BS_PUSHBUTTON,          0,0,0,0, hw, (HMENU)IDC_COPY_BTN,   hi, NULL);
        g_hwndBrowseBtn = CreateWindow(L"BUTTON", L"Browse\u2026", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 0,0,0,0, hw, (HMENU)IDC_BROWSE_BTN, hi, NULL);
        g_hwndProgress  = CreateWindow(PROGRESS_CLASS, NULL, WS_CHILD|PBS_SMOOTH, 0,0,0,0, hw, (HMENU)IDC_PROGRESS, hi, NULL);

        SendMessage(g_hwndRadMD5,   BM_SETCHECK, BST_CHECKED, 0);
        SendMessage(g_hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(g_hwndProgress, PBM_SETBARCOLOR, 0, (LPARAM)C_ACCENT);
        SendMessage(g_hwndProgress, PBM_SETBKCOLOR,  0, (LPARAM)RGB(50, 50, 65));

        for (HWND h : {g_hwndRadMD5, g_hwndRadSHA256, g_hwndCopyBtn, g_hwndBrowseBtn})
            SendMessage(h, WM_SETFONT, (WPARAM)g_fNormal, TRUE);
        SendMessage(g_hwndHashEdit, WM_SETFONT, (WPARAM)g_fMono, TRUE);
        return 0;
    }

    case WM_SIZE: {
        int W = LOWORD(lp), H = HIWORD(lp);
        if (W == 0 || H == 0) return 0;
        auto l = CalcLayout(W, H);
        auto mv = [](HWND h, RECT r) {
            SetWindowPos(h, NULL, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER);
        };
        mv(g_hwndRadMD5,    l.radMD5);
        mv(g_hwndRadSHA256, l.radSHA);
        mv(g_hwndProgress,  l.prog);
        mv(g_hwndHashEdit,  l.hashEdit);
        mv(g_hwndCopyBtn,   l.copyBtn);
        mv(g_hwndBrowseBtn, l.browseBtn);
        InvalidateRect(hw, NULL, TRUE);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hw, &ps);
        RECT cli; GetClientRect(hw, &cli);
        FillRect(dc, &cli, g_brBg);

        auto l = CalcLayout(cli.right, cli.bottom);
        DrawDropZone(dc, l.drop, (bool)g_busy);

        if (g_hasResult) {
            DrawRow(dc, l.fileRow, L"File:",
                    g_result.filename.c_str(),
                    g_result.ok ? C_TEXT : C_ERROR);

            std::wstring algStr = (g_result.alg == L"md5") ? L"MD5" : L"SHA-256";
            DrawRow(dc, l.algRow, L"Algorithm:", algStr.c_str(), C_TEXT);

            if (g_result.ok) {
                std::wstring t = std::to_wstring(g_result.ms) + L" ms";
                DrawRow(dc, l.timeRow, L"Time:", t.c_str(), C_DIM);
            } else {
                DrawRow(dc, l.timeRow, L"Error:", g_result.err.c_str(), C_ERROR);
            }

            // "Hash:" label to the left of the edit control
            SetBkMode(dc, TRANSPARENT);
            RECT hl = {l.hashEdit.left, l.hashEdit.top,
                       l.hashEdit.left + 45, l.hashEdit.bottom};
            // (the edit control handles its own display; just draw the section header)
			// The label is drawn in the same colour as the edit control text for better contrast against the background.
        }
        EndPaint(hw, &ps);
        return 0;
    }

    case WM_ERASEBKGND: return 1;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_BG);
        return (LRESULT)g_brBg;
    }

    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_SUCCESS);
        SetBkColor(dc, C_PANEL);
        return (LRESULT)g_brPanel;
    }

    case WM_DROPFILES: {
        HDROP hd = (HDROP)wp;
        if (!g_busy) {
            wchar_t path[MAX_PATH];
            if (DragQueryFile(hd, 0, path, MAX_PATH)) {
                g_currentPath = path;
                StartHash(path);
            }
        }
        DragFinish(hd);
        return 0;
    }

    case WM_COMMAND: {
        switch (LOWORD(wp)) {
        case IDC_COPY_BTN: {
            int len = GetWindowTextLength(g_hwndHashEdit);
            if (len > 0) {
                std::wstring s(len, L'\0');
                GetWindowText(g_hwndHashEdit, s.data(), len + 1);
                CopyToClipboard(hw, s);
                SetWindowText(g_hwndCopyBtn, L"Copied!");
                SetTimer(hw, 1, 1500, NULL);
            }
            break;
        }
        case IDC_BROWSE_BTN: {
            OPENFILENAME ofn = {};
            wchar_t fn[MAX_PATH] = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner   = hw;
            ofn.lpstrFile   = fn;
            ofn.nMaxFile    = MAX_PATH;
            ofn.lpstrFilter = L"All Files\0*.*\0ZIP Files\0*.zip\0";
            ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileName(&ofn)) {
                g_currentPath = fn;
                StartHash(fn);
            }
            break;
        }
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == 1) { SetWindowText(g_hwndCopyBtn, L"Copy Hash"); KillTimer(hw, 1); }
        return 0;

    case WM_HASH_PROGRESS:
        SendMessage(g_hwndProgress, PBM_SETPOS, wp, 0);
        return 0;

    case WM_HASH_DONE: {
        HashResult* r = (HashResult*)lp;
        g_result    = *r;
        delete r;
        g_busy      = false;
        g_hasResult = true;

        SetWindowText(g_hwndHashEdit, g_result.ok ? g_result.hash.c_str()
                                                  : (L"Error: " + g_result.err).c_str());
        ShowWindow(g_hwndHashEdit, SW_SHOW);
        if (g_result.ok) ShowWindow(g_hwndCopyBtn, SW_SHOW);
        SendMessage(g_hwndProgress, PBM_SETPOS, 100, 0);
        InvalidateRect(hw, NULL, TRUE);
        return 0;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize = {460, 400};
        return 0;
    }

    case WM_DESTROY:
        DeleteObject(g_fNormal); DeleteObject(g_fSemi); DeleteObject(g_fMono);
        DeleteObject(g_brBg);    DeleteObject(g_brPanel);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hw, msg, wp, lp);
}

// ── Entry point ───────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int show) {
    INITCOMMONCONTROLSEX ic = {sizeof(ic), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&ic);

    WNDCLASSEX wc    = {sizeof(wc)};
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(C_BG);
    wc.lpszClassName = L"ZipHashGUI";
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassEx(&wc);

    RECT r = {0, 0, 520, 440};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    int W = r.right - r.left, H = r.bottom - r.top;
    int X = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
    int Y = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;

    g_hwnd = CreateWindowEx(
        WS_EX_ACCEPTFILES,
        L"ZipHashGUI",
        L"ZipHash \u2014 File Hash Calculator",
        WS_OVERLAPPEDWINDOW,
        X, Y, W, H,
        NULL, NULL, hi, NULL);

    ShowWindow(g_hwnd, show);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
