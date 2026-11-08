---
version: alpha
name: Arbiter Investigation Desk
description: "Quiet, offline-first SOC investigation desk. Implemented as the Quiet Evidence Desk design system; tokens live in app/static/styles/tokens.css."
colors:
  primary: "#F5F5F5"
  secondary: "#B8B8B8"
  neutral: "#111111"
  surface: "#181818"
  raised: "#242424"
  border: "#383838"
  control: "#757575"
  inverse: "#111111"
  critical: "#FF9292"
  critical-surface: "#321B1B"
  warning: "#E8C16A"
  warning-surface: "#302919"
  success: "#8DD4AA"
  success-surface: "#1C2C23"
  info: "#A8C7FA"
  info-surface: "#1E2938"
typography:
  h1:
    fontFamily: IBM Plex Sans
    fontSize: 1.5rem
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  section:
    fontFamily: IBM Plex Sans
    fontSize: 1rem
    fontWeight: 600
    lineHeight: 1.5
  body-md:
    fontFamily: IBM Plex Sans
    fontSize: 0.875rem
    fontWeight: 400
    lineHeight: 1.5
  meta:
    fontFamily: IBM Plex Sans
    fontSize: 0.75rem
    fontWeight: 400
    lineHeight: 1.5
  code:
    fontFamily: IBM Plex Mono
    fontSize: 0.8125rem
    fontWeight: 400
    lineHeight: 1.6
rounded:
  sm: 4px
  md: 8px
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.inverse}"
    rounded: "{rounded.sm}"
    height: 40px
    padding: 12px
  button-primary-hover:
    backgroundColor: "{colors.secondary}"
    textColor: "{colors.inverse}"
  button-secondary:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.primary}"
    rounded: "{rounded.sm}"
    height: 40px
  page:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.primary}"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.primary}"
    rounded: "{rounded.md}"
    padding: 16px
  metadata:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.secondary}"
  severity-critical:
    backgroundColor: "{colors.critical-surface}"
    textColor: "{colors.critical}"
    rounded: "{rounded.sm}"
  severity-warning:
    backgroundColor: "{colors.warning-surface}"
    textColor: "{colors.warning}"
    rounded: "{rounded.sm}"
  status-success:
    backgroundColor: "{colors.success-surface}"
    textColor: "{colors.success}"
    rounded: "{rounded.sm}"
  status-info:
    backgroundColor: "{colors.info-surface}"
    textColor: "{colors.info}"
    rounded: "{rounded.sm}"
---

## Overview

**Status: disetujui dan diimplementasikan.** Arah "Quiet Evidence Desk" sudah hidup di `app/static/styles/tokens.css` (stempel "user-approved") dan komponen di `app/static/styles/*.css`. File ini adalah sumber token, dilint dengan `@google/design.md`.

Arbiter adalah local SOC investigation desk untuk menormalkan Wazuh telemetry, melakukan triage, menyusun insiden, dan menghasilkan dokumen. Mode utama: **Operate**. Keberhasilan berarti analis menemukan bukti, mengambil keputusan, dan menghasilkan laporan dengan scope yang benar—bukan melihat dashboard dekoratif.

Arah: **Quiet Evidence Desk**. Hierarki berasal dari antrean alert, bukti, klasifikasi, dan narasi insiden. Signature interaction: memilih alert membuka inspector kontekstual tanpa kehilangan filter, selection, atau posisi antrean; event respons tertaut ke alert asal, dan korelasi menjelaskan kronologi tanpa menggantikan keputusan analis.

Referensi prinsip: IBM/Carbon untuk functional density, tipografi, dan semantic tokens; app-screen guidance untuk neutral chrome; Emil design engineering untuk feedback singkat. Ini desain Arbiter sendiri, bukan clone IBM atau Linear. Tidak ada hero marketing, metric rekaan, chart tanpa pertanyaan, neon chrome, atau icon tile dekoratif.

## Colors

- **Primary / secondary:** teks utama dan pendukung, bukan warna branding pada navigation.
- **Neutral / surface / raised:** neutral dark untuk sesi investigasi panjang; elevation lewat perubahan tone, bukan glow.
- **Border:** structural divider, tidak menjadi satu-satunya batas input atau indikator state.
- **Control:** batas input yang perlu terlihat; uji rasio non-text 3:1 pada permukaan aktual.
- **Critical / warning / success / info:** hanya untuk status yang dibuktikan data. Setiap warna disertai label/glyph; tidak pernah satu-satunya penyampai makna.
- **Focus:** outline 2px primary dengan offset 3px pada dark surfaces; gunakan inverse outline pada inverted primary button. Tidak dianimasikan.
- Tidak ada palette cyan/violet untuk chrome. Link navigasi cukup dikenali lewat placement, label, hover underline di prose, dan focus; tidak semua link harus biru.
- Nol tetap 0; data tidak tersedia adalah em dash. Intel score 0 bukan verdict “aman” atau “clean”. Tulis “Tidak ada deteksi pada cache” dengan freshness bila tersedia.

## Typography

- IBM Plex Sans, bobot 400/500/600, untuk interface. IBM Plex Mono khusus raw logs, IP, identifiers, dan code; bukan semua caption.
- **Offline wajib:** self-host file font berlisensi yang diverifikasi saat implementasi. Tidak ada Google Fonts/CDN runtime. Fallback: Arial/sans-serif dan ui-monospace.
- Scale: 24px page title, 16px section, 14px body/table, 12px metadata; technical code 13px. Tidak ada interactive label 10px.
- Sentence case. Hindari label ALL CAPS dan emoji sebagai icon sistem.
- Angka pembanding memakai `font-variant-numeric: tabular-nums`; count dan numeric columns rata kanan. IP tidak diurutkan lexicographically.
- Log dan JSON mempertahankan makna whitespace; wrap toggle dan copy action tidak mengubah isi asli. Konten panjang punya region scroll lokal, bukan membuat seluruh row membesar.

## Layout

### Global shell

- Desktop >=1100px: sidebar 208px, page gutter 24px, utility header 48px; area kerja `minmax(0, 1fr)`.
- Primary navigation: **Triage, Insiden, Impor, Laporan**. Utility: Status workspace dan bantuan hanya jika benar-benar ada isinya. Jangan menambahkan halaman placeholder Settings.
- Satu workspace/tenant switcher yang persisten. All tenants adalah mode lintas-scope yang eksplisit; export dan incident actions selalu menampilkan scope.
- Jangan menambahkan Overview sebagai landing default. Returning analyst masuk ke Triage; workspace tanpa alert memberi satu ajakan Impor di empty state.
- Grid arithmetic pada 1440px: 208 sidebar + 24 left gutter + 1184 workspace + 24 right gutter = 1440. Inspector 400px + 16px gap menyisakan 768px queue pada workspace itu; saat kolom tidak lagi terbaca, ganti master/detail menjadi satu region.

### Triage

- Title, scope/freshness, satu toolbar: Search, Review status, Filter lanjutan, Urutan, Columns/overflow.
- Saved/quick views sebagai kontrol antrean, bukan dicampur dengan selection commands.
- Kolom default: selection, waktu, severity, event/asset, source+intel ringkas, hits, review. Tenant hadir ketika lintas tenant; informasi lengkap di inspector.
- Target row 48–56px untuk dua baris ringkas. Table sticky header berada dalam scroll region kerja yang jelas, bukan nested-scroll 720px di dalam page panjang.
- First data row terlihat <=240px dari atas viewport pada 1440×900; <=280px pada 1280×720. Ini acceptance target, bukan hasil ukur redesign yang sudah dibuat.
- Inspector non-modal pada desktop cukup lebar; tabs Detail, Kejadian, Raw. Alert identity, target, rule dan waktu tetap terlihat; copy raw ditandai sensitif. Pada mobile menjadi full detail view dengan Back yang memulihkan konteks.
- Batch bar ditempatkan dalam workspace dan muncul hanya saat ada selection; tidak menutupi last row atau keyboard focus.

### Klasifikasi & korelasi

- Klasifikasi adalah bukti pendukung, bukan pengganti keputusan analis. Setiap verdict membawa label, alasan, dan sinyal; warna tidak pernah menjadi satu-satunya penyampai makna.
- Tiga verdict: **True Positive**, **False Positive**, **Perlu ditinjau**. Tiga role: **Indikator**, **Respons**, **Konteks**. Role menjelaskan fungsi event, bukan tingkat bahaya.
- **Respons aktif bukan serangan mandiri.** Event rule 651/652 ditampilkan sebagai bukti respons yang tertaut ke alert asal. Bila alert asal berada di luar scope, tampilkan sebagai “Respons tanpa alert asal” dengan verdict **Perlu ditinjau**, bukan “False Positive” atau “serangan”.
- Baris antrean tetap ringkas: severity, event/asset, source+intel, hits, review. Verdict ditampilkan sebagai badge kecil di inspector dan correlation card, bukan kolom baru yang memenuhi toolbar. Bila verdict ditambahkan ke tabel, gunakan satu kolom dengan label teks dan tooltip alasan.
- Inspector memiliki blok **“Mengapa verdict ini?”** berisi daftar sinyal: profil rule, level Wazuh, grup rule, tautan alert asal, MITRE, source IP berisiko, pengulangan. Setiap sinyal menyebut jenisnya (rule/severity/correlation/intel/volume); sinyal konteks tidak boleh berbunyi seperti bukti pasti.
- Untuk event respons, inspector menampilkan **Alert asal** (rule, deskripsi, source IP, agent) dan aksi respons (`add`/`delete`, program). Jangan menyembunyikan origin di balik tombol “raw”.
- **Correlation panel** menampilkan: judul host+rule, jumlah alert primer vs respons, source IP sebagai facet, rentang waktu, confidence, dan urutan tahapan (Pengintaian → Akses kredensial → Aktivitas administratif → Persistensi → Dampak). Tahapan adalah penjelas kronologi, bukan tuduhan.
- Source IP berputar tetap satu grup. Jangan memecah grup hanya karena IP berubah; tampilkan “3 IP sumber” sebagai facet yang dapat dibuka.
- **Context strip** hanya berisi konteks yang tersedia: known-bad IP, first occurrence, business hours, source IP type. Beri label “Konteks”, bukan “Bukti”. Dataset sintetis menunjukkan field ini tidak mengubah label; UI tidak boleh mengklaim kausalitas.
- Empty state: “Belum ada hasil korelasi” dengan ajakan memperluas scope atau memilih filter; jangan menampilkan kartu kosong. Error: “Korelasi gagal dimuat” + retry, tanpa menghapus antrean.
- Wording: “Tidak ada deteksi pada cache”, “Belum ada cache”, “Perlu ditinjau”, “Respons aktif tertaut”. Dilarang: “Clean”, “Aman”, “Safe”, “False positive” tanpa alasan yang terlihat.
- Acceptance: pada 1440×900, inspector dapat menampilkan origin + tiga sinyal pertama tanpa scroll halaman; correlation panel tidak menyebabkan horizontal page overflow; 200% zoom tetap mempertahankan tombol tutup, tautan origin, dan aksi “Tinjau sebagai insiden”; keyboard dapat mencapai badge, daftar sinyal, dan tautan origin.

### Insiden

- Index berupa list yang dapat diurutkan, bukan kartu besar untuk setiap kasus.
- Detail merupakan halaman: heading identitas/severity/status, Summary, Evidence/chronology, Analysis, Conclusion, Recommendation. Satu save model eksplisit per form, dirty-state guard, saved/error feedback.
- Triage chronology dan dedup berada dekat bukti, bukan di halaman duplikat yang memaksa context switch.

### Impor dan Laporan

- Impor: satu route, mode file/paste, validasi, commit, hasil. File dan paste tidak menjadi dua halaman.
- Laporan: scope yang eksplisit + preview dokumen + satu menu format export. Bukan lima tombol global pada setiap layar.
- Tidak menampilkan history impor/export yang tidak disimpan backend. Tidak memberi progress percentage yang tidak dapat diukur server.

### Responsive

- 768–1099px: sidebar dilipat; toolbar ringkas; inspector menempati region detail, bukan memaksa dua pane sempit.
- <768px: header 48px dengan menu, search dan Filter sheet; alert ditampilkan sebagai list dua baris. Full raw/table tersedia melalui detail, bukan dipotong diam-diam.
- 320/375/390/414px: tidak ada horizontal page overflow; hit target minimal 44×44px. Tabel teknis boleh scroll hanya di region lokal dengan label dan keyboard access.
- 200% zoom tidak kehilangan action; teks panjang, translation, banyak tenant dan banyak kasus tidak menambah baris toolbar tak terbatas.

## Elevation & Depth

Flat surfaces dan structural hairlines. Shadow hanya pada menu/popover yang benar-benar melayang. Tidak ada backdrop blur untuk inspector operasional. Modal hanya untuk konfirmasi destruktif atau keputusan yang benar-benar blocking; dialog memakai semantics, focus trap, Escape, dan return-focus.

## Shapes

Control radius 4px; standalone panel radius 8px. Hindari kotak bersarang berulang. Brand memakai wordmark Arbiter yang tenang; tidak perlu gradient letter tile baru sebagai pengganti identitas.

## Components

Reusable: AppShell, WorkspaceSwitcher, PageHeader, QueueToolbar, FilterSheet, AlertTable/AlertList, SeverityLabel, IntelSummary, VerdictBadge, RoleLabel, EvidenceSignals, OriginAlertLink, CorrelationChain, ContextStrip, AlertInspector, SelectionToolbar, IncidentEditor, EvidenceTimeline, ImportPanel, ExportMenu, InlineStatus, EmptyState, SkeletonRows, ErrorRegion.

Semua control punya default, hover, focus-visible, active, disabled, pending, success dan error jika state relevan. Disabled harus punya alasan. Pending action mencegah double-submit; gagal tidak menghapus input. Async feedback diumumkan via live region, bukan hanya warna toast.

Motion: press feedback 100–120ms; menu 120–160ms; inspector 180–220ms dengan ease-out `cubic-bezier(0.23, 1, 0.32, 1)`. Keyboard navigation/filter/row selection instan. Reduced-motion menghilangkan travel; focus ring selalu instan. Jangan memakai `transition: all`.

## Do's and Don'ts

- Pisahkan route menurut pekerjaan, module menurut domain; jangan menggandakan file/paste, single/batch triage, atau chronology sebagai app baru.
- Simpan filter/sort/pagination/inspector identity di URL; selection tenant-scoped di state tersendiri. Back memulihkan scroll dan filter.
- Poll tidak merender ulang selection aktif, editor, atau focus. Tampilkan “Ada pembaruan” dan apply dengan aman.
- Semua export menyebut tenant, selected IDs/case, rentang/filter, dan jumlah actual. Tidak ada silent fallback ke seluruh database atau pemotongan 500 alert.
- Jangan menyebut sanitized text “Aman AI Cloud” secara absolut. Label “Salin versi tersamarkan” + review sebelum sharing; redaction bukan jaminan hilangnya semua informasi sensitif.
- Raw telemetry tidak masuk localStorage, screenshot demo, analytics, eksternal URL, error console, atau third-party resource.
- Jangan mengklaim live sync tanpa health check sukses; offline/error/missing-cache bukan state sukses.
