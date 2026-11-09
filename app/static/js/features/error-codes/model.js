export const ERROR_CODE_CATEGORIES = [
  ['all', 'Semua'],
  ['1xx', '1xx Informational'],
  ['2xx', '2xx Success'],
  ['3xx', '3xx Redirection'],
  ['4xx', '4xx Client Error'],
  ['5xx', '5xx Server Error'],
  ['vendor', 'Nonstandard / Vendor'],
];

export const ERROR_CODE_SECTIONS = [
  {
    id: '1xx',
    group: '1xx',
    title: '1xx Informational Response',
    subtitle: 'Respons informasional menandakan request telah diterima dan sedang diproses. Tidak memiliki body pesan.',
    items: [
      {
        code: '100',
        name: 'Continue',
        description: 'Server telah menerima request header dan klien dapat melanjutkan mengirim request body (mis. pada request POST besar yang mengirim header Expect: 100-continue). Jika ditolak, server mengembalikan 403/405 atau 417 Expectation Failed.',
      },
      {
        code: '101',
        name: 'Switching Protocols',
        description: 'Klien meminta server berganti protokol (contoh: upgrade HTTP ke WebSocket) dan server menyetujuinya.',
      },
      {
        code: '102',
        name: 'Processing (WebDAV; RFC 2518)',
        description: 'Request WebDAV dapat melibatkan banyak sub-request operasi file yang memakan waktu lama. Kode ini memberi tahu klien bahwa request sedang diproses agar tidak mengalami timeout (deprecated).',
      },
      {
        code: '103',
        name: 'Early Hints (RFC 8297)',
        description: 'Digunakan untuk mengembalikan beberapa response header (seperti Link preload) sebelum pesan HTTP final selesai disiapkan.',
      },
    ],
  },
  {
    id: '2xx',
    group: '2xx',
    title: '2xx Success',
    subtitle: 'Menandakan bahwa tindakan yang diminta klien telah diterima, dipahami, dan disetujui.',
    items: [
      {
        code: '200',
        name: 'OK',
        description: 'Respons standar untuk request HTTP yang berhasil. Pada GET berisi resource yang diminta; pada POST berisi hasil dari aksi.',
      },
      {
        code: '201',
        name: 'Created',
        description: 'Request telah terpenuhi dan menghasilkan pembuatan resource baru di server.',
      },
      {
        code: '202',
        name: 'Accepted',
        description: 'Request telah diterima untuk diproses, namun pemrosesannya belum selesai (asinkron).',
      },
      {
        code: '203',
        name: 'Non-Authoritative Information (since HTTP/1.1)',
        description: 'Server bertindak sebagai transforming proxy (mis. Web accelerator) yang menerima 200 OK dari origin tetapi mengembalikan versi respons yang telah dimodifikasi.',
      },
      {
        code: '204',
        name: 'No Content',
        description: 'Server berhasil memproses request dan tidak mengembalikan konten apa pun.',
      },
      {
        code: '205',
        name: 'Reset Content',
        description: 'Server berhasil memproses request, tidak mengembalikan konten, dan meminta klien me-reset tampilan dokumen/form.',
      },
      {
        code: '206',
        name: 'Partial Content',
        description: 'Server hanya mengirimkan sebagian dari resource (byte serving) sesuai header Range yang dikirim klien (untuk melanjutkan unduhan terputus atau streaming).',
      },
      {
        code: '207',
        name: 'Multi-Status (WebDAV; RFC 4918)',
        description: 'Body pesan berformat XML dan dapat memuat beberapa kode respons terpisah sesuai jumlah sub-request yang dibuat.',
      },
      {
        code: '208',
        name: 'Already Reported (WebDAV; RFC 5842)',
        description: 'Anggota ikatan DAV telah disebutkan pada bagian sebelumnya dari respons multistatus dan tidak disertakan kembali.',
      },
      {
        code: '226',
        name: 'IM Used (RFC 3229)',
        description: 'Server telah memenuhi request untuk resource, dan respons merupakan representasi hasil dari satu atau lebih manipulasi instance.',
      },
    ],
  },
  {
    id: '3xx',
    group: '3xx',
    title: '3xx Redirection',
    subtitle: 'Klien harus melakukan tindakan tambahan (umumnya pengalihan URL / redirect) untuk menyelesaikan request.',
    items: [
      {
        code: '300',
        name: 'Multiple Choices',
        description: 'Menyediakan beberapa pilihan untuk resource yang dapat dipilih klien (mis. pilihan format video atau ekstensi file berbeda).',
      },
      {
        code: '301',
        name: 'Moved Permanently',
        description: 'Target tautan telah dipindahkan secara permanen sehingga request saat ini dan mendatang harus diarahkan ke URI baru (praktik standar untuk upgrade HTTP ke HTTPS).',
      },
      {
        code: '302',
        name: 'Found',
        description: 'Resource dapat diakses melalui URL alternatif pada header Location (pengalihan sementara / Moved Temporarily).',
      },
      {
        code: '303',
        name: 'See Other (since HTTP/1.1)',
        description: 'Mengarahkan klien untuk melakukan GET request ke lokasi URI baru pada header Location setelah memproses POST atau request non-idempoten.',
      },
      {
        code: '304',
        name: 'Not Modified',
        description: 'Resource belum dimodifikasi sejak versi yang ditentukan pada header If-Modified-Since atau If-None-Match; klien cukup memakai salinan cache.',
      },
      {
        code: '305',
        name: 'Use Proxy (since HTTP/1.1)',
        description: 'Resource hanya tersedia melalui proxy yang alamatnya tertera pada respons (banyak browser mengabaikan kode ini demi keamanan).',
      },
      {
        code: '306',
        name: 'Switch Proxy',
        description: 'Tidak lagi digunakan. Dulunya berarti request berikutnya harus memakai proxy yang ditentukan.',
      },
      {
        code: '307',
        name: 'Temporary Redirect (since HTTP/1.1)',
        description: 'Request harus diulang dengan URI lain sementara waktu, namun metode HTTP asli tidak boleh diubah (POST tetap diulang sebagai POST).',
      },
      {
        code: '308',
        name: 'Permanent Redirect',
        description: 'Request ini dan seluruh request mendatang harus diarahkan ke URI baru tanpa mengizinkan perubahan metode HTTP.',
      },
    ],
  },
  {
    id: '4xx',
    group: '4xx',
    title: '4xx Client Error',
    subtitle: 'Situasi di mana error disebabkan oleh sisi klien (sintaks salah, tidak terautentikasi, akses ditolak, atau resource tidak ada).',
    items: [
      {
        code: '400',
        name: 'Bad Request',
        description: 'Server tidak dapat atau tidak akan memproses request karena kesalahan klien (sintaks request rusak, ukuran terlalu besar, message framing tidak valid, atau routing mencurigakan seperti path traversal).',
      },
      {
        code: '401',
        name: 'Unauthorized',
        description: 'Autentikasi diperlukan namun gagal atau belum diberikan (unauthenticated). Respons menyertakan header WWW-Authenticate.',
      },
      {
        code: '402',
        name: 'Payment Required',
        description: 'Dicadangkan untuk penggunaan masa depan / pembayaran digital. Dipakai oleh Google Developers API (batas request harian terlampaui), Sipgate, Shopify (toko belum bayar), Stripe, dan Cloudflare Turnstile (saat diakses memakai cURL).',
      },
      {
        code: '403',
        name: 'Forbidden',
        description: 'Request valid tetapi server menolak tindakan karena akun tidak memiliki izin akses, directory listing dimatikan di Apache/IIS, atau permintaan diblokir WAF/aturan keamanan.',
      },
      {
        code: '404',
        name: 'Not Found',
        description: 'Resource yang diminta tidak dapat ditemukan di server saat ini.',
      },
      {
        code: '405',
        name: 'Method Not Allowed',
        description: 'Metode request tidak didukung untuk resource tersebut (mis. mengirim GET ke form yang mewajibkan POST, atau PUT ke resource read-only).',
      },
      {
        code: '406',
        name: 'Not Acceptable',
        description: 'Resource hanya mampu menghasilkan konten yang tidak dapat diterima menurut header Accept yang dikirim dalam request.',
      },
      {
        code: '407',
        name: 'Proxy Authentication Required',
        description: 'Klien harus melakukan autentikasi terlebih dahulu dengan server proxy.',
      },
      {
        code: '408',
        name: 'Request Timeout',
        description: 'Server kehabisan waktu saat menunggu request penuh dikirim oleh klien.',
      },
      {
        code: '409',
        name: 'Conflict',
        description: 'Request tidak dapat diproses karena adanya konflik dengan state resource saat ini (mis. konflik edit antar beberapa pembaruan simultan).',
      },
      {
        code: '410',
        name: 'Gone',
        description: 'Resource yang diminta sebelumnya ada tetapi kini telah dihapus secara permanen dan tidak akan tersedia lagi.',
      },
      {
        code: '411',
        name: 'Length Required',
        description: 'Request tidak mencantumkan panjang kontennya (Content-Length) yang diwajibkan oleh resource tujuan.',
      },
      {
        code: '412',
        name: 'Precondition Failed',
        description: 'Server tidak memenuhi salah satu prasyarat yang dicantumkan pemohon pada bagian request header.',
      },
      {
        code: '413',
        name: 'Content Too Large',
        description: 'Ukuran request lebih besar daripada yang bersedia atau mampu diproses oleh server (sebelumnya disebut Request Entity Too Large / Payload Too Large).',
      },
      {
        code: '414',
        name: 'URI Too Long',
        description: 'URI yang diberikan terlalu panjang untuk diproses server (sering akibat terlalu banyak data yang di-encode sebagai query-string pada request GET).',
      },
      {
        code: '415',
        name: 'Unsupported Media Type',
        description: 'Entitas request memiliki tipe media (Content-Type) yang tidak didukung oleh server atau resource tujuan.',
      },
      {
        code: '416',
        name: 'Range Not Satisfiable',
        description: 'Klien meminta sebagian porsi file (byte serving), tetapi server tidak dapat menyuplai porsi tersebut (mis. melewati akhir file).',
      },
      {
        code: '417',
        name: 'Expectation Failed',
        description: 'Server tidak dapat memenuhi persyaratan pada field request-header Expect.',
      },
      {
        code: '418',
        name: "I'm a teapot (RFC 2324, RFC 7168)",
        description: 'Didefinisikan pada RFC 2324 (Hyper Text Coffee Pot Control Protocol) sebagai lelucon April Mop IETF. Kadang digunakan sebagai respons terhadap request yang diblokir sebagai pengganti 403 Forbidden.',
      },
      {
        code: '421',
        name: 'Misdirected Request',
        description: 'Request diarahkan ke server yang tidak mampu menghasilkan respons (misalnya karena penggunaan ulang koneksi HTTP/2).',
      },
      {
        code: '422',
        name: 'Unprocessable Content',
        description: 'Request memiliki bentuk sintaks yang benar, tetapi tidak dapat diproses karena kesalahan semantik/validasi.',
      },
      {
        code: '423',
        name: 'Locked (WebDAV; RFC 4918)',
        description: 'Resource yang sedang diakses dalam keadaan terkunci (locked).',
      },
      {
        code: '424',
        name: 'Failed Dependency (WebDAV; RFC 4918)',
        description: 'Request gagal karena bergantung pada request lain dan request tersebut mengalami kegagalan (mis. PROPPATCH).',
      },
      {
        code: '425',
        name: 'Too Early (RFC 8470)',
        description: 'Menandakan bahwa server tidak bersedia mengambil risiko memproses request yang mungkin diputar ulang (replayed).',
      },
      {
        code: '426',
        name: 'Upgrade Required',
        description: 'Klien harus beralih ke protokol yang berbeda seperti TLS/1.3 sesuai yang tertera pada field header Upgrade.',
      },
      {
        code: '428',
        name: 'Precondition Required (RFC 6585)',
        description: 'Server origin mewajibkan request bersifat kondisional untuk mencegah masalah lost update saat beberapa pihak memodifikasi state secara bersamaan.',
      },
      {
        code: '429',
        name: 'Too Many Requests (RFC 6585)',
        description: 'Pengguna telah mengirim terlalu banyak request dalam rentang waktu tertentu (digunakan pada skema rate-limiting).',
      },
      {
        code: '431',
        name: 'Request Header Fields Too Large (RFC 6585)',
        description: 'Server menolak memproses request karena ukuran satu field header atau keseluruhan field header terlalu besar.',
      },
      {
        code: '451',
        name: 'Unavailable For Legal Reasons (RFC 7725)',
        description: 'Operator server menerima tuntutan hukum untuk menolak akses ke resource atau kumpulan resource yang mencakup target request.',
      },
    ],
  },
  {
    id: '5xx',
    group: '5xx',
    title: '5xx Server Error',
    subtitle: 'Menandakan server menyadari telah terjadi error atau tidak mampu menjalankan request.',
    items: [
      {
        code: '500',
        name: 'Internal Server Error',
        description: 'Pesan error umum ketika kondisi tak terduga terjadi di server dan tidak ada pesan yang lebih spesifik.',
      },
      {
        code: '501',
        name: 'Not Implemented',
        description: 'Server tidak mengenali metode request atau belum memiliki kemampuan untuk memenuhi request tersebut.',
      },
      {
        code: '502',
        name: 'Bad Gateway',
        description: 'Server bertindak sebagai gateway atau proxy dan menerima respons yang tidak valid dari server upstream.',
      },
      {
        code: '503',
        name: 'Service Unavailable',
        description: 'Server tidak dapat menangani request karena sedang mengalami kelebihan beban (overload) atau sedang dimatikan untuk pemeliharaan (maintenance).',
      },
      {
        code: '504',
        name: 'Gateway Timeout',
        description: 'Server bertindak sebagai gateway atau proxy dan tidak menerima respons tepat waktu dari server upstream.',
      },
      {
        code: '505',
        name: 'HTTP Version Not Supported',
        description: 'Server tidak mendukung versi protokol HTTP yang digunakan dalam request.',
      },
      {
        code: '506',
        name: 'Variant Also Negotiates (RFC 2295)',
        description: 'Negosiasi konten transparan untuk request mengakibatkan referensi melingkar (circular reference).',
      },
      {
        code: '507',
        name: 'Insufficient Storage (WebDAV; RFC 4918)',
        description: 'Server tidak mampu menyimpan representasi yang dibutuhkan untuk menyelesaikan request.',
      },
      {
        code: '508',
        name: 'Loop Detected (WebDAV; RFC 5842)',
        description: 'Server mendeteksi infinite loop saat memproses request WebDAV.',
      },
      {
        code: '510',
        name: 'Not Extended (RFC 2774)',
        description: 'Ekstensi lebih lanjut pada request diperlukan agar server dapat memenuhinya.',
      },
      {
        code: '511',
        name: 'Network Authentication Required (RFC 6585)',
        description: 'Klien perlu melakukan autentikasi untuk mendapatkan akses jaringan (digunakan oleh intercepting proxy atau captive portal Wi-Fi).',
      },
    ],
  },

  // ── Nonstandard / Vendor Sections (Tabel Terpisah per Layanan/Server) ───────
  {
    id: 'vendor-iis',
    group: 'vendor',
    title: 'Internet Information Services (Microsoft IIS)',
    subtitle: 'Web server Microsoft IIS memperluas ruang error 4xx untuk memberi sinyal masalah pada request klien.',
    items: [
      {
        code: '440',
        name: 'Login Time-out',
        description: 'Sesi klien telah kedaluwarsa dan pengguna harus login kembali.',
      },
      {
        code: '449',
        name: 'Retry With',
        description: 'Server tidak dapat memenuhi request karena pengguna belum memberikan informasi yang diwajibkan.',
      },
      {
        code: '450',
        name: 'Blocked by Windows Parental Controls',
        description: 'Menandakan bahwa Windows Parental Controls memblokir akses ke halaman web yang diminta.',
      },
      {
        code: '451',
        name: 'Redirect (Exchange ActiveSync)',
        description: 'Digunakan di Exchange ActiveSync ketika tersedia server yang lebih efisien atau server tidak dapat mengakses mailbox pengguna. Klien diharapkan menjalankan ulang operasi HTTP AutoDiscover.',
      },
    ],
  },
  {
    id: 'vendor-nginx',
    group: 'vendor',
    title: 'nginx',
    subtitle: 'Web server nginx memperluas ruang error 4xx untuk menandakan masalah spesifik pada request klien dan koneksi.',
    items: [
      {
        code: '444',
        name: 'No Response',
        description: 'Digunakan secara internal di nginx untuk menginstruksikan server agar tidak mengembalikan informasi apa pun ke klien dan langsung menutup koneksi TCP.',
      },
      {
        code: '494',
        name: 'Request Header Too Large',
        description: 'Klien mengirim request yang terlalu besar atau baris header yang terlalu panjang.',
      },
      {
        code: '495',
        name: 'SSL Certificate Error',
        description: 'Ekspansi dari kode 400 Bad Request, digunakan ketika klien telah memberikan sertifikat klien (client certificate) yang tidak valid.',
      },
      {
        code: '496',
        name: 'SSL Certificate Required',
        description: 'Ekspansi dari kode 400 Bad Request, digunakan ketika sertifikat klien diwajibkan tetapi tidak diberikan.',
      },
      {
        code: '497',
        name: 'HTTP Request Sent to HTTPS Port',
        description: 'Ekspansi dari kode 400 Bad Request, digunakan ketika klien membuat request HTTP biasa ke port yang sedang mendengarkan request HTTPS.',
      },
      {
        code: '499',
        name: 'Client Closed Request',
        description: 'Digunakan ketika klien telah menutup koneksi request sebelum server selesai mengirimkan respons.',
      },
    ],
  },
  {
    id: 'vendor-cloudflare',
    group: 'vendor',
    title: 'Cloudflare',
    subtitle: 'Layanan reverse proxy Cloudflare memperluas seri error 5xx untuk menandakan kendala komunikasi dengan server origin.',
    items: [
      {
        code: '520',
        name: 'Web Server Returned an Unknown Error',
        description: 'Server origin mengembalikan respons kosong, tidak dikenal, atau tidak terduga ke Cloudflare.',
      },
      {
        code: '521',
        name: 'Web Server Is Down',
        description: 'Server origin menolak koneksi dari Cloudflare (layanan web mati atau solusi keamanan di origin memblokir IP Cloudflare).',
      },
      {
        code: '522',
        name: 'Connection Timed Out',
        description: 'Cloudflare kehabisan waktu (timed out) saat menghubungi server origin.',
      },
      {
        code: '523',
        name: 'Origin Is Unreachable',
        description: 'Cloudflare tidak dapat menjangkau server origin (mis. masalah rute jaringan).',
      },
      {
        code: '524',
        name: 'A Timeout Occurred',
        description: 'Cloudflare berhasil menyelesaikan koneksi TCP ke server origin, tetapi origin tidak memberikan respons HTTP tepat waktu.',
      },
      {
        code: '525',
        name: 'SSL Handshake Failed',
        description: 'Cloudflare tidak dapat menegosiasikan SSL/TLS handshake dengan server origin.',
      },
      {
        code: '526',
        name: 'Invalid SSL Certificate',
        description: 'Cloudflare tidak dapat memvalidasi sertifikat SSL pada web server origin (juga digunakan oleh gorouter Cloud Foundry).',
      },
      {
        code: '527',
        name: 'Railgun Error (Obsolete)',
        description: 'Menandakan koneksi terputus antara Cloudflare dan server Railgun milik origin (sudah usang karena Cloudflare telah menghentikan Railgun).',
      },
      {
        code: '530',
        name: 'Origin Unavailable',
        description: 'Cloudflare tidak dapat me-resolve hostname origin sehingga gagal membangun koneksi ke server origin (body respons memuat error 1xxx).',
      },
    ],
  },
  {
    id: 'vendor-aws-elb',
    group: 'vendor',
    title: 'AWS Elastic Load Balancing',
    subtitle: 'Amazon Web Services (AWS) Elastic Load Balancing menambahkan kode khusus untuk masalah request klien atau origin server.',
    items: [
      {
        code: '000',
        name: 'HTTP/2 GOAWAY Frame',
        description: 'Dikembalikan bersama frame HTTP/2 GOAWAY jika panjang terkompresi dari salah satu header melebihi 8K byte atau jika lebih dari 10.000 request dilayani melalui satu koneksi.',
      },
      {
        code: '460',
        name: 'Client Closed Connection Before Idle Timeout',
        description: 'Klien menutup koneksi dengan load balancer sebelum periode idle timeout berakhir (biasanya ketika timeout klien lebih pendek daripada timeout Elastic Load Balancer).',
      },
      {
        code: '463',
        name: 'Too Many IP Addresses in X-Forwarded-For',
        description: 'Load balancer menerima request header X-Forwarded-For yang berisi lebih dari 30 alamat IP.',
      },
      {
        code: '464',
        name: 'Incompatible Protocol Versions',
        description: 'Versi protokol tidak kompatibel antara Klien dan server Origin.',
      },
      {
        code: '561',
        name: 'Unauthorized (IdP Error)',
        description: 'Error autentikasi yang dikembalikan oleh server yang terdaftar di load balancer; aturan listener dikonfigurasi untuk mengautentikasi pengguna tetapi Identity Provider (IdP) mengembalikan kode error.',
      },
    ],
  },
  {
    id: 'vendor-apache',
    group: 'vendor',
    title: 'Apache',
    subtitle: 'Kode tambahan yang digunakan oleh Apache HTTP Server.',
    items: [
      {
        code: '509',
        name: 'Bandwidth Limit Exceeded',
        description: 'Server telah melampaui batas bandwidth yang ditetapkan oleh administrator server; sering digunakan oleh penyedia shared hosting dan cPanel untuk membatasi bandwidth pelanggan.',
      },
    ],
  },
  {
    id: 'vendor-laravel',
    group: 'vendor',
    title: 'Laravel Framework',
    subtitle: 'Kode status khusus yang digunakan oleh Laravel PHP Framework.',
    items: [
      {
        code: '419',
        name: 'Page Expired',
        description: 'Token CSRF hilang atau telah kedaluwarsa.',
      },
    ],
  },
  {
    id: 'vendor-spring',
    group: 'vendor',
    title: 'Spring Framework',
    subtitle: 'Kode status yang digunakan oleh Spring Framework.',
    items: [
      {
        code: '420',
        name: 'Method Failure',
        description: 'Status respons deprecated yang diusulkan saat pengembangan WebDAV dan digunakan oleh Spring Framework ketika sebuah metode gagal dijalankan.',
      },
    ],
  },
  {
    id: 'vendor-twitter',
    group: 'vendor',
    title: 'Twitter',
    subtitle: 'Kode status khusus yang pernah digunakan oleh API Twitter.',
    items: [
      {
        code: '420',
        name: 'Enhance Your Calm',
        description: 'Dikembalikan oleh Twitter Search and Trends API versi 1 ketika klien terkena rate limit (versi 1.1 ke atas menggunakan kode standar 429 Too Many Requests).',
      },
    ],
  },
  {
    id: 'vendor-shopify',
    group: 'vendor',
    title: 'Shopify',
    subtitle: 'Kode status kustom yang digunakan oleh platform e-commerce Shopify.',
    items: [
      {
        code: '430',
        name: 'Request Header Fields Too Large / Shopify Security Rejection',
        description: 'Digunakan oleh Shopify ketika terlalu banyak URL diminta dalam rentang waktu tertentu (sebagai pengganti 429) atau untuk memberi sinyal bahwa request dianggap berbahaya (Security Rejection).',
      },
      {
        code: '530',
        name: 'Origin DNS Error',
        description: 'Menandakan bahwa Cloudflare tidak dapat me-resolve catatan DNS yang diminta.',
      },
      {
        code: '540',
        name: 'Temporarily Disabled',
        description: 'Menandakan bahwa endpoint yang diminta sedang dinonaktifkan sementara waktu.',
      },
      {
        code: '783',
        name: 'Unexpected Token',
        description: 'Menandakan bahwa request menyertakan kesalahan sintaks JSON.',
      },
    ],
  },
  {
    id: 'vendor-arcgis',
    group: 'vendor',
    title: 'ArcGIS Server',
    subtitle: 'Kode status autentikasi token yang digunakan oleh ArcGIS Server.',
    items: [
      {
        code: '498',
        name: 'Invalid Token',
        description: 'Menandakan token telah kedaluwarsa atau dinyatakan tidak valid.',
      },
      {
        code: '499',
        name: 'Token Required',
        description: 'Menandakan bahwa token diwajibkan namun tidak dikirimkan pada request.',
      },
    ],
  },
  {
    id: 'vendor-cpanel',
    group: 'vendor',
    title: 'cPanel',
    subtitle: 'Kode status pembatasan resource akun yang digunakan oleh cPanel.',
    items: [
      {
        code: '508',
        name: 'Resource Limit Is Reached',
        description: 'Digunakan sebagai pengganti 503 ketika akun di server telah melampaui batas resource yang ditetapkan (seperti penggunaan CPU/RAM atau jumlah proses konkuren).',
      },
    ],
  },
  {
    id: 'vendor-ssllabs',
    group: 'vendor',
    title: 'SSLLabs Server Testing API (Qualys)',
    subtitle: 'Digunakan oleh Qualys pada API pengujian server SSLLabs.',
    items: [
      {
        code: '529',
        name: 'Site is Overloaded',
        description: 'Memberi sinyal bahwa situs sedang kelebihan beban dan tidak dapat memproses request pengujian.',
      },
    ],
  },
  {
    id: 'vendor-pantheon',
    group: 'vendor',
    title: 'Pantheon Systems Web Platform',
    subtitle: 'Digunakan oleh platform web Pantheon Systems.',
    items: [
      {
        code: '530',
        name: 'Site is Frozen',
        description: 'Menandakan sebuah situs yang telah dibekukan (frozen) karena tidak ada aktivitas.',
      },
    ],
  },
  {
    id: 'vendor-linkedin',
    group: 'vendor',
    title: 'LinkedIn',
    subtitle: 'Digunakan oleh web server LinkedIn.',
    items: [
      {
        code: '999',
        name: 'Request Denied',
        description: 'Terkait dengan pemblokiran akses otomatis/bot atau ketidakmampuan mengakses halaman web LinkedIn tanpa login terlebih dahulu.',
      },
    ],
  },
  {
    id: 'vendor-misc',
    group: 'vendor',
    title: 'Miscellaneous (Lainnya)',
    subtitle: 'Konvensi informal yang digunakan oleh proxy atau server HTTP tertentu.',
    items: [
      {
        code: '218',
        name: 'This is fine',
        description: 'Kondisi error catch-all informal yang sering dikaitkan dengan Apache HTTP Server untuk mengizinkan lewatnya message body ketika pengaturan ProxyErrorOverride diaktifkan.',
      },
      {
        code: '598',
        name: 'Network Read Timeout Error',
        description: 'Konvensi informal yang digunakan oleh beberapa HTTP proxy untuk memberi sinyal terjadinya network read timeout di belakang proxy kepada klien di depan proxy.',
      },
      {
        code: '599',
        name: 'Network Connect Timeout Error',
        description: 'Error yang digunakan oleh beberapa HTTP proxy untuk memberi sinyal terjadinya network connect timeout di belakang proxy kepada klien di depan proxy.',
      },
    ],
  },
];

export const ERROR_CODES = ERROR_CODE_SECTIONS.flatMap(section =>
  section.items.map(item => ({
    ...item,
    category: section.group,
    sectionId: section.id,
    sectionTitle: section.title,
  }))
);

export function filterErrorCodeSections(sections = ERROR_CODE_SECTIONS, {category = 'all', q = ''} = {}) {
  const cat = String(category || 'all').trim().toLowerCase();
  const needle = String(q || '').trim().toLowerCase();
  const result = [];
  for (const section of sections) {
    if (cat !== 'all' && String(section.group).toLowerCase() !== cat) continue;
    const matchedItems = !needle
      ? section.items
      : section.items.filter(item => {
          const hay = `${item.code} ${item.name} ${section.title} ${section.subtitle} ${item.description}`.toLowerCase();
          return hay.includes(needle);
        });
    if (matchedItems.length) {
      result.push({...section, items: matchedItems});
    }
  }
  return result;
}

export function filterErrorCodes(items = ERROR_CODES, {category = 'all', q = ''} = {}) {
  const cat = String(category || 'all').trim().toLowerCase();
  const needle = String(q || '').trim().toLowerCase();
  return items.filter(item => {
    if (cat !== 'all' && String(item.category).toLowerCase() !== cat) return false;
    if (!needle) return true;
    const hay = `${item.code} ${item.name} ${item.sectionTitle || ''} ${item.description}`.toLowerCase();
    return hay.includes(needle);
  });
}
