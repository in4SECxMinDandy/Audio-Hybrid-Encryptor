# Audio Hybrid Encryptor - Hướng dẫn sử dụng

## Cài đặt thư viện

```bash
pip install cryptography
```

> Thư viện `tkinter` đã có sẵn trong Python (CPython) trên mọi hệ điều hành.
> Nếu dùng Linux và thiếu tkinter, cài thêm: `sudo apt install python3-tk`

## Chạy chương trình

```bash
python audio_encryptor.py
```

## Quy trình sử dụng

### Bước 1: Tạo bộ khóa RSA
1. Chọn kích thước khóa (2048 / 3072 / 4096 bit) — khuyến nghị **4096-bit**
2. Nhấn **"Tạo bộ khóa RSA"**
3. Chọn thư mục lưu → Chương trình sẽ tạo 2 file:
   - `public_key.pem` — Khóa công khai (dùng để mã hóa)
   - `private_key.pem` — Khóa bí mật (dùng để giải mã) ⚠️ **Giữ bí mật!**

### Bước 2: Mã hóa file Audio
1. Đảm bảo đã chọn hoặc tạo **Public Key**
2. Nhấn **"Mã hóa Audio"**
3. Chọn file audio đầu vào (.wav, .mp3, .flac, .aac, .ogg, ...)
4. Chọn nơi lưu file mã hóa (.enc)
5. Chờ quá trình hoàn tất → File `.enc` chứa dữ liệu đã được mã hóa

### Bước 3: Giải mã file Audio
1. Đảm bảo đã chọn hoặc tạo **Private Key** (khớp với Public Key đã dùng)
2. Nhấn **"Giải mã Audio"**
3. Chọn file `.enc` cần giải mã
4. Chọn nơi lưu file audio đầu ra
5. Chờ quá trình hoàn tất → File audio gốc được khôi phục

## Kiến trúc Mã hóa Lai (Hybrid Encryption)

```
MÃ HÓA:
  File Audio ──► AES-256-GCM (khóa ngẫu nhiên) ──► Ciphertext
  Khóa AES   ──► RSA-OAEP (Public Key)          ──► Encrypted Key
  Output: [Encrypted Key] + [Nonce] + [Ciphertext + Auth Tag]

GIẢI MÃ:
  Encrypted Key ──► RSA-OAEP (Private Key) ──► Khóa AES
  Ciphertext    ──► AES-256-GCM (khóa AES) ──► File Audio gốc
```

## Cấu trúc file .enc

| Offset | Kích thước | Nội dung |
|--------|-----------|----------|
| 0 | 2 bytes | Độ dài encrypted AES key (big-endian) |
| 2 | N bytes | RSA-encrypted AES key (N = 256/384/512 tùy RSA key size) |
| 2+N | 12 bytes | AES-GCM nonce |
| 2+N+12 | Còn lại | AES-GCM ciphertext + 16-byte authentication tag |

## Bảo mật

- **AES-256-GCM**: Authenticated encryption — đảm bảo cả tính bí mật và toàn vẹn dữ liệu
- **RSA-OAEP (SHA-256)**: Chống chosen-ciphertext attack
- **Nonce 12 bytes ngẫu nhiên**: Đúng chuẩn NIST SP 800-38D cho GCM
- **Khóa AES mới cho mỗi file**: Forward secrecy ở mức file
