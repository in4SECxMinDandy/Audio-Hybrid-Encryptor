"""
=============================================================================
  AUDIO HYBRID ENCRYPTION/DECRYPTION APPLICATION (RSA + AES-256-GCM)
=============================================================================
  Tác giả: Chuyên gia Bảo mật & Lập trình Python
  Mô tả:
    Ứng dụng GUI (Tkinter) cho phép mã hóa và giải mã file audio
    sử dụng kiến trúc Mã hóa Lai (Hybrid Encryption):
      - AES-256-GCM: mã hóa nội dung file audio (nhanh, bảo mật cao)
      - RSA-OAEP (SHA-256): mã hóa khóa AES (bảo mật khóa đối xứng)

  Quy trình mã hóa:
    1. Tạo khóa AES-256 ngẫu nhiên (32 bytes)
    2. Tạo IV/nonce ngẫu nhiên (12 bytes) cho AES-GCM
    3. Mã hóa nội dung file audio bằng AES-256-GCM
    4. Mã hóa khóa AES bằng RSA Public Key (OAEP + SHA-256)
    5. Lưu file .enc với cấu trúc:
       [RSA_ENC_KEY_LEN (2 bytes)] [RSA_ENC_KEY] [IV (12 bytes)] [TAG (16 bytes)] [CIPHERTEXT]

  Quy trình giải mã:
    1. Đọc file .enc, tách các thành phần
    2. Dùng RSA Private Key giải mã lấy khóa AES
    3. Dùng khóa AES + IV + Tag để giải mã và xác thực nội dung audio

  Thư viện cần cài đặt:
    pip install cryptography

  Chạy chương trình:
    python audio_encryptor.py
=============================================================================
"""

import os
import sys
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# =============================================================================
#  IMPORT THƯ VIỆN MÃ HÓA
# =============================================================================
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("=" * 60)
    print("  LỖI: Chưa cài đặt thư viện 'cryptography'")
    print("  Hãy chạy lệnh: pip install cryptography")
    print("=" * 60)
    sys.exit(1)


# =============================================================================
#  MODULE MÃ HÓA CORE (Crypto Engine)
# =============================================================================

class CryptoEngine:
    """
    Module xử lý mã hóa lai (Hybrid Encryption) kết hợp RSA và AES-256-GCM.
    
    Thiết kế tuân thủ các best practices:
    - RSA-OAEP với SHA-256 (chống chosen-ciphertext attack)
    - AES-256-GCM (authenticated encryption - đảm bảo tính toàn vẹn + bí mật)
    - Nonce 12 bytes ngẫu nhiên cho mỗi lần mã hóa (đúng chuẩn GCM)
    - Khóa RSA tối thiểu 2048-bit (khuyến nghị 4096-bit)
    """

    # Kích thước khóa AES (256-bit = 32 bytes)
    AES_KEY_SIZE = 32
    # Kích thước nonce cho AES-GCM (12 bytes theo khuyến nghị NIST)
    AES_GCM_NONCE_SIZE = 12

    # -------------------------------------------------------------------------
    #  1. TẠO CẶP KHÓA RSA
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_rsa_keypair(key_size=4096):
        """
        Tạo cặp khóa RSA (Public Key + Private Key).
        
        Args:
            key_size: Độ dài khóa RSA (mặc định 4096-bit cho bảo mật cao)
        
        Returns:
            tuple: (private_key, public_key) - các đối tượng khóa RSA
        """
        # Tạo Private Key với public_exponent=65537 (chuẩn F4)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        # Trích xuất Public Key từ Private Key
        public_key = private_key.public_key()
        return private_key, public_key

    # -------------------------------------------------------------------------
    #  2. LƯU KHÓA RA FILE .PEM
    # -------------------------------------------------------------------------
    @staticmethod
    def save_private_key(private_key, filepath, passphrase=None):
        """
        Lưu Private Key ra file .pem (có thể mã hóa bằng passphrase).
        
        Args:
            private_key: Đối tượng RSA Private Key
            filepath: Đường dẫn file .pem
            passphrase: Mật khẩu bảo vệ Private Key (bytes hoặc None)
        """
        # Nếu có passphrase, mã hóa Private Key bằng AES-256-CBC
        if passphrase:
            encryption = serialization.BestAvailableEncryption(
                passphrase if isinstance(passphrase, bytes) else passphrase.encode('utf-8')
            )
        else:
            encryption = serialization.NoEncryption()

        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        with open(filepath, 'wb') as f:
            f.write(pem_data)

    @staticmethod
    def save_public_key(public_key, filepath):
        """
        Lưu Public Key ra file .pem.
        
        Args:
            public_key: Đối tượng RSA Public Key
            filepath: Đường dẫn file .pem
        """
        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, 'wb') as f:
            f.write(pem_data)

    # -------------------------------------------------------------------------
    #  3. ĐỌC KHÓA TỪ FILE .PEM
    # -------------------------------------------------------------------------
    @staticmethod
    def load_public_key(filepath):
        """
        Đọc Public Key từ file .pem.
        
        Args:
            filepath: Đường dẫn file .pem chứa Public Key
        
        Returns:
            Đối tượng RSA Public Key
        
        Raises:
            ValueError: Nếu file không chứa Public Key hợp lệ
        """
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        try:
            public_key = serialization.load_pem_public_key(
                pem_data, backend=default_backend()
            )
            return public_key
        except Exception as e:
            raise ValueError(f"File không chứa Public Key hợp lệ: {e}")

    @staticmethod
    def load_private_key(filepath, passphrase=None):
        """
        Đọc Private Key từ file .pem.
        
        Args:
            filepath: Đường dẫn file .pem chứa Private Key
            passphrase: Mật khẩu (nếu Private Key đã được mã hóa)
        
        Returns:
            Đối tượng RSA Private Key
        
        Raises:
            ValueError: Nếu file không chứa Private Key hợp lệ hoặc sai passphrase
        """
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        try:
            pwd = None
            if passphrase:
                pwd = passphrase if isinstance(passphrase, bytes) else passphrase.encode('utf-8')
            private_key = serialization.load_pem_private_key(
                pem_data, password=pwd, backend=default_backend()
            )
            return private_key
        except Exception as e:
            raise ValueError(f"Không thể đọc Private Key (sai passphrase hoặc file không hợp lệ): {e}")

    # -------------------------------------------------------------------------
    #  4. MÃ HÓA FILE AUDIO (Hybrid Encryption)
    # -------------------------------------------------------------------------
    @staticmethod
    def encrypt_file(input_path, output_path, public_key, progress_callback=None):
        """
        Mã hóa file audio sử dụng Hybrid Encryption (AES-256-GCM + RSA-OAEP).
        
        Quy trình:
          1. Tạo khóa AES-256 ngẫu nhiên (32 bytes)
          2. Tạo nonce ngẫu nhiên (12 bytes)
          3. Đọc toàn bộ nội dung file audio
          4. Mã hóa nội dung bằng AES-256-GCM → ciphertext (bao gồm tag 16 bytes ở cuối)
          5. Mã hóa khóa AES bằng RSA Public Key (OAEP + SHA-256)
          6. Ghi file output với cấu trúc:
             [2 bytes: độ dài RSA encrypted key]
             [RSA encrypted key]
             [12 bytes: nonce]
             [ciphertext + tag (AES-GCM tự động nối tag vào cuối ciphertext)]
        
        Args:
            input_path: Đường dẫn file audio gốc
            output_path: Đường dẫn file .enc đầu ra
            public_key: Đối tượng RSA Public Key
            progress_callback: Hàm callback để cập nhật tiến trình (optional)
        """
        if progress_callback:
            progress_callback("Đang tạo khóa AES-256 ngẫu nhiên...")

        # Bước 1: Tạo khóa AES-256 ngẫu nhiên
        aes_key = os.urandom(CryptoEngine.AES_KEY_SIZE)  # 32 bytes = 256-bit

        # Bước 2: Tạo nonce ngẫu nhiên cho AES-GCM
        nonce = os.urandom(CryptoEngine.AES_GCM_NONCE_SIZE)  # 12 bytes

        if progress_callback:
            progress_callback("Đang đọc file audio...")

        # Bước 3: Đọc nội dung file audio
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        file_size_mb = len(plaintext) / (1024 * 1024)
        if progress_callback:
            progress_callback(f"Đang mã hóa {file_size_mb:.2f} MB bằng AES-256-GCM...")

        # Bước 4: Mã hóa nội dung bằng AES-256-GCM
        # AESGCM.encrypt() trả về ciphertext + authentication tag (16 bytes)
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        if progress_callback:
            progress_callback("Đang mã hóa khóa AES bằng RSA Public Key (OAEP + SHA-256)...")

        # Bước 5: Mã hóa khóa AES bằng RSA-OAEP
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if progress_callback:
            progress_callback("Đang ghi file mã hóa...")

        # Bước 6: Ghi file đầu ra
        # Cấu trúc: [key_len (2 bytes)] [encrypted_aes_key] [nonce (12 bytes)] [ciphertext+tag]
        with open(output_path, 'wb') as f:
            # Ghi độ dài của encrypted AES key (2 bytes, big-endian)
            f.write(struct.pack('>H', len(encrypted_aes_key)))
            # Ghi encrypted AES key
            f.write(encrypted_aes_key)
            # Ghi nonce (12 bytes)
            f.write(nonce)
            # Ghi ciphertext + authentication tag
            f.write(ciphertext_with_tag)

        if progress_callback:
            progress_callback(
                f"✔ Mã hóa thành công!\n"
                f"   File gốc: {file_size_mb:.2f} MB\n"
                f"   File mã hóa: {os.path.getsize(output_path) / (1024*1024):.2f} MB\n"
                f"   Thuật toán: AES-256-GCM + RSA-OAEP (SHA-256)"
            )

    # -------------------------------------------------------------------------
    #  5. GIẢI MÃ FILE AUDIO (Hybrid Decryption)
    # -------------------------------------------------------------------------
    @staticmethod
    def decrypt_file(input_path, output_path, private_key, progress_callback=None):
        """
        Giải mã file .enc về file audio gốc.
        
        Quy trình:
          1. Đọc file .enc, tách các thành phần theo cấu trúc
          2. Dùng RSA Private Key giải mã khóa AES
          3. Dùng khóa AES + nonce để giải mã và xác thực nội dung
        
        Args:
            input_path: Đường dẫn file .enc
            output_path: Đường dẫn file audio đầu ra
            private_key: Đối tượng RSA Private Key
            progress_callback: Hàm callback để cập nhật tiến trình (optional)
        
        Raises:
            ValueError: Nếu file không đúng định dạng hoặc khóa sai
        """
        if progress_callback:
            progress_callback("Đang đọc file mã hóa...")

        with open(input_path, 'rb') as f:
            data = f.read()

        # Bước 1: Tách các thành phần từ file .enc
        if len(data) < 2:
            raise ValueError("File mã hóa quá ngắn hoặc không đúng định dạng.")

        # Đọc độ dài encrypted AES key (2 bytes đầu tiên)
        enc_key_len = struct.unpack('>H', data[:2])[0]
        offset = 2

        # Kiểm tra kích thước file hợp lệ
        # Tối thiểu cần: 2 + enc_key_len + 12 (nonce) + 16 (tag) bytes
        min_size = 2 + enc_key_len + CryptoEngine.AES_GCM_NONCE_SIZE + 16
        if len(data) < min_size:
            raise ValueError(
                f"File mã hóa không đúng định dạng. "
                f"Kích thước tối thiểu: {min_size} bytes, thực tế: {len(data)} bytes."
            )

        # Tách encrypted AES key
        encrypted_aes_key = data[offset:offset + enc_key_len]
        offset += enc_key_len

        # Tách nonce (12 bytes)
        nonce = data[offset:offset + CryptoEngine.AES_GCM_NONCE_SIZE]
        offset += CryptoEngine.AES_GCM_NONCE_SIZE

        # Phần còn lại là ciphertext + tag
        ciphertext_with_tag = data[offset:]

        if progress_callback:
            progress_callback("Đang giải mã khóa AES bằng RSA Private Key...")

        # Bước 2: Giải mã khóa AES bằng RSA-OAEP
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            raise ValueError(
                "Không thể giải mã khóa AES. Nguyên nhân có thể:\n"
                "  - Private Key không khớp với Public Key đã dùng để mã hóa\n"
                "  - File .enc bị hỏng hoặc đã bị chỉnh sửa"
            )

        file_size_mb = len(ciphertext_with_tag) / (1024 * 1024)
        if progress_callback:
            progress_callback(f"Đang giải mã {file_size_mb:.2f} MB bằng AES-256-GCM...")

        # Bước 3: Giải mã nội dung bằng AES-256-GCM
        try:
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except Exception:
            raise ValueError(
                "Giải mã AES thất bại! Dữ liệu có thể đã bị thay đổi (authentication failed).\n"
                "AES-GCM đảm bảo tính toàn vẹn dữ liệu - nếu file bị sửa đổi, giải mã sẽ bị từ chối."
            )

        if progress_callback:
            progress_callback("Đang ghi file audio đã giải mã...")

        # Ghi file audio đầu ra
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        if progress_callback:
            progress_callback(
                f"✔ Giải mã thành công!\n"
                f"   File giải mã: {len(plaintext) / (1024*1024):.2f} MB\n"
                f"   Tính toàn vẹn: Đã xác thực (GCM Authentication Tag hợp lệ)"
            )


# =============================================================================
#  GIAO DIỆN NGƯỜI DÙNG (GUI) - Tkinter
# =============================================================================

class AudioEncryptorApp:
    """
    Giao diện đồ họa chính cho ứng dụng mã hóa/giải mã file audio.
    
    Bố cục giao diện:
    ┌──────────────────────────────────────────────┐
    │           TIÊU ĐỀ ỨNG DỤNG                  │
    ├──────────────────────────────────────────────┤
    │  [Khung 1: Quản lý khóa RSA]                │
    │    ○ Tạo bộ khóa RSA (2048/4096-bit)        │
    │    ○ Chọn Public Key (.pem)                  │
    │    ○ Chọn Private Key (.pem)                 │
    ├──────────────────────────────────────────────┤
    │  [Khung 2: Mã hóa Audio]                    │
    │    ○ Chọn file audio → Mã hóa → Lưu .enc   │
    ├──────────────────────────────────────────────┤
    │  [Khung 3: Giải mã Audio]                   │
    │    ○ Chọn file .enc → Giải mã → Lưu audio   │
    ├──────────────────────────────────────────────┤
    │  [Khung 4: Nhật ký trạng thái]              │
    │    ○ Hiển thị thông báo, lỗi, tiến trình    │
    └──────────────────────────────────────────────┘
    """

    # Định nghĩa các đuôi file audio được hỗ trợ
    AUDIO_EXTENSIONS = [
        ("Tất cả file Audio", "*.wav *.mp3 *.flac *.aac *.ogg *.wma *.m4a *.opus"),
        ("WAV files", "*.wav"),
        ("MP3 files", "*.mp3"),
        ("FLAC files", "*.flac"),
        ("AAC files", "*.aac"),
        ("OGG files", "*.ogg"),
        ("Tất cả files", "*.*"),
    ]

    def __init__(self, root):
        """Khởi tạo giao diện ứng dụng."""
        self.root = root
        self.root.title("🔐 Audio Hybrid Encryptor - RSA + AES-256-GCM")
        self.root.geometry("780x820")
        self.root.resizable(True, True)
        self.root.minsize(700, 750)

        # Biến lưu trữ đường dẫn khóa
        self.public_key_path = tk.StringVar(value="Chưa chọn")
        self.private_key_path = tk.StringVar(value="Chưa chọn")

        # Đối tượng khóa đã nạp (cache)
        self._public_key = None
        self._private_key = None

        # Crypto engine
        self.crypto = CryptoEngine()

        # Thiết lập style
        self._setup_styles()

        # Xây dựng giao diện
        self._build_gui()

        # Log khởi động
        self._log("Ứng dụng đã sẵn sàng. Hãy tạo hoặc chọn bộ khóa RSA để bắt đầu.")
        self._log("Kiến trúc: Hybrid Encryption (AES-256-GCM + RSA-OAEP SHA-256)")

    # -------------------------------------------------------------------------
    #  THIẾT LẬP STYLE
    # -------------------------------------------------------------------------
    def _setup_styles(self):
        """Cấu hình style cho các widget."""
        style = ttk.Style()
        style.theme_use('clam')  # Theme hiện đại hơn default

        # Style cho các nút chính
        style.configure('Action.TButton', font=('Segoe UI', 10, 'bold'), padding=6)
        style.configure('Generate.TButton', font=('Segoe UI', 10, 'bold'), padding=8)
        
        # Style cho Label
        style.configure('Header.TLabel', font=('Segoe UI', 11, 'bold'))
        style.configure('Path.TLabel', font=('Segoe UI', 9), foreground='#555555')
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground='#1a5276')

        # Style cho LabelFrame
        style.configure('Card.TLabelframe', padding=10)
        style.configure('Card.TLabelframe.Label', font=('Segoe UI', 11, 'bold'), foreground='#2c3e50')

    # -------------------------------------------------------------------------
    #  XÂY DỰNG GIAO DIỆN
    # -------------------------------------------------------------------------
    def _build_gui(self):
        """Xây dựng toàn bộ giao diện ứng dụng."""
        # Container chính với padding
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- TIÊU ĐỀ ---
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(
            title_frame,
            text="Audio Hybrid Encryptor",
            style='Title.TLabel'
        ).pack(side=tk.LEFT)
        ttk.Label(
            title_frame,
            text="RSA-4096 + AES-256-GCM",
            font=('Segoe UI', 10),
            foreground='#7f8c8d'
        ).pack(side=tk.RIGHT, pady=5)

        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=5)

        # --- KHUNG 1: QUẢN LÝ KHÓA RSA ---
        key_frame = ttk.LabelFrame(
            main_frame,
            text="  1. Quản lý Khóa RSA  ",
            style='Card.TLabelframe'
        )
        key_frame.pack(fill=tk.X, pady=5)

        # Hàng 1: Nút tạo khóa + lựa chọn kích thước
        gen_row = ttk.Frame(key_frame)
        gen_row.pack(fill=tk.X, pady=3)

        ttk.Label(gen_row, text="Kích thước khóa:").pack(side=tk.LEFT, padx=(0, 5))
        self.key_size_var = tk.StringVar(value="4096")
        key_size_combo = ttk.Combobox(
            gen_row, textvariable=self.key_size_var,
            values=["2048", "3072", "4096"],
            width=6, state='readonly'
        )
        key_size_combo.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Button(
            gen_row, text="Tạo bộ khóa RSA",
            style='Generate.TButton',
            command=self._generate_keys
        ).pack(side=tk.LEFT, padx=5)

        ttk.Label(
            gen_row,
            text="(Lưu Public Key + Private Key ra file .pem)",
            foreground='#7f8c8d', font=('Segoe UI', 9)
        ).pack(side=tk.LEFT, padx=10)

        # Hàng 2: Chọn Public Key
        pub_row = ttk.Frame(key_frame)
        pub_row.pack(fill=tk.X, pady=3)
        ttk.Button(
            pub_row, text="Chọn Public Key",
            style='Action.TButton', width=18,
            command=self._select_public_key
        ).pack(side=tk.LEFT, padx=5)
        ttk.Label(
            pub_row, textvariable=self.public_key_path,
            style='Path.TLabel', wraplength=500
        ).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # Hàng 3: Chọn Private Key
        priv_row = ttk.Frame(key_frame)
        priv_row.pack(fill=tk.X, pady=3)
        ttk.Button(
            priv_row, text="Chọn Private Key",
            style='Action.TButton', width=18,
            command=self._select_private_key
        ).pack(side=tk.LEFT, padx=5)
        ttk.Label(
            priv_row, textvariable=self.private_key_path,
            style='Path.TLabel', wraplength=500
        ).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # --- KHUNG 2: MÃ HÓA AUDIO ---
        enc_frame = ttk.LabelFrame(
            main_frame,
            text="  2. Mã hóa Audio  ",
            style='Card.TLabelframe'
        )
        enc_frame.pack(fill=tk.X, pady=5)

        enc_desc = ttk.Label(
            enc_frame,
            text="Chọn file audio → Mã hóa bằng AES-256-GCM → Khóa AES được bảo vệ bởi RSA Public Key",
            foreground='#555555', font=('Segoe UI', 9),
            wraplength=700
        )
        enc_desc.pack(fill=tk.X, pady=(0, 5))

        enc_btn_row = ttk.Frame(enc_frame)
        enc_btn_row.pack(fill=tk.X)

        ttk.Button(
            enc_btn_row, text="Mã hóa Audio",
            style='Generate.TButton',
            command=self._encrypt_audio
        ).pack(side=tk.LEFT, padx=5)

        self.enc_progress = ttk.Progressbar(
            enc_btn_row, mode='indeterminate', length=200
        )
        self.enc_progress.pack(side=tk.LEFT, padx=15)

        # --- KHUNG 3: GIẢI MÃ AUDIO ---
        dec_frame = ttk.LabelFrame(
            main_frame,
            text="  3. Giải mã Audio  ",
            style='Card.TLabelframe'
        )
        dec_frame.pack(fill=tk.X, pady=5)

        dec_desc = ttk.Label(
            dec_frame,
            text="Chọn file .enc → Giải mã khóa AES bằng RSA Private Key → Khôi phục file audio gốc",
            foreground='#555555', font=('Segoe UI', 9),
            wraplength=700
        )
        dec_desc.pack(fill=tk.X, pady=(0, 5))

        dec_btn_row = ttk.Frame(dec_frame)
        dec_btn_row.pack(fill=tk.X)

        ttk.Button(
            dec_btn_row, text="Giải mã Audio",
            style='Generate.TButton',
            command=self._decrypt_audio
        ).pack(side=tk.LEFT, padx=5)

        self.dec_progress = ttk.Progressbar(
            dec_btn_row, mode='indeterminate', length=200
        )
        self.dec_progress.pack(side=tk.LEFT, padx=15)

        # --- KHUNG 4: NHẬT KÝ TRẠNG THÁI ---
        log_frame = ttk.LabelFrame(
            main_frame,
            text="  4. Nhật ký trạng thái  ",
            style='Card.TLabelframe'
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Textbox hiển thị trạng thái với scrollbar
        log_container = ttk.Frame(log_frame)
        log_container.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            log_container,
            height=10,
            font=('Consolas', 10),
            bg='#1e1e2e',       # Nền tối
            fg='#cdd6f4',       # Chữ sáng
            insertbackground='#cdd6f4',
            selectbackground='#45475a',
            wrap=tk.WORD,
            state=tk.DISABLED,  # Chỉ đọc
            padx=10, pady=8,
            relief=tk.FLAT,
            borderwidth=0
        )
        scrollbar = ttk.Scrollbar(log_container, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Cấu hình tag màu cho log
        self.log_text.tag_configure('success', foreground='#a6e3a1')  # Xanh lá
        self.log_text.tag_configure('error', foreground='#f38ba8')    # Đỏ
        self.log_text.tag_configure('warning', foreground='#f9e2af')  # Vàng
        self.log_text.tag_configure('info', foreground='#89b4fa')     # Xanh dương
        self.log_text.tag_configure('separator', foreground='#585b70')

        # Nút xóa log
        ttk.Button(
            log_frame, text="Xóa nhật ký",
            command=self._clear_log
        ).pack(anchor=tk.E, pady=(5, 0))

    # -------------------------------------------------------------------------
    #  HÀM GHI LOG
    # -------------------------------------------------------------------------
    def _log(self, message, tag='info'):
        """
        Ghi thông báo vào textbox nhật ký.
        
        Args:
            message: Nội dung thông báo
            tag: Loại thông báo ('info', 'success', 'error', 'warning')
        """
        self.log_text.configure(state=tk.NORMAL)

        # Thêm prefix theo loại
        prefix_map = {
            'info':    '[INFO]    ',
            'success': '[OK]      ',
            'error':   '[LỖI]     ',
            'warning': '[CẢNH BÁO]',
        }
        prefix = prefix_map.get(tag, '[INFO]    ')
        full_message = f"{prefix} {message}\n"

        self.log_text.insert(tk.END, full_message, tag)
        self.log_text.see(tk.END)  # Auto-scroll xuống cuối
        self.log_text.configure(state=tk.DISABLED)

    def _log_separator(self):
        """Thêm đường phân cách vào log."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, "─" * 70 + "\n", 'separator')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _clear_log(self):
        """Xóa toàn bộ nhật ký."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)

    # -------------------------------------------------------------------------
    #  XỬ LÝ KHÓA RSA
    # -------------------------------------------------------------------------
    def _generate_keys(self):
        """
        Tạo cặp khóa RSA và lưu ra file .pem.
        Chạy trong thread riêng để không block GUI.
        """
        # Hỏi người dùng thư mục lưu
        save_dir = filedialog.askdirectory(
            title="Chọn thư mục lưu bộ khóa RSA"
        )
        if not save_dir:
            return

        key_size = int(self.key_size_var.get())
        self._log_separator()
        self._log(f"Đang tạo bộ khóa RSA {key_size}-bit... (có thể mất vài giây)", 'warning')

        def _generate_thread():
            """Thread tạo khóa RSA."""
            try:
                # Tạo cặp khóa
                private_key, public_key = self.crypto.generate_rsa_keypair(key_size)

                # Đường dẫn file
                pub_path = os.path.join(save_dir, "public_key.pem")
                priv_path = os.path.join(save_dir, "private_key.pem")

                # Lưu khóa
                self.crypto.save_public_key(public_key, pub_path)
                self.crypto.save_private_key(private_key, priv_path)

                # Cập nhật giao diện (phải dùng root.after vì đang trong thread khác)
                self.root.after(0, lambda: self._on_keys_generated(pub_path, priv_path, key_size))

            except Exception as e:
                self.root.after(0, lambda: self._log(f"Lỗi tạo khóa: {e}", 'error'))

        # Chạy trong thread riêng
        thread = threading.Thread(target=_generate_thread, daemon=True)
        thread.start()

    def _on_keys_generated(self, pub_path, priv_path, key_size):
        """Callback khi tạo khóa thành công."""
        self.public_key_path.set(pub_path)
        self.private_key_path.set(priv_path)

        # Nạp khóa vào bộ nhớ
        try:
            self._public_key = self.crypto.load_public_key(pub_path)
            self._private_key = self.crypto.load_private_key(priv_path)
        except Exception as e:
            self._log(f"Lỗi nạp khóa: {e}", 'error')
            return

        self._log(f"✔ Tạo bộ khóa RSA-{key_size} thành công!", 'success')
        self._log(f"   Public Key:  {pub_path}", 'success')
        self._log(f"   Private Key: {priv_path}", 'success')
        self._log(
            "⚠ LƯU Ý: Bảo mật Private Key! Không chia sẻ file private_key.pem cho bất kỳ ai.",
            'warning'
        )

    def _select_public_key(self):
        """Cho phép người dùng chọn file Public Key (.pem)."""
        filepath = filedialog.askopenfilename(
            title="Chọn file Public Key (.pem)",
            filetypes=[("PEM files", "*.pem"), ("Tất cả files", "*.*")]
        )
        if not filepath:
            return

        try:
            self._public_key = self.crypto.load_public_key(filepath)
            self.public_key_path.set(filepath)
            self._log(f"✔ Đã nạp Public Key: {filepath}", 'success')
        except ValueError as e:
            self._log(str(e), 'error')
            messagebox.showerror("Lỗi Public Key", str(e))
        except Exception as e:
            self._log(f"Lỗi đọc file: {e}", 'error')
            messagebox.showerror("Lỗi", f"Không thể đọc file:\n{e}")

    def _select_private_key(self):
        """Cho phép người dùng chọn file Private Key (.pem)."""
        filepath = filedialog.askopenfilename(
            title="Chọn file Private Key (.pem)",
            filetypes=[("PEM files", "*.pem"), ("Tất cả files", "*.*")]
        )
        if not filepath:
            return

        try:
            self._private_key = self.crypto.load_private_key(filepath)
            self.private_key_path.set(filepath)
            self._log(f"✔ Đã nạp Private Key: {filepath}", 'success')
        except ValueError as e:
            # Có thể Private Key cần passphrase
            self._log(str(e), 'error')
            # Thử hỏi passphrase
            self._ask_passphrase_and_load(filepath)
        except Exception as e:
            self._log(f"Lỗi đọc file: {e}", 'error')
            messagebox.showerror("Lỗi", f"Không thể đọc file:\n{e}")

    def _ask_passphrase_and_load(self, filepath):
        """Hỏi passphrase nếu Private Key đã được mã hóa."""
        # Tạo dialog nhỏ hỏi passphrase
        dialog = tk.Toplevel(self.root)
        dialog.title("Nhập Passphrase")
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        dialog.grab_set()  # Modal dialog

        ttk.Label(
            dialog,
            text="Private Key được bảo vệ bằng passphrase.\nVui lòng nhập passphrase:",
            font=('Segoe UI', 10)
        ).pack(pady=10)

        passphrase_var = tk.StringVar()
        entry = ttk.Entry(dialog, textvariable=passphrase_var, show='*', width=40)
        entry.pack(pady=5)
        entry.focus_set()

        def _try_load():
            passphrase = passphrase_var.get()
            try:
                self._private_key = self.crypto.load_private_key(filepath, passphrase)
                self.private_key_path.set(filepath)
                self._log(f"✔ Đã nạp Private Key (có passphrase): {filepath}", 'success')
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Sai Passphrase", str(e), parent=dialog)

        ttk.Button(dialog, text="Xác nhận", command=_try_load).pack(pady=10)
        entry.bind('<Return>', lambda e: _try_load())

    # -------------------------------------------------------------------------
    #  MÃ HÓA AUDIO
    # -------------------------------------------------------------------------
    def _encrypt_audio(self):
        """
        Quy trình mã hóa file audio:
          1. Kiểm tra đã chọn Public Key chưa
          2. Cho phép chọn file audio đầu vào
          3. Cho phép chọn đường dẫn lưu file .enc
          4. Thực hiện mã hóa trong thread riêng
        """
        # Kiểm tra Public Key
        if self._public_key is None:
            self._log("Chưa chọn Public Key! Hãy tạo hoặc chọn Public Key trước.", 'error')
            messagebox.showwarning(
                "Thiếu Public Key",
                "Bạn cần tạo bộ khóa RSA hoặc chọn Public Key (.pem) trước khi mã hóa."
            )
            return

        # Chọn file audio đầu vào
        input_path = filedialog.askopenfilename(
            title="Chọn file Audio cần mã hóa",
            filetypes=self.AUDIO_EXTENSIONS
        )
        if not input_path:
            return

        # Đề xuất tên file output
        default_name = Path(input_path).stem + ".enc"
        output_path = filedialog.asksaveasfilename(
            title="Lưu file mã hóa",
            initialfile=default_name,
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("Tất cả files", "*.*")]
        )
        if not output_path:
            return

        # Bắt đầu mã hóa trong thread riêng
        self._log_separator()
        self._log(f"Bắt đầu mã hóa: {os.path.basename(input_path)}", 'info')
        self.enc_progress.start(10)

        def _encrypt_thread():
            """Thread mã hóa file audio."""
            try:
                def progress_cb(msg):
                    self.root.after(0, lambda: self._log(msg, 'info'))

                self.crypto.encrypt_file(
                    input_path, output_path,
                    self._public_key,
                    progress_callback=progress_cb
                )
                self.root.after(0, lambda: self._on_encrypt_done(True))
            except Exception as e:
                self.root.after(0, lambda: self._on_encrypt_done(False, str(e)))

        thread = threading.Thread(target=_encrypt_thread, daemon=True)
        thread.start()

    def _on_encrypt_done(self, success, error_msg=None):
        """Callback khi mã hóa hoàn tất."""
        self.enc_progress.stop()
        if success:
            self._log("═══ MÃ HÓA HOÀN TẤT ═══", 'success')
        else:
            self._log(f"Mã hóa thất bại: {error_msg}", 'error')
            messagebox.showerror("Lỗi Mã Hóa", error_msg)

    # -------------------------------------------------------------------------
    #  GIẢI MÃ AUDIO
    # -------------------------------------------------------------------------
    def _decrypt_audio(self):
        """
        Quy trình giải mã file .enc:
          1. Kiểm tra đã chọn Private Key chưa
          2. Cho phép chọn file .enc đầu vào
          3. Cho phép chọn đường dẫn lưu file audio đầu ra
          4. Thực hiện giải mã trong thread riêng
        """
        # Kiểm tra Private Key
        if self._private_key is None:
            self._log("Chưa chọn Private Key! Hãy tạo hoặc chọn Private Key trước.", 'error')
            messagebox.showwarning(
                "Thiếu Private Key",
                "Bạn cần tạo bộ khóa RSA hoặc chọn Private Key (.pem) trước khi giải mã."
            )
            return

        # Chọn file .enc đầu vào
        input_path = filedialog.askopenfilename(
            title="Chọn file mã hóa (.enc)",
            filetypes=[("Encrypted files", "*.enc"), ("Tất cả files", "*.*")]
        )
        if not input_path:
            return

        # Đề xuất tên file output (bỏ .enc, thêm _decrypted)
        stem = Path(input_path).stem
        # Cố gắng đoán đuôi file gốc
        default_ext = ".wav"  # Mặc định
        for ext in ['.wav', '.mp3', '.flac', '.aac', '.ogg', '.wma', '.m4a']:
            if stem.lower().endswith(ext.replace('.', '_')) or stem.lower().endswith(ext[1:]):
                default_ext = ext
                break

        output_path = filedialog.asksaveasfilename(
            title="Lưu file Audio đã giải mã",
            initialfile=stem + default_ext,
            defaultextension=default_ext,
            filetypes=self.AUDIO_EXTENSIONS
        )
        if not output_path:
            return

        # Bắt đầu giải mã trong thread riêng
        self._log_separator()
        self._log(f"Bắt đầu giải mã: {os.path.basename(input_path)}", 'info')
        self.dec_progress.start(10)

        def _decrypt_thread():
            """Thread giải mã file audio."""
            try:
                def progress_cb(msg):
                    self.root.after(0, lambda: self._log(msg, 'info'))

                self.crypto.decrypt_file(
                    input_path, output_path,
                    self._private_key,
                    progress_callback=progress_cb
                )
                self.root.after(0, lambda: self._on_decrypt_done(True))
            except ValueError as e:
                self.root.after(0, lambda: self._on_decrypt_done(False, str(e)))
            except Exception as e:
                self.root.after(0, lambda: self._on_decrypt_done(False, str(e)))

        thread = threading.Thread(target=_decrypt_thread, daemon=True)
        thread.start()

    def _on_decrypt_done(self, success, error_msg=None):
        """Callback khi giải mã hoàn tất."""
        self.dec_progress.stop()
        if success:
            self._log("═══ GIẢI MÃ HOÀN TẤT ═══", 'success')
        else:
            self._log(f"Giải mã thất bại: {error_msg}", 'error')
            messagebox.showerror("Lỗi Giải Mã", error_msg)


# =============================================================================
#  ĐIỂM KHỞI CHẠY CHƯƠNG TRÌNH
# =============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = AudioEncryptorApp(root)
    root.mainloop()
