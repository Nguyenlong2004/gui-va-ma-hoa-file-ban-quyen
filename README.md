# Hệ thống Gửi và Bảo vệ Tập tin Nhạc có Bản quyền

## Mô tả
Hệ thống bảo vệ bản quyền nhạc số sử dụng mã hóa lai (RSA + Triple DES) và chữ ký số để đảm bảo an toàn truyền tải và xác thực tập tin nhạc.

## Công nghệ chính
- **RSA-2048**: Mã hóa khóa phiên và tạo chữ ký số
- **Triple DES**: Mã hóa dữ liệu tập tin nhạc
- **SHA-256**: Tạo hash cho chữ ký số

## Tính năng
- ✅ Mã hóa lai tối ưu hiệu suất
- ✅ Xác thực nguồn gốc bằng chữ ký số
- ✅ Bảo vệ toàn vẹn dữ liệu
- ✅ Hỗ trợ nhiều định dạng nhạc (MP3, FLAC, WAV)

## Cài đặt
```bash
pip install -r requirements.txt
python main.py
```

## Sử dụng
```python
from music_protection import MusicProtector

# Mã hóa và ký
protector = MusicProtector()
encrypted_file = protector.encrypt_music_file("song.mp3", "recipient_pub.pem")
signature = protector.sign_file("song.mp3", "sender_private.pem")

# Giải mã và xác minh
decrypted_file = protector.decrypt_music_file("encrypted_song.enc", "recipient_private.pem")
is_valid = protector.verify_signature("song.mp3", "signature.sig", "sender_public.pem")
```

## Quy trình bảo vệ
1. **Người gửi**: Tạo khóa phiên → Mã hóa file bằng 3DES → Mã hóa khóa phiên bằng RSA → Tạo chữ ký số
2. **Người nhận**: Giải mã khóa phiên → Giải mã file → Xác minh chữ ký → Phát nhạc

## Ưu điểm
- Bảo mật cao với mã hóa lai
- Hiệu suất tối ưu cho file lớn
- Xác thực và chống chối bỏ
- Dễ tích hợp và mở rộng

## Giấy phép
MIT License
