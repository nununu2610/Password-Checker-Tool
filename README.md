#  Password Strength Checker Tool

Một công cụ kiểm tra độ mạnh mật khẩu (Password Strength Checker) được xây dựng bằng **Python (Flask)** cho backend và **HTML/CSS/JS** cho frontend.  
Dự án này giúp người dùng kiểm tra mức độ an toàn của mật khẩu dựa trên **entropy**, **độ dài**, **tính đa dạng ký tự**, và kiểm tra với **cơ sở dữ liệu rò rỉ mật khẩu (Have I Been Pwned API)**.

---

##  Tính năng

- Đánh giá độ mạnh mật khẩu dựa trên entropy.  
- Kiểm tra độ dài, sự kết hợp chữ hoa, chữ thường, số, ký tự đặc biệt.  
- Tích hợp API **Have I Been Pwned** để xem mật khẩu có từng bị lộ hay chưa.  
- Giao diện trực quan, người dùng nhập mật khẩu và nhận kết quả ngay lập tức.  
- Có **unit test** để đảm bảo độ chính xác của logic kiểm tra.

---

##  Công nghệ sử dụng

- **Python 3.13**, **Flask** (Backend)  
- **HTML, CSS, JavaScript** (Frontend)  
- **Pytest** (Testing)  
- **Have I Been Pwned API** (Bảo mật & Kiểm tra rò rỉ)

---

