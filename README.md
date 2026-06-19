# MADEx-DNS

**Multi-Agent DNS Exfiltration Detection System**

MADEx-DNS là hệ thống phát hiện hành vi rò rỉ dữ liệu qua DNS dựa trên kiến
trúc đa tác tử và học máy. Hệ thống tiếp nhận lưu lượng từ tệp PCAP/PCAPng,
tập dữ liệu CSV hoặc quá trình bắt gói DNS trực tiếp; sau đó kết hợp ba tín
hiệu phân tích độc lập để đánh giá mức độ rủi ro của từng truy vấn.

> Đây là project học thuật phục vụ môn Lập trình mạng và AI/ML. Kết quả của hệ
> thống nên được dùng để hỗ trợ điều tra, không nên được xem là bằng chứng duy
> nhất để tự động chặn tên miền trong môi trường thực tế.

## Tính năng chính

- Đọc lưu lượng DNS từ `.pcap` và `.pcapng`.
- Chuẩn hóa dữ liệu từ PCAP hoặc CSV về cùng một cấu trúc truy vấn.
- Bắt lưu lượng DNS trực tiếp bằng `tcpdump`.
- Phân tích song song bằng ba phương pháp:
  - Shannon entropy của subdomain.
  - Random Forest dự đoán xác suất DGA.
  - TF-IDF ký tự kết hợp tìm kiếm láng giềng gần nhất trên dữ liệu lành tính.
- Tổng hợp điểm bằng luật kết hợp có trọng số và các điều kiện cảnh báo bổ sung.
- Sinh báo cáo an toàn thông tin ở định dạng Markdown.
- Dashboard FastAPI theo dõi trạng thái của từng agent theo thời gian thực.
- Lưu kết quả, báo cáo và nhật ký riêng cho từng lần chạy.

## Kiến trúc hệ thống

Pipeline gồm ba giai đoạn và bảy agent:

```text
PCAP / PCAPng / CSV / Live DNS
              |
              v
+----------------------------------------+
| Stage 1 - Thu thập và chuẩn hóa        |
| pcap_reader_agent -> dns_extractor_agent|
+----------------------------------------+
              |
              v
+----------------------------------------+
| Stage 2 - Phân tích song song          |
|                                        |
| entropy_agent                          |
| dga_classifier_agent                   |
| embedding_agent                        |
+----------------------------------------+
              |
              v
+----------------------------------------+
| Stage 3 - Tổng hợp và báo cáo          |
| orchestrator_agent -> report_agent     |
+----------------------------------------+
```

### Stage 1: Thu thập và chuẩn hóa

`pcap_reader_agent` trích xuất thông tin gói DNS UDP/TCP từ PCAP. Với DNS qua
TCP, công cụ hỗ trợ ghép lại thông điệp theo độ dài được khai báo trong luồng.
`dns_extractor_agent` tiếp tục phân tích tên miền và tạo
`data/output/dns_queries.json`.

Trong chế độ CSV, pipeline bỏ qua `pcap_reader_agent`. Tệp CSV cần tối thiểu
hai cột:

```text
domain_name,label
example.com,benign
x7k2p9.example,malicious
```

### Stage 2: Phân tích song song

Ba agent nhận cùng danh sách truy vấn và chạy đồng thời:

| Agent | Phương pháp | Đầu ra |
|---|---|---|
| `entropy_agent` | Shannon entropy trên nhãn DNS | `entropy_scores.json` |
| `dga_classifier_agent` | Random Forest với 7 đặc trưng | `dga_scores.json` |
| `embedding_agent` | TF-IDF character n-gram và cosine nearest neighbor | `embed_scores.json` |

### Stage 3: Tổng hợp và báo cáo

Các kết quả được ghép theo `query_id`. Điểm tổng hợp được tính như sau:

```text
combined_score =
    0.3 * entropy_norm
  + 0.4 * dga_score
  + 0.3 * embed_score
```

Một truy vấn được đánh dấu `suspected` khi thỏa mãn ít nhất một điều kiện:

- `combined_score >= 0.60`;
- `dga_score >= 0.75`;
- đồng thời `entropy_norm >= 0.65` và `embed_score >= 0.85`.

## Công nghệ sử dụng

- Python 3.10+
- Scapy
- pandas và NumPy
- scikit-learn
- FastAPI và Uvicorn
- WebSocket
- Pi agent/skill metadata
- tcpdump và libpcap/Npcap cho chế độ live capture

## Cấu trúc thư mục

```text
dns_exfil/
|-- .pi/
|   |-- agents/              # Mô tả vai trò của 7 agent
|   |-- prompts/             # Khai báo chuỗi thực thi pipeline
|   `-- skills/              # Hợp đồng đầu vào/đầu ra của từng công cụ
|-- data/
|   |-- input/               # PCAP, PCAPng hoặc CSV đầu vào
|   |-- output/              # Kết quả trung gian của Stage 1
|   `-- web_jobs/            # Snapshot của các job từ dashboard
|-- models/                  # Mô hình DGA và embedding đã huấn luyện
|-- outputs/                 # Kết quả Stage 2/3 theo từng lần chạy
|-- logs/                    # Nhật ký pipeline
|-- tests/                   # Kiểm thử Stage 1, 2, 3 và dashboard
|-- tools/                   # Mã nguồn xử lý chính
|-- webapp/                  # FastAPI backend và giao diện web
|-- requirements.txt
`-- README.md
```

## Cài đặt

Clone project và chuyển vào thư mục mã nguồn:

```bash
git clone <repository-url>
cd dns_exfil
```

Tạo môi trường ảo:

```bash
python -m venv .venv
```

Kích hoạt môi trường trên Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Hoặc trên Linux/macOS:

```bash
source .venv/bin/activate
```

Cài đặt thư viện:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Chuẩn bị mô hình

Pipeline cần hai tệp:

```text
models/dga_model.pkl
models/embed_model.pkl
```

Thư mục `models/` không được đưa lên Git vì các mô hình có kích thước lớn.
Nếu chưa có mô hình, hãy chuẩn bị CSV có cột `domain_name` và `label`, sau đó
tạo trực tiếp `dns_queries.json`:

```bash
python tools/dns_extractor.py data/input/merged.csv
```

Huấn luyện mô hình DGA:

```bash
python tools/train_dga_model.py data/output/dns_queries.json models/dga_model.pkl
```

Huấn luyện mô hình embedding:

```bash
python tools/embed_score.py train data/input/merged.csv models/embed_model.pkl
```

Quá trình huấn luyện DGA có thể tốn nhiều CPU, RAM và thời gian trên tập dữ
liệu lớn.

## Chạy pipeline bằng CLI

Các lệnh nên được chạy từ thư mục gốc của project.

### Phân tích PCAP

```bash
python -m tools.run_pipeline \
  --mode pcap \
  --input data/input/demo.pcap
```

Ví dụ tương đương trên PowerShell:

```powershell
python -m tools.run_pipeline `
  --mode pcap `
  --input data/input/demo.pcap
```

### Phân tích CSV

```bash
python -m tools.run_pipeline \
  --mode csv \
  --input data/input/merged.csv
```

### Bắt và phân tích DNS trực tiếp

```bash
python -m tools.run_pipeline \
  --mode live \
  --interface <interface> \
  --timeout 30 \
  --max-packets 1000
```

Live capture yêu cầu:

- Có lệnh `tcpdump` trong `PATH`.
- Có libpcap trên Linux/macOS hoặc môi trường tcpdump tương thích Npcap trên
  Windows.
- Tiến trình có quyền bắt gói tin trên card mạng.
- Bộ lọc được cố định ở lưu lượng gửi đến UDP/TCP port 53.

Xem toàn bộ tùy chọn CLI:

```bash
python -m tools.run_pipeline --help
```

## Chạy Web Dashboard

Khởi động FastAPI:

```bash
python -m uvicorn webapp.app:app --reload
```

Mở:

- Dashboard: <http://127.0.0.1:8000>
- API documentation: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/api/health>

Dashboard hỗ trợ:

- Upload `.pcap`, `.pcapng` hoặc `.csv` với dung lượng tối đa 512 MB.
- Chọn card mạng và bắt DNS trực tiếp từ 5 đến 300 giây.
- Theo dõi trạng thái của bảy agent qua WebSocket.
- Xem điểm rủi ro và báo cáo Markdown.
- Tải lại PCAP được tạo từ phiên live capture.

Do Stage 1 sử dụng các tệp đầu ra dùng chung, web job manager chủ động xử lý
mỗi lần một pipeline để tránh trộn dữ liệu giữa các job.

## Kết quả đầu ra

Mỗi lần chạy CLI tạo một thư mục:

```text
outputs/YYYYMMDD_HHMMSS_microseconds/
|-- entropy_scores.json
|-- dga_scores.json
|-- embed_scores.json
|-- scores.json
`-- exfil_report.md
```

Stage 1 ghi:

```text
data/output/raw_packets.json
data/output/dns_queries.json
```

Nhật ký thực thi được lưu trong `logs/`. Với dashboard, snapshot đầy đủ của
từng job nằm tại:

```text
data/web_jobs/<job-id>/output/
```

Một bản ghi trong `scores.json` có dạng:

```json
{
  "query_id": 1,
  "domain": "example.com",
  "label": "unknown",
  "source": "pcap",
  "entropy_score": 3.4219,
  "entropy_norm": 0.6619,
  "dga_score": 0.8125,
  "embed_score": 0.9032,
  "combined_score": 0.7944,
  "verdict": "suspected",
  "risk_reasons": [
    "combined_score_above_threshold",
    "high_dga_probability",
    "high_entropy",
    "far_from_benign_embedding",
    "entropy_embedding_agreement"
  ]
}
```

## Huấn luyện mô hình

### Mô hình DGA

`tools/train_dga_model.py` sử dụng Random Forest và bảy đặc trưng:

1. Độ dài tên miền.
2. Tỷ lệ chữ số.
3. Số lượng nhãn DNS.
4. Độ dài subdomain.
5. Tỷ lệ nguyên âm.
6. Tỷ lệ phụ âm.
7. Tỷ lệ ký tự duy nhất.

Script chia tập train/test có phân tầng, dùng `RandomizedSearchCV` với
`roc_auc`, sau đó huấn luyện lại mô hình tốt nhất trên toàn bộ tập train.

### Mô hình embedding

`tools/embed_score.py` huấn luyện hai nhánh TF-IDF character n-gram:

- Nhánh subdomain cho chuỗi đủ dài.
- Nhánh full domain làm đường dự phòng khi subdomain rỗng hoặc quá ngắn.

Điểm embedding là khoảng cách cosine đến mẫu lành tính gần nhất:

- Gần `0.0`: giống dữ liệu DNS lành tính.
- Gần `1.0`: khác xa các mẫu lành tính.

## Kiểm thử

Chạy toàn bộ test:

```bash
python -m pytest -v
```

Chạy theo từng nhóm:

```bash
python -m pytest tests/test_stage1.py -v
python -m pytest tests/test_stage2.py -v
python -m pytest tests/test_stage3.py -v
python -m pytest tests/test_web_job_manager.py -v
```

## Giới hạn hiện tại

- Hệ thống chỉ đọc DNS truyền thống trên port 53, chưa giải mã DoH hoặc DoT.
- Phát hiện dựa trên đặc trưng chuỗi và mô hình đã huấn luyện nên vẫn có thể
  sinh false positive hoặc false negative.
- Chất lượng dự đoán phụ thuộc mạnh vào dữ liệu huấn luyện và mức độ tương
  đồng với môi trường triển khai.
- Live capture phụ thuộc vào `tcpdump`, driver bắt gói và quyền hệ điều hành.
- Web dashboard xử lý tuần tự các pipeline thay vì chạy đồng thời nhiều job.
- Đây chưa phải IDS/IPS thời gian thực hoàn chỉnh và không tự động chặn lưu
  lượng mạng.

## Nhóm phát triển

Project được xây dựng cho mục đích học tập, nghiên cứu và trình diễn kiến trúc
đa tác tử trong bài toán an toàn mạng.
