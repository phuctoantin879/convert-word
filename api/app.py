import os
import re
import json
import base64
import hashlib
import xml.etree.ElementTree as ET
import requests
import shutil
import time
import logging
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from PyPDF2 import PdfReader
from mistralai import Mistral

app = Flask(__name__)

# Vercel dùng hệ thống tệp tạm thời, thay đổi thư mục lưu trữ
if os.environ.get('VERCEL_ENV') == 'production':
    # Sử dụng thư mục /tmp trên Vercel
    app.config['UPLOAD_FOLDER'] = '/tmp'
else:
    app.config['UPLOAD_FOLDER'] = 'uploads'
    
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size

# Tạo thư mục upload nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Cấu hình logging
if os.environ.get('VERCEL_ENV') == 'production':
    app.logger.setLevel(logging.INFO)
else:
    app.logger.setLevel(logging.DEBUG)
    
# Log handler
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
app.logger.addHandler(handler)

# Tăng thời gian timeout cho các request
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 300  # 5 phút

# Hàm tiện ích từ ứng dụng gốc (giữ nguyên các hàm này)
def load_rsa_private_key_from_xml(xml_str):
    """Tải khóa RSA riêng tư từ định dạng XML"""
    root = ET.fromstring(xml_str)
    def get_int(tag):
        text = root.find(tag).text
        return int.from_bytes(base64.b64decode(text), 'big')
    n = get_int('Modulus')
    e = get_int('Exponent')
    d = get_int('D')
    p = get_int('P')
    q = get_int('Q')
    key = RSA.construct((n, e, d, p, q))
    return key

def decrypt_api_key(encrypted_key_base64, rsa_private_key):
    """Giải mã API key đã được mã hóa"""
    try:
        cipher = PKCS1_v1_5.new(rsa_private_key)
        encrypted_data = base64.b64decode(encrypted_key_base64)
        decrypted = cipher.decrypt(encrypted_data, None)
        
        if not decrypted:
            raise ValueError("Giải mã thất bại")
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Lỗi giải mã API key: {str(e)}")

def get_mineru_token():
    """Lấy API key từ GitHub"""
    PRIVATE_KEY_XML = """<RSAKeyValue>
<Modulus>pWVItQwZ7NCPcBhSL4rqJrwh4OQquiPVtqTe4cqxO7o+UjYNzDPfLkfKAvR8k9ED4lq2TU11zEj8p2QZAM7obUlK4/HVexzfZd0qsXlCy5iaWoTQLXbVdzjvkC4mkO5TaX3Mpg/+p4oZjk1iS68tQFmju5cT19dcsPh554ICk8U=</Modulus>
<Exponent>AQAB</Exponent>
<P>0ZWwsKa9Vw9BJAsRaW4eV60i6Z+R6z9LNSgjNn4pYH2meZtGUbmJVowRv7EM5sytouB5EMru7sQbRHEQ7nrwSw==</P>
<Q>ygZQWNkUgfHhHBataXvYLxWgPB5UZTWogN8Mb33LT4rq7I5P1GX3oWtYF2AdmChX8Lq3Ms/A/jBhqYomhYOiLw==</Q>
<DP>qS9VOsTfA3Bk/VuR6rHh/JTfIgiWGnk1lOuZwVuGu0WzJWebFE3Z9+uKSFv8NjPz1w+tq0imKEhWWqGLMXg8kQ==</DP>
<DQ>UCtXQRrMB5EL6tCY+k4aCP1E+/ZxOUSk3Jcm4SuDPcp71WnYBgp8zULCz2vl8pa35yDBSFmnVXevmc7n4H3PIw==</DQ>
<InverseQ>Qm9RjBhxANWyIb8I28vjGz+Yb9CnunWxpHWbfRo1vF+Z38WB7dDgLsulAXMGrUPQTeG6K+ot5moeZ9ZcAc1Hzw==</InverseQ>
<D>F9lU9JY8HsOsCzPWlfhn7xHtqKn95z1HkcCQSuqZR82BMwWMU8efBONhI6/xTrcy4i7GXrsuozhbBiAO4ujy5qPytdFemLuqjwFTyvllkcOy3Kbe0deczxnPPCwmSMVKsYInByJoBP3JYoyVAj4bvY3UqZJtw+2u/OIOhoBe33k=</D>
</RSAKeyValue>"""
    
    try:
        rsa_private_key = load_rsa_private_key_from_xml(PRIVATE_KEY_XML)
        github_url = "https://raw.githubusercontent.com/thayphuctoan/pconvert/refs/heads/main/ocr-pdf"
        response = requests.get(github_url, timeout=10)
        response.raise_for_status()
        
        encrypted_keys = [line.strip() for line in response.text.splitlines() if line.strip()]
        if not encrypted_keys:
            raise ValueError("Không tìm thấy API key đã mã hóa")
        
        token = decrypt_api_key(encrypted_keys[0], rsa_private_key)
        if not token:
            raise ValueError("API key giải mã rỗng")
        return token
    except Exception as e:
        raise Exception(f"Lỗi lấy API key: {str(e)}")

def count_pdf_pages(file_path):
    """Đếm số trang trong file PDF"""
    try:
        with open(file_path, 'rb') as file:
            pdf = PdfReader(file)
            return len(pdf.pages)
    except Exception as e:
        app.logger.error(f"Lỗi khi đếm số trang PDF: {str(e)}")
        return -1

def check_activation(hardware_id):
    """Kiểm tra xem hardware ID có được kích hoạt không"""
    try:
        url = "https://raw.githubusercontent.com/thayphuctoan/pconvert/refs/heads/main/convert-special-1"
        response = requests.get(url, timeout=(10, 30))
        
        if response.status_code == 200:
            valid_ids = response.text.strip().split('\n')
            if hardware_id in valid_ids:
                return True
        return False
    except Exception as e:
        app.logger.error(f"Lỗi khi kiểm tra kích hoạt: {str(e)}")
        return False

def process_ocr(file_path):
    """Xử lý OCR cho file PDF"""
    try:
        # Lấy API key
        api_key = get_mineru_token()
        client = Mistral(api_key=api_key)
        
        # Upload file
        with open(file_path, 'rb') as f:
            file_content = f.read()
            
        uploaded_pdf = client.files.upload(
            file={
                "file_name": os.path.basename(file_path),
                "content": file_content,
            },
            purpose="ocr"
        )
        
        # Lấy signed URL
        signed_url = client.files.get_signed_url(file_id=uploaded_pdf.id)
        
        # Xử lý OCR
        ocr_response = client.ocr.process(
            model="mistral-ocr-latest",
            document={
                "type": "document_url",
                "document_url": signed_url.url,
            },
            include_image_base64=True
        )
        
        # Phân tích kết quả
        result_data = {
            "text": "",
            "images": {}
        }
        
        if hasattr(ocr_response, 'pages'):
            for page in ocr_response.pages:
                if hasattr(page, 'markdown') and page.markdown:
                    result_data["text"] += page.markdown + "\n\n"
                elif hasattr(page, 'text') and page.text:
                    result_data["text"] += page.text + "\n\n"
                
                if hasattr(page, 'images') and page.images:
                    for img in page.images:
                        if hasattr(img, 'id') and hasattr(img, 'image_base64'):
                            result_data["images"][img.id] = img.image_base64
        
        # Làm sạch văn bản
        cleaned_text = result_data["text"]
        cleaned_text = re.sub(r'OCRPageObject\(.*?\)', '', cleaned_text)
        cleaned_text = re.sub(r'OCRPageDimensions\(.*?\)', '', cleaned_text)
        cleaned_text = re.sub(r'images=\[\]', '', cleaned_text)
        cleaned_text = re.sub(r'index=\d+', '', cleaned_text)
        
        # Tiền xử lý
        cleaned_text = re.sub(r'(Câu\s+\d+\.?[:]?)', r'\n\n\1', cleaned_text)
        cleaned_text = re.sub(r'(Bài\s+\d+\.?[:]?)', r'\n\n\1', cleaned_text)
        cleaned_text = re.sub(r'([A-D]\.)', r'\n\1', cleaned_text)
        
        # Chuẩn hóa tham chiếu hình ảnh
        for img_id in result_data["images"].keys():
            pattern = r'!\[.*?\]\(.*?' + re.escape(img_id) + r'.*?\)'
            cleaned_text = re.sub(pattern, f'[HÌNH: {img_id}]', cleaned_text)
            
            pattern = r'!{1,2}\[' + re.escape(img_id) + r'\]'
            cleaned_text = re.sub(pattern, f'[HÌNH: {img_id}]', cleaned_text)
            
            pattern = r'(?<![a-zA-Z0-9\-\.])' + re.escape(img_id) + r'(?![a-zA-Z0-9\-\.])'
            cleaned_text = re.sub(pattern, f'[HÌNH: {img_id}]', cleaned_text)
        
        result_data["text"] = cleaned_text
        return result_data
    
    except Exception as e:
        app.logger.error(f"Lỗi trong quá trình OCR: {str(e)}")
        raise

def process_equations(text):
    """Xử lý và chuẩn hóa công thức toán học trong văn bản"""
    processed_text = text
    
    # Phát hiện và chuẩn hóa các công thức LaTeX inline
    inline_patterns = [
        (r'\$([^$]+?)\$', r'$\1$'),              # $công_thức$
        (r'\\[(]([^)]+?)\\[)]', r'$\1$'),        # \(công_thức\)
        (r'`\$([^$]+?)\$`', r'$\1$'),            # `$công_thức$`
        (r'`\\[(]([^)]+?)\\[)]`', r'$\1$')       # `\(công_thức\)`
    ]
    
    for pattern, replacement in inline_patterns:
        processed_text = re.sub(pattern, replacement, processed_text)
    
    # Phát hiện và chuẩn hóa các công thức LaTeX block
    simple_block_patterns = [
        (r'\$\$([^$]+?)\$\$', r'$$\1$$'),        # $$công_thức$$
        (r'\\[\[]([^]]+?)\\[\]]', r'$$\1$$')     # \[công_thức\]
    ]
    
    for pattern, replacement in simple_block_patterns:
        processed_text = re.sub(pattern, replacement, processed_text)
    
    # Xử lý các mẫu cần flags đặc biệt
    processed_text = re.sub(r'```math\n(.*?)\n```', r'$$\1$$', processed_text, flags=re.DOTALL)  # ```math ... ```
    processed_text = re.sub(r'```latex\n(.*?)\n```', r'$$\1$$', processed_text, flags=re.DOTALL)  # ```latex ... ```
    
    return processed_text

# Routes
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    # Kiểm tra hardware ID và kích hoạt
    hardware_id = request.form.get('hardware_id')
    if not hardware_id or not check_activation(hardware_id):
        return jsonify({
            'success': False,
            'error': 'Phần mềm chưa được kích hoạt hoặc Hardware ID không hợp lệ.'
        }), 403
    
    # Kiểm tra file
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Không có file nào được tải lên'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Chưa chọn file'}), 400
    
    if file and file.filename.lower().endswith('.pdf'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Kiểm tra số trang
        page_count = count_pdf_pages(file_path)
        if page_count > 100:
            os.remove(file_path)  # Xóa file
            return jsonify({
                'success': False, 
                'error': f'File có {page_count} trang, vượt quá giới hạn 100 trang.'
            }), 400
        elif page_count <= 0:
            os.remove(file_path)
            return jsonify({
                'success': False, 
                'error': 'Không thể đọc file PDF, vui lòng kiểm tra lại.'
            }), 400
        
        try:
            # Xử lý OCR
            result = process_ocr(file_path)
            
            # Tạo ID duy nhất cho kết quả này
            timestamp = int(time.time())
            clean_filename = os.path.splitext(filename)[0].replace(" ", "_")
            result_id = f"result_{clean_filename}_{timestamp}.json"
            
            # Lưu kết quả vào một file tạm thời để tải xuống sau này
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], result_id)
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False)
            
            # Log để debug
            app.logger.info(f"Đã lưu kết quả OCR vào file: {result_path}")
            
            # Trả về kết quả
            return jsonify({
                'success': True,
                'filename': filename,
                'page_count': page_count,
                'text': result['text'],
                'image_count': len(result['images']),
                'result_id': result_id
            })
            
        except Exception as e:
            app.logger.error(f"Lỗi khi xử lý OCR: {str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            # Xóa file tạm thời
            if os.path.exists(file_path):
                os.remove(file_path)
                
    return jsonify({'success': False, 'error': 'Loại file không được hỗ trợ, chỉ chấp nhận PDF'}), 400

@app.route('/api/hardware-id', methods=['POST'])
def get_hardware_id():
    """API để tạo hardware ID từ thông tin gửi lên"""
    data = request.json
    if not data or not all(k in data for k in ('cpu_id', 'bios_serial', 'motherboard_serial')):
        return jsonify({'success': False, 'error': 'Thiếu thông tin phần cứng'}), 400
    
    combined_info = f"{data['cpu_id']}|{data['bios_serial']}|{data['motherboard_serial']}"
    hardware_id = hashlib.md5(combined_info.encode()).hexdigest().upper()
    formatted_id = '-'.join([hardware_id[i:i+8] for i in range(0, len(hardware_id), 8)])
    formatted_id = formatted_id + "-Premium"
    
    return jsonify({
        'success': True,
        'hardware_id': formatted_id,
        'activated': check_activation(formatted_id)
    })

@app.route('/results/<result_id>', methods=['GET'])
def get_result(result_id):
    """Lấy kết quả OCR đã lưu trước đó"""
    result_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(result_id))
    
    app.logger.info(f"Đang tìm kết quả: {result_path}")
    
    if not os.path.exists(result_path):
        app.logger.error(f"Không tìm thấy kết quả tại đường dẫn: {result_path}")
        # Liệt kê các file trong thư mục để debug
        try:
            files_in_folder = os.listdir(app.config['UPLOAD_FOLDER'])
            app.logger.info(f"Các file trong thư mục: {files_in_folder}")
        except Exception as e:
            app.logger.error(f"Không thể liệt kê file trong thư mục: {str(e)}")
            
        return jsonify({'success': False, 'error': 'Không tìm thấy kết quả'}), 404
    
    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        app.logger.info(f"Đã đọc kết quả thành công với {len(result.get('images', {}))} hình ảnh")
        
        return jsonify({
            'success': True,
            'text': result['text'],
            'image_count': len(result.get('images', {})),
            'image_ids': list(result.get('images', {}).keys()) # Trả về danh sách ID hình ảnh
        })
    except Exception as e:
        app.logger.error(f"Lỗi khi đọc kết quả: {str(e)}")
        return jsonify({'success': False, 'error': f'Lỗi khi đọc kết quả: {str(e)}'}), 500

@app.route('/images/<result_id>/<image_id>', methods=['GET'])
def get_image(result_id, image_id):
    """Lấy hình ảnh từ kết quả OCR"""
    result_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(result_id))
    
    app.logger.info(f"Đang tìm kết quả để lấy hình ảnh: {result_path}, hình ảnh: {image_id}")
    
    if not os.path.exists(result_path):
        app.logger.error(f"Không tìm thấy kết quả tại đường dẫn: {result_path}")
        return jsonify({'success': False, 'error': 'Không tìm thấy kết quả'}), 404
    
    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        if image_id not in result.get('images', {}):
            app.logger.error(f"Không tìm thấy hình ảnh {image_id} trong kết quả")
            # Liệt kê các ID hình ảnh có sẵn để debug
            available_images = list(result.get('images', {}).keys())
            app.logger.info(f"Các hình ảnh có sẵn: {available_images}")
            return jsonify({'success': False, 'error': 'Không tìm thấy hình ảnh'}), 404
        
        # Lưu hình ảnh vào file tạm và gửi về
        img_data = result['images'][image_id]
        if "," in img_data:
            img_data = img_data.split(",", 1)[1]
        
        temp_img_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{result_id}_{image_id}")
        with open(temp_img_path, 'wb') as f:
            f.write(base64.b64decode(img_data))
        
        app.logger.info(f"Đã lưu hình ảnh tạm thời: {temp_img_path}")
        
        try:
            return send_file(temp_img_path, mimetype='image/jpeg')
        finally:
            # Xóa file tạm sau khi gửi xong, nhưng không gây lỗi nếu không xóa được
            try:
                if os.path.exists(temp_img_path):
                    os.remove(temp_img_path)
            except:
                app.logger.warning(f"Không thể xóa file hình ảnh tạm thời: {temp_img_path}")
    except Exception as e:
        app.logger.error(f"Lỗi khi xử lý hình ảnh: {str(e)}")
        return jsonify({'success': False, 'error': f'Lỗi khi xử lý hình ảnh: {str(e)}'}), 500

@app.route('/export/word/<result_id>', methods=['GET'])
def export_to_word(result_id):
    """Xuất kết quả OCR sang file Word với công thức toán học và hình ảnh"""
    result_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(result_id))
    
    app.logger.info(f"Đang tìm kết quả để xuất Word: {result_path}")
    
    if not os.path.exists(result_path):
        app.logger.error(f"Không tìm thấy kết quả tại đường dẫn: {result_path}")
        # Liệt kê các file trong thư mục để debug
        try:
            files_in_folder = os.listdir(app.config['UPLOAD_FOLDER'])
            app.logger.info(f"Các file trong thư mục: {files_in_folder}")
        except Exception as e:
            app.logger.error(f"Không thể liệt kê file trong thư mục: {str(e)}")
            
        return jsonify({'success': False, 'error': 'Không tìm thấy kết quả'}), 404
    
    try:
        # Đọc kết quả OCR
        with open(result_path, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        app.logger.info(f"Đã đọc kết quả thành công, bắt đầu xử lý cho Word với {len(result.get('images', {}))} hình ảnh")
        
        # Chuẩn bị nội dung markdown
        markdown_content = result['text']
        
        # Xử lý công thức toán học (nếu có)
        markdown_content = process_equations(markdown_content)
        
        # Nhúng hình ảnh vào markdown
        for img_id, base64_data in result.get('images', {}).items():
            try:
                # Làm sạch dữ liệu base64
                if "," in base64_data:
                    prefix, base64_data = base64_data.split(",", 1)
                else:
                    prefix = "data:image/jpeg;base64"
                
                # Tạo data URI
                data_uri = f"{prefix},{base64_data}"
                
                # Tạo tham chiếu hình ảnh inline trong markdown
                image_ref = f"![{img_id}]({data_uri})"
                
                # Thay thế placeholder
                placeholder = f"[HÌNH: {img_id}]"
                if placeholder in markdown_content:
                    markdown_content = markdown_content.replace(placeholder, f"\n\n{image_ref}\n\n")
                    app.logger.info(f"Đã thay thế placeholder cho hình ảnh {img_id}")
                else:
                    # Nếu không tìm thấy placeholder, thêm vào cuối
                    app.logger.warning(f"Không tìm thấy placeholder cho hình ảnh {img_id}, thêm vào cuối tài liệu")
                    markdown_content += f"\n\n{image_ref}\n\n"
            except Exception as img_error:
                app.logger.error(f"Lỗi khi xử lý hình ảnh {img_id}: {str(img_error)}")
                # Tiếp tục với hình ảnh khác
        
        # Gọi Pandoc API
        app.logger.info("Đang gọi Pandoc API Onrender")
        try:
            response = requests.post(
                'https://pandoc-api.onrender.com/convert',
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/octet-stream'
                },
                json={'markdown': markdown_content},
                timeout=60  # Tăng timeout lên 60 giây
            )
            
            if response.status_code == 200:
                # Tạo tên file
                docx_filename = f"ocr_result_{int(time.time())}.docx"
                
                # Tạo file tạm thời để lưu kết quả
                temp_docx_path = os.path.join(app.config['UPLOAD_FOLDER'], docx_filename)
                with open(temp_docx_path, 'wb') as f:
                    f.write(response.content)
                
                app.logger.info(f"Đã lưu file Word tạm thời: {temp_docx_path}")
                
                # Gửi file đến client
                return send_file(
                    temp_docx_path,
                    mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    as_attachment=True,
                    download_name=docx_filename
                )
            else:
                error_message = response.text if response.text else f"Lỗi HTTP {response.status_code}"
                app.logger.error(f"Lỗi từ Pandoc API: {error_message}")
                return jsonify({
                    'success': False,
                    'error': f'Lỗi từ Pandoc API: {error_message}'
                }), 500
        except requests.RequestException as req_error:
            app.logger.error(f"Lỗi kết nối đến Pandoc API: {str(req_error)}")
            return jsonify({
                'success': False,
                'error': f'Lỗi kết nối đến Pandoc API: {str(req_error)}'
            }), 500
        
    except Exception as e:
        app.logger.error(f"Lỗi khi xuất file Word: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
    finally:
        # Dọn dẹp file tạm nếu có
        try:
            if 'temp_docx_path' in locals() and os.path.exists(temp_docx_path):
                os.remove(temp_docx_path)
                app.logger.info(f"Đã xóa file Word tạm thời: {temp_docx_path}")
        except Exception as e:
            app.logger.error(f"Lỗi khi dọn dẹp file tạm: {str(e)}")
