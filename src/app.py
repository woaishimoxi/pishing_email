"""
Web 管理平台 - 后端 API 服务
基于 Flask 框架构建的轻量级管理界面
"""
import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from parse_email import parse_email
from features import build_feature_vector
from detector import PhishingDetector, analyze_phishing_risk
from email_traceback import generate_traceback_report


# 初始化 Flask 应用
app = Flask(__name__)

# 配置
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(APP_DIR)
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
MODELS_DIR = os.path.join(PROJECT_DIR, 'models')
UPLOAD_DIR = os.path.join(PROJECT_DIR, 'uploads')
CONFIG_DIR = os.path.join(PROJECT_DIR, 'config')

# 确保数据目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

DATABASE_PATH = os.path.join(DATA_DIR, 'alerts.db')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'api_config.json')

# 文件上传配置
ALLOWED_EXTENSIONS = {'eml', 'msg'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB 最大上传限制
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 加载 API 配置
def load_api_config():
    """加载 API 配置"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return {
        'virustotal': {
            'api_key': '',
            'api_url': 'https://www.virustotal.com/vtapi/v2/url/report'
        },
        'ipapi': {
            'api_url': 'http://ip-api.com/json/'
        }
    }

# 保存 API 配置
def save_api_config(config):
    """保存 API 配置"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except:
        return False

# 加载配置
api_config = load_api_config()
vt_api_key = api_config.get('virustotal', {}).get('api_key', '') or os.environ.get('VT_API_KEY', '')
vt_api_url = api_config.get('virustotal', {}).get('api_url', 'https://www.virustotal.com/vtapi/v2/url/report')
ip_api_url = api_config.get('ipapi', {}).get('api_url', 'http://ip-api.com/json/')

# 初始化检测器
detector = PhishingDetector()


def allowed_file(filename: str) -> bool:
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def read_email_file(filepath: str) -> str:
    """读取邮件文件内容，支持 .eml 和.msg格式"""
    try:
        # 尝试 UTF-8 编码读取
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # 尝试 GBK 编码读取（中文 Windows 常见）
        try:
            with open(filepath, 'r', encoding='gbk') as f:
                return f.read()
        except:
            pass
        # 尝试二进制读取并忽略错误
        try:
            with open(filepath, 'rb') as f:
                return f.read().decode('utf-8', errors='ignore')
        except:
            pass
    except Exception as e:
        raise Exception(f"读取邮件文件失败：{e}")

    raise Exception("无法解析邮件文件编码")


def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 检查是否存在旧表结构
    cursor.execute("PRAGMA table_info(alerts)")
    columns = [column[1] for column in cursor.fetchall()]

    # 如果存在旧表结构且包含 is_phish 字段，删除旧表
    if 'is_phish' in columns:
        cursor.execute('DROP TABLE IF EXISTS alerts')

    # 创建新表结构
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_addr TEXT,
            from_display_name TEXT,
            from_email TEXT,
            to_addr TEXT,
            subject TEXT,
            detection_time TEXT,
            label TEXT,
            confidence REAL,
            source_ip TEXT,
            risk_indicators TEXT,
            raw_email TEXT,
            traceback_data TEXT,
            attachment_data TEXT,
            url_data TEXT,
            header_data TEXT
        )
    ''')

    # 创建索引以加快查询速度
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_detection_time ON alerts(detection_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_label ON alerts(label)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_from_email ON alerts(from_email)')

    conn.commit()
    conn.close()


init_db()


@app.route('/')
def dashboard():
    """渲染主仪表盘页面"""
    return render_template('dashboard.html')


@app.route('/report.html')
def report_page():
    """渲染报告详情页面"""
    return render_template('report.html')


@app.route('/api/health')
def health_check():
    """健康检查接口"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Detection System',
        'version': '1.0.0'
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """
    分析邮件 API
    接收原始邮件字符串，返回检测结果
    """
    try:
        data = request.get_json()
        raw_email = data.get('email', '')

        if not raw_email:
            return jsonify({'error': 'No email content provided'}), 400

        return process_email(raw_email)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
def upload_email():
    """
    上传邮件文件 API
    支持 .eml 和.msg 格式的邮件文件
    """
    try:
        # 检查是否有文件
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': '不支持的文件格式，请上传.eml 或.msg 文件'}), 400

        # 保存上传的文件
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_DIR, filename)
        file.save(filepath)

        # 读取邮件文件内容
        raw_email = read_email_file(filepath)

        # 删除临时文件
        try:
            os.remove(filepath)
        except:
            pass

        return process_email(raw_email)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def process_email(raw_email: str):
    """处理邮件内容并返回检测结果"""
    # 解析邮件
    parsed = parse_email(raw_email)

    # 提取特征
    features = build_feature_vector(parsed, vt_api_key, vt_api_url)

    # 分析（三分类）
    label, confidence, reason = analyze_phishing_risk(parsed, features, vt_api_key=vt_api_key)

    # 生成溯源报告
    traceback_report = generate_traceback_report(parsed, vt_api_key, ip_api_url)

    # 保存到数据库
    save_to_database(parsed, label, confidence, traceback_report)

    # 处理附件的沙箱分析结果
    attachments_with_analysis = []
    for att in parsed.get('attachments', []):
        # 移除内容字段以减少响应大小
        att_with_analysis = {**att}
        if 'content' in att_with_analysis:
            del att_with_analysis['content']
        attachments_with_analysis.append(att_with_analysis)

    # 移除 features 中可能包含的字节类型数据
    safe_features = {}
    for key, value in features.items():
        if isinstance(value, bytes):
            safe_features[key] = str(value)
        else:
            safe_features[key] = value

    # 计算各模块评分
    module_scores = {
        'header': 0.0,
        'url': 0.0,
        'text': 0.0,
        'attachment': 0.0,
        'html': 0.0
    }
    
    # 邮件头特征评分
    header_features = [
        'is_suspicious_from_domain', 'spf_fail', 'dkim_fail', 'dmarc_fail',
        'from_display_name_mismatch', 'from_domain_in_subject'
    ]
    for feat in header_features:
        if features.get(feat, 0):
            module_scores['header'] += 0.2
    
    # URL特征评分
    url_features = [
        'ip_address_count', 'port_count', 'at_symbol_count', 'subdomain_count',
        'suspicious_param_count', 'short_url_count'
    ]
    for feat in url_features:
        if features.get(feat, 0) > 0:
            module_scores['url'] += 0.167
    
    # 文本特征评分
    text_features = [
        'urgent_keywords_count', 'financial_keywords_count', 'exclamation_count',
        'caps_ratio', 'urgency_score'
    ]
    for feat in text_features:
        value = features.get(feat, 0)
        if feat == 'urgency_score':
            module_scores['text'] += value * 0.2
        else:
            if value > 0:
                module_scores['text'] += 0.2
    
    # 附件特征评分
    attachment_features = [
        'has_suspicious_attachment', 'has_executable_attachment',
        'has_double_extension', 'sandbox_detected'
    ]
    for feat in attachment_features:
        if features.get(feat, 0):
            module_scores['attachment'] += 0.25
    
    # HTML特征评分
    html_features = [
        'has_hidden_links', 'has_form', 'has_iframe', 'has_external_script'
    ]
    for feat in html_features:
        if features.get(feat, 0):
            module_scores['html'] += 0.25
    
    # 确保评分在0-1之间
    for key in module_scores:
        module_scores[key] = min(1.0, module_scores[key])
    
    result = {
        'label': label,
        'confidence': round(confidence, 4),
        'reason': reason,
        'module_scores': module_scores,
        'parsed': {
            'from': parsed.get('from'),
            'from_display_name': parsed.get('from_display_name'),
            'from_email': parsed.get('from_email'),
            'to': parsed.get('to'),
            'subject': parsed.get('subject'),
            'body': parsed.get('body', ''),
            'html_body': parsed.get('html_body', ''),
            'urls': parsed.get('urls', []),
            'url_count': len(parsed.get('urls', [])),
            'attachment_count': len(parsed.get('attachments', [])),
            'has_html_body': 1 if parsed.get('html_body') else 0
        },
        'features': safe_features,
        'attachments': attachments_with_analysis,
        'html_links': parsed.get('html_links', []),
        'html_forms': parsed.get('html_forms', []),
        'headers': parsed.get('headers', {}),
        'traceback': traceback_report,
        'sandbox_analysis': {
            'enabled': bool(vt_api_key),
            'has_sandbox_analysis': features.get('has_sandbox_analysis', 0) == 1,
            'sandbox_detected': features.get('sandbox_detected', 0) == 1,
            'max_detection_ratio': features.get('max_sandbox_detection_ratio', 0.0)
        }
    }

    return jsonify(result)


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """获取所有告警记录"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    label_filter = request.args.get('label', None)

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 构建查询
    base_query = "SELECT * FROM alerts"
    count_query = "SELECT COUNT(*) FROM alerts"

    params = []

    if label_filter is not None:
        base_query += " WHERE label = ?"
        count_query += " WHERE label = ?"
        params = [label_filter]

    cursor.execute(count_query, params)
    total = cursor.fetchone()[0]

    offset = (page - 1) * per_page
    cursor.execute(f"{base_query} ORDER BY detection_time DESC LIMIT ? OFFSET ?",
                   params + [per_page, offset])

    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        'alerts': alerts,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })


@app.route('/api/stats/overview')
def get_overview_stats():
    """获取概览统计数据"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 总数
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    # 钓鱼邮件数
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE label = 'PHISHING'")
    phish_count = cursor.fetchone()[0]

    # 可疑邮件数
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE label = 'SUSPICIOUS'")
    suspicious_count = cursor.fetchone()[0]

    # 正常邮件数
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE label = 'SAFE'")
    normal_count = cursor.fetchone()[0]

    # 今日新增
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE date(detection_time) = ?", (today,))
    today_count = cursor.fetchone()[0]

    # 近 7 天趋势
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT date(detection_time) as day,
               COUNT(*) as count,
               SUM(CASE WHEN label = 'PHISHING' THEN 1 ELSE 0 END) as phish_count,
               SUM(CASE WHEN label = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_count,
               SUM(CASE WHEN label = 'SAFE' THEN 1 ELSE 0 END) as safe_count
        FROM alerts
        WHERE detection_time >= datetime('now', '-7 days')
        GROUP BY day
        ORDER BY day
    """)
    trend_data = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        'total': total,
        'phishing': phish_count,
        'suspicious': suspicious_count,
        'normal': normal_count,
        'today': today_count,
        'trend': trend_data
    })


@app.route('/api/stats/daily')
def get_daily_stats():
    """获取每日统计"""
    days = request.args.get('days', 7, type=int)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            date(detection_time) as day,
            COUNT(*) as total,
            SUM(CASE WHEN label = 'PHISHING' THEN 1 ELSE 0 END) as phishing,
            SUM(CASE WHEN label = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN label = 'SAFE' THEN 1 ELSE 0 END) as normal
        FROM alerts
        WHERE detection_time >= datetime('now', '-{} days')
        GROUP BY day
        ORDER BY day
    """.format(days))

    stats = cursor.fetchall()
    conn.close()

    return jsonify([dict(row) for row in stats])


@app.route('/api/alerts/<int:alert_id>')
def get_alert(alert_id):
    """获取单个告警详情"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        return jsonify({'error': 'Alert not found'}), 404

    alert = dict(row)
    conn.close()

    # 解析追溯数据
    if alert.get('traceback_data'):
        alert['traceback'] = json.loads(alert['traceback_data'])

    return jsonify(alert)


def _shutdown_server():
    """关闭 Flask 开发服务器（仅本机调用）"""
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app.route('/api/shutdown', methods=['POST'])
def shutdown():
    """
    一键关闭系统接口
    - 调用后会优雅停止当前 Flask 服务进程
    """
    try:
        _shutdown_server()
        return jsonify({'status': 'shutting_down'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API 配置管理路由
@app.route('/api/config')
def get_api_config():
    """获取 API 配置"""
    return jsonify(api_config)

@app.route('/api/config', methods=['POST'])
def update_api_config():
    """更新 API 配置"""
    global api_config, vt_api_key, vt_api_url, ip_api_url
    try:
        config = request.get_json()
        if config:
            api_config = config
            save_api_config(api_config)
            # 更新当前使用的 API 配置
            vt_api_key = api_config.get('virustotal', {}).get('api_key', '') or os.environ.get('VT_API_KEY', '')
            vt_api_url = api_config.get('virustotal', {}).get('api_url', 'https://www.virustotal.com/vtapi/v2/url/report')
            ip_api_url = api_config.get('ipapi', {}).get('api_url', 'http://ip-api.com/json/')
            return jsonify({'status': 'success', 'message': '配置已保存'})
        return jsonify({'status': 'error', 'message': '无效的配置数据'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/config/test')
def test_api_connection():
    """测试 API 连接"""
    try:
        test_url = 'https://www.google.com'
        from features import query_virustotal
        result = query_virustotal(test_url, vt_api_key, vt_api_url)
        if result >= 0:
            return jsonify({'status': 'success', 'message': 'VirusTotal API 连接成功'})
        else:
            return jsonify({'status': 'error', 'message': 'VirusTotal API 连接失败'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'测试失败: {str(e)}'}), 500


def save_to_database(parsed: Dict, label: str, confidence: float,
                     traceback_report: Dict):
    """保存检测结果到数据库（增强版）"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 处理附件数据，移除字节类型的content字段
    attachments = parsed.get('attachments', [])
    safe_attachments = []
    for att in attachments:
        safe_att = {**att}
        if 'content' in safe_att:
            del safe_att['content']
        safe_attachments.append(safe_att)

    cursor.execute('''
        INSERT INTO alerts (from_addr, from_display_name, from_email, to_addr, subject, detection_time,
                           label, confidence, source_ip, risk_indicators,
                           raw_email, traceback_data, attachment_data, url_data, header_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        parsed.get('from', ''),
        parsed.get('from_display_name', ''),
        parsed.get('from_email', ''),
        parsed.get('to', ''),
        parsed.get('subject', ''),
        datetime.now().isoformat(),
        label,
        confidence,
        traceback_report.get('email_source', {}).get('source_ip', ''),
        json.dumps(traceback_report.get('risk_indicators', [])),
        '',  # 为节省空间，实际应用中可能需要存储原始邮件
        json.dumps(traceback_report),
        json.dumps(safe_attachments),
        json.dumps(parsed.get('urls', [])),
        json.dumps(parsed.get('headers', {}))
    ))

    conn.commit()
    conn.close()


if __name__ == '__main__':
    print("=" * 60)
    print("钓鱼邮件检测与溯源系统 - Web 管理平台")
    print("=" * 60)
    print(f"数据目录：{DATA_DIR}")
    print(f"模型目录：{MODELS_DIR}")
    print("-" * 60)
    print("访问地址：http://localhost:5000")
    print("API 文档：http://localhost:5000/api/docs")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
