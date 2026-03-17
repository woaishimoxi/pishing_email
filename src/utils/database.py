import sqlite3
import os

# 数据库文件路径 - 与 app.py 保持一致
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'alerts.db')

def get_db_connection():
    """获取数据库连接"""
    try:
        # 确保data目录存在
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        # 启用共享缓存模式，减少数据库锁定
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"获取数据库连接失败: {e}")
        return None

def init_database():
    """初始化数据库"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # 创建 alerts 表（主要告警表）
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
                header_data TEXT,
                source TEXT,
                email_hash TEXT
            )
        ''')
        
        # 创建 processed_uids 表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_uids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT UNIQUE,
                processed_at TEXT
            )
        ''')
        
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_detection_time ON alerts(detection_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_label ON alerts(label)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_from_email ON alerts(from_email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email_hash ON alerts(email_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uid ON processed_uids(uid)')
        
        conn.commit()
        return True
    except Exception as e:
        print(f"初始化数据库失败: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def execute_query(query, params=None):
    """执行查询操作"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        print(f"执行查询失败: {e}")
        return []
    finally:
        conn.close()

def execute_update(query, params=None):
    """执行更新操作"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        conn.commit()
        return True
    except Exception as e:
        print(f"执行更新失败: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
