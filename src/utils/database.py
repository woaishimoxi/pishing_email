import sqlite3
import os

# 数据库文件路径 - 与 app.py 保持一致
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(PROJECT_DIR, 'data', 'alerts.db')

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
        
        # 创建邮件分析表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT UNIQUE,
            subject TEXT,
            sender TEXT,
            recipient TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_phishing INTEGER,
            confidence REAL,
            report TEXT
        )
        ''')
        
        # 创建特征分析表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS feature_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT,
            feature_name TEXT,
            feature_value REAL,
            FOREIGN KEY (email_id) REFERENCES email_analysis(email_id)
        )
        ''')
        
        # 创建URL分析表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT,
            url TEXT,
            is_malicious INTEGER,
            threat_type TEXT,
            FOREIGN KEY (email_id) REFERENCES email_analysis(email_id)
        )
        ''')
        
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