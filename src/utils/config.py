import os
import json
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置文件路径
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config')
API_CONFIG_PATH = os.path.join(CONFIG_DIR, 'api_config.json')
WHITELIST_PATH = os.path.join(CONFIG_DIR, 'whitelist.json')

def load_config(config_path):
    """加载配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        return {}

def save_config(config_path, config):
    """保存配置文件"""
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"保存配置文件失败: {e}")
        return False

def get_env_var(key, default=None):
    """获取环境变量"""
    return os.getenv(key, default)