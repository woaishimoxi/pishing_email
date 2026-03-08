"""
轻量级检测模型实现模块
本模块使用 LightGBM 作为核心分类器，对提取的特征向量进行钓鱼风险预测。
"""
import os
import json
import pickle
from typing import Dict, List, Tuple, Optional
import numpy as np


# 特征列顺序 (与 features.py 中保持一致) - 增强版 39 维
FEATURE_COLUMNS = [
    # 邮件头特征 (8 维)
    'is_suspicious_from_domain', 'received_hops_count',
    'first_external_ip_is_blacklisted',
    'spf_fail', 'dkim_fail', 'dmarc_fail',
    'from_display_name_mismatch', 'from_domain_in_subject',

    # URL 特征 (14 维)
    'avg_domain_age_days', 'max_vt_detection_ratio',
    'min_has_https', 'short_url_count', 'mixed_sld_count',
    'max_domain_length',
    'ip_address_count', 'port_count',
    'at_symbol_count', 'subdomain_count', 'suspicious_param_count',
    'avg_url_length', 'avg_path_depth', 'max_query_length',

    # 文本特征 (7 维)
    'urgent_keywords_count', 'financial_keywords_count',
    'text_length', 'urgency_score', 'exclamation_count',
    'caps_ratio', 'url_count',

    # 附件特征 (5 维)
    'attachment_count', 'has_suspicious_attachment',
    'has_executable_attachment', 'total_attachment_size',
    'has_double_extension',

    # HTML 特征 (5 维)
    'has_html_body', 'html_link_count', 'has_hidden_links',
    'has_form', 'has_iframe',
]

# 默认预测阈值
DEFAULT_THRESHOLD = 0.7


class PhishingDetector:
    """
    钓鱼邮件检测器类
    支持加载预训练模型或生成模拟预测结果（用于演示）
    """

    def __init__(self, model_path: Optional[str] = None, threshold: float = DEFAULT_THRESHOLD):
        """
        初始化检测器。

        Args:
            model_path: 预训练模型文件路径 (LightGBM .txt 文件或自定义 Pickle 文件)
            threshold: 判定为钓鱼邮件的置信度阈值
        """
        self.threshold = threshold
        self.model = None
        self.model_path = model_path or 'models/phish_detector.txt'

        if model_path and os.path.exists(model_path):
            self.load_model()

    def load_model(self) -> bool:
        """
        加载预训练模型。

        Returns:
            bool: 是否成功加载
        """
        try:
            # 尝试加载 LightGBM 模型
            import lightgbm as lgb
            self.model = lgb.Booster(model_file=self.model_path)
            print(f"成功加载 LightGBM 模型：{self.model_path}")
            return True
        except Exception as e:
            print(f"加载 LightGBM 模型失败：{e}")
            self.model = None
            return False

    def generate_demo_model(self):
        """
        生成一个演示用的简单规则模型 (当没有真实训练数据时使用)
        这个模型基于简单的启发式规则进行预测
        """
        # 创建一个基于规则的简易检测函数
        self.is_demo_mode = True
        self.demo_weights = {
            # 邮件头特征 - 高风险
            'is_suspicious_from_domain': 0.30,
            'spf_fail': 0.20,
            'dkim_fail': 0.15,
            'dmarc_fail': 0.15,
            'from_display_name_mismatch': 0.20,
            'received_hops_count': 0.01,
            'first_external_ip_is_blacklisted': 0.25,
            'from_domain_in_subject': 0.10,

            # URL 特征 - 高风险
            'avg_domain_age_days': -0.0002,  # 年龄越小越可疑
            'max_vt_detection_ratio': 0.50,
            'min_has_https': -0.15,
            'short_url_count': 0.20,
            'mixed_sld_count': 0.10,
            'max_domain_length': 0.003,
            'ip_address_count': 0.25,
            'port_count': 0.15,
            'at_symbol_count': 0.20,
            'subdomain_count': 0.10,
            'suspicious_param_count': 0.15,
            'avg_url_length': 0.001,
            'avg_path_depth': 0.02,
            'max_query_length': 0.001,

            # 文本特征
            'urgent_keywords_count': 0.15,
            'financial_keywords_count': 0.12,
            'text_length': -0.0001,
            'urgency_score': 0.25,
            'exclamation_count': 0.05,
            'caps_ratio': 0.10,
            'url_count': 0.03,

            # 附件特征 - 高风险
            'attachment_count': 0.05,
            'has_suspicious_attachment': 0.25,
            'has_executable_attachment': 0.35,
            'total_attachment_size': 0.00001,
            'has_double_extension': 0.30,

            # HTML 特征
            'has_html_body': 0.02,
            'html_link_count': 0.02,
            'has_hidden_links': 0.25,
            'has_form': 0.15,
            'has_iframe': 0.20,
        }

    def predict(self, feature_vector: Dict) -> Tuple[bool, float]:
        """
        对一封邮件的特征向量进行钓鱼风险预测。

        Args:
            feature_vector: 由特征工程模块生成的特征字典

        Returns:
            tuple: (is_phish: bool, confidence: float)
                - is_phish: 是否判定为钓鱼邮件
                - confidence: 预测置信度 (0-1 之间的概率值)
        """
        if hasattr(self, 'is_demo_mode') and self.is_demo_mode:
            return self._demo_predict(feature_vector)

        if self.model is None:
            # 如果没有模型，返回低风险但带警告
            return False, 0.0

        try:
            # 构造与训练时相同结构的输入
            input_data = [[float(feature_vector.get(col, 0)) for col in FEATURE_COLUMNS]]
            prediction_prob = self.model.predict(np.array(input_data))[0]

            # 确保概率在合理范围内
            prediction_prob = max(0, min(1, float(prediction_prob)))

            # 设定阈值判定
            is_phish = prediction_prob > self.threshold

            return is_phish, prediction_prob

        except Exception as e:
            print(f"预测错误：{e}")
            return False, 0.0

    def _demo_predict(self, feature_vector: Dict) -> Tuple[bool, float]:
        """
        演示模式下的预测 (基于规则)
        """
        score = 0.0

        for feature, weight in self.demo_weights.items():
            value = float(feature_vector.get(feature, 0))

            # 特殊处理：域名年龄是负相关（年龄越小越可疑）
            if feature == 'avg_domain_age_days':
                # 将域名年龄转换为风险分数：0 天=1, 3650 天=0
                score += weight * max(0, (3650 - value)) / 3650

            # 特殊处理：文本长度是负相关（越短越可疑）
            elif feature == 'text_length':
                score += weight * max(0, (1000 - value)) / 1000

            # 其他特征直接相乘
            else:
                score += weight * value

        # 归一化到 0-1 范围
        confidence = min(1.0, max(0.0, score))
        is_phish = confidence > self.threshold

        return is_phish, confidence

    def set_threshold(self, threshold: float):
        """
        设置判定阈值。

        Args:
            threshold: 新的阈值 (0-1 之间)
        """
        self.threshold = max(0, min(1, threshold))

    def get_threshold(self) -> float:
        """获取当前阈值"""
        return self.threshold


def predict_phishing_risk(feature_vector: Dict, model: Optional[PhishingDetector] = None,
                          threshold: float = DEFAULT_THRESHOLD) -> Tuple[bool, float]:
    """
    便捷函数：对一封邮件的特征向量进行钓鱼风险预测。

    Args:
        feature_vector: 特征字典
        model: 可选的探测器实例，如果未提供则创建新实例
        threshold: 判定阈值

    Returns:
        tuple: (is_phish: bool, confidence: float)
    """
    if model is None:
        model = PhishingDetector()
        # 检查是否有 demo 模型可用
        demo_path = 'models/phish_detector.pkl'
        if os.path.exists(demo_path):
            try:
                with open(demo_path, 'rb') as f:
                    model.model = pickle.load(f)
                print("加载了演示模式模型")
            except:
                model.generate_demo_model()
        else:
            model.generate_demo_model()

    return model.predict(feature_vector)


def batch_predict(feature_vectors: List[Dict], model: Optional[PhishingDetector] = None,
                  threshold: float = DEFAULT_THRESHOLD) -> List[Tuple[bool, float]]:
    """
    批量预测多封邮件。

    Args:
        feature_vectors: 特征字典列表
        model: 探测器实例
        threshold: 判定阈值

    Returns:
        List[Tuple[bool, float]]: [(is_phish, confidence), ...]
    """
    results = []
    for fv in feature_vectors:
        result = predict_phishing_risk(fv, model, threshold)
        results.append(result)
    return results


if __name__ == "__main__":
    # 测试示例
    from src.features import build_feature_vector
    from src.parse_email import parse_email

    test_email = """From: "Bank Security" <security@suspicious-bank.com>
To: user@example.com
Subject: 【紧急】您的账户存在异常登录！

尊敬的客户，

我们检测到您的账户有异常活动。请立即点击以下链接验证您的身份：
http://secure-login-verify.com/account/check

如果不立即处理，您的账户将在 24 小时内被冻结！

此致
银行安全团队
"""

    parsed = parse_email(test_email)
    features = build_feature_vector(parsed)

    detector = PhishingDetector()
    is_phish, confidence = detector.predict(features)

    print("=" * 50)
    print("钓鱼邮件检测结果")
    print("=" * 50)
    print(f"是否钓鱼邮件：{'是' if is_phish else '否'}")
    print(f"置信度：{confidence:.4f}")
    print(f"判定阈值：{detector.threshold}")
    print("=" * 50)
