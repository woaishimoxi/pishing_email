"""
轻量级检测模型实现模块
本模块使用 LightGBM 作为核心分类器，对提取的特征向量进行钓鱼风险预测。
"""
import os
import json
import pickle
from typing import Dict, List, Tuple, Optional
import numpy as np


# 特征列顺序 (与 features.py 中保持一致) - 增强版 45 维
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

    # 附件特征 (9 维)
    'attachment_count', 'has_suspicious_attachment',
    'has_executable_attachment', 'total_attachment_size',
    'has_double_extension', 'sandbox_detected',
    'max_sandbox_detection_ratio', 'has_sandbox_analysis',
    'attachment_risk_score',  # 新增：附件风险评分

    # HTML 特征 (6 维)
    'has_html_body', 'html_link_count', 'has_hidden_links',
    'has_form', 'has_iframe', 'has_external_script',
]

# 三分类阈值定义
THRESHOLD_SAFE = 0.40
THRESHOLD_SUSPICIOUS = 0.70


class PhishingDetector:
    """
    钓鱼邮件检测器类
    支持加载预训练模型或生成模拟预测结果（用于演示）
    实现三分类（正常、可疑、钓鱼）检测逻辑
    """

    def __init__(self, model_path: Optional[str] = None, vt_api_key: Optional[str] = None):
        """
        初始化检测器。

        Args:
            model_path: 预训练模型文件路径 (LightGBM .txt 文件或自定义 Pickle 文件)
            vt_api_key: VirusTotal API 密钥
        """
        self.vt_api_key = vt_api_key
        self.model = None
        self.model_path = model_path or 'models/phish_detector.txt'
        # 定义阈值
        self.THRESHOLD_SAFE = THRESHOLD_SAFE
        self.THRESHOLD_SUSPICIOUS = THRESHOLD_SUSPICIOUS

        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            # 生成演示模型
            self.generate_demo_model()

    def load_model(self) -> bool:
        """
        加载预训练模型。

        Returns:
            bool: 是否成功加载
        """
        # 检查文件是否存在
        import os
        if not os.path.exists(self.model_path):
            print(f"模型文件不存在：{self.model_path}")
            self.model = None
            # 切换到演示模式
            self.generate_demo_model()
            return False
        
        try:
            # 尝试加载 LightGBM 模型
            import lightgbm as lgb
            self.model = lgb.Booster(model_file=self.model_path)
            print(f"成功加载 LightGBM 模型：{self.model_path}")
            return True
        except Exception as e:
            print(f"加载 LightGBM 模型失败：{e}")
            self.model = None
            # 切换到演示模式
            self.generate_demo_model()
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
            'sandbox_detected': 0.40,
            'max_sandbox_detection_ratio': 0.35,
            'has_sandbox_analysis': 0.05,
            'attachment_risk_score': 0.1,  # 新增：附件风险评分

            # HTML 特征
            'has_html_body': 0.02,
            'html_link_count': 0.02,
            'has_hidden_links': 0.25,
            'has_form': 0.15,
            'has_iframe': 0.20,
            'has_external_script': 0.25,
        }

    def analyze(self, email_data: Dict, features: Dict) -> Tuple[str, float, str]:
        """
        对邮件进行三分类分析。

        Args:
            email_data: 解析后的邮件数据
            features: 特征向量字典

        Returns:
            tuple: (label: str, confidence: float, reason: str)
                - label: 'SAFE', 'SUSPICIOUS', 'PHISHING'
                - confidence: 预测置信度 (0-1 之间的概率值)
                - reason: 判定理由
        """
        # --- 第一步：硬性熔断检查 (Kill Switch) ---
        kill_reason = self._check_kill_switch(features)
        if kill_reason:
            return "PHISHING", 0.99, f"Hard Rule Triggered: {kill_reason}"
            
        # --- 第二步：沙箱高危检查 (High Weight) ---
        # 如果沙箱已运行且发现可疑但未达恶意，或者文件类型极度危险
        sandbox_risk = self._check_sandbox_risk(features)
        if sandbox_risk == "HIGH_RISK_FILE_NO_RESULT":
            # 强制提升至可疑或以上
            base_confidence = 0.65
        else:
            base_confidence = 0.0

        # --- 第三步：模型预测 ---
        if self.model:
            # 获取模型原始概率
            input_data = [[float(features.get(col, 0)) for col in FEATURE_COLUMNS]]
            model_prob = self.model.predict(np.array(input_data))[0]
        else:
            # 降级处理，使用演示模式
            _, model_prob = self._demo_predict(features)
            
        # --- 第四步：融合决策逻辑 ---
        final_confidence = max(base_confidence, model_prob)
        
        # 动态调整：如果溯源发现IP黑名单，增加置信度
        if features.get('first_external_ip_is_blacklisted'):
            final_confidence = min(1.0, final_confidence + 0.2)
            
        # --- 第五步：档位划分 ---
        if final_confidence >= self.THRESHOLD_SUSPICIOUS:
            label = "PHISHING"
            reason = "High confidence phishing detected."
        elif final_confidence >= self.THRESHOLD_SAFE:
            label = "SUSPICIOUS"
            reason = "Ambiguous features detected. Manual review recommended."
        else:
            label = "SAFE"
            reason = "No significant threats detected."
            
        return label, final_confidence, reason

    def _check_kill_switch(self, features: Dict) -> Optional[str]:
        """
        检查硬性熔断规则。

        Args:
            features: 特征向量字典

        Returns:
            Optional[str]: 熔断原因，如果未触发则返回 None
        """
        # 沙箱确认为恶意
        if features.get('sandbox_detected'):
            return "Sandbox Detected Malware"
        # SPF/DKIM/DMARC 全部失败且发件人域名与显示名称不匹配
        if features.get('spf_fail') and features.get('dkim_fail') and features.get('dmarc_fail') and features.get('from_display_name_mismatch'):
            return "Authentication Failed + Impersonation"
        # URL 存在于已知黑名单中（通过 VirusTotal 检测率判断）
        if features.get('max_vt_detection_ratio', 0) > 0.5:
            return "Known Malicious URL"
        return None

    def _check_sandbox_risk(self, features: Dict) -> Optional[str]:
        """
        检查沙箱高危情况。

        Args:
            features: 特征向量字典

        Returns:
            Optional[str]: 风险类型，如果无风险则返回 None
        """
        # 高风险文件类型但沙箱未分析出结果
        if features.get('has_executable_attachment') and not features.get('has_sandbox_analysis'):
            return "HIGH_RISK_FILE_NO_RESULT"
        return None

    def _demo_predict(self, feature_vector: Dict) -> Tuple[bool, float]:
        """
        演示模式下的预测 (基于规则)

        Returns:
            tuple: (is_phish: bool, confidence: float)
        """
        # 确保 demo_weights 存在
        if not hasattr(self, 'demo_weights'):
            self.generate_demo_model()
        
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
        is_phish = confidence > self.THRESHOLD_SUSPICIOUS

        return is_phish, confidence

    def set_thresholds(self, safe_threshold: float, suspicious_threshold: float):
        """
        设置三分类阈值。

        Args:
            safe_threshold: 正常邮件阈值
            suspicious_threshold: 可疑邮件阈值
        """
        self.THRESHOLD_SAFE = max(0, min(1, safe_threshold))
        self.THRESHOLD_SUSPICIOUS = max(self.THRESHOLD_SAFE, min(1, suspicious_threshold))

    def get_thresholds(self) -> Tuple[float, float]:
        """获取当前阈值"""
        return self.THRESHOLD_SAFE, self.THRESHOLD_SUSPICIOUS


def analyze_phishing_risk(email_data: Dict, feature_vector: Dict, model: Optional[PhishingDetector] = None,
                          vt_api_key: Optional[str] = None) -> Tuple[str, float, str]:
    """
    便捷函数：对一封邮件进行三分类钓鱼风险分析。

    Args:
        email_data: 解析后的邮件数据
        feature_vector: 特征字典
        model: 可选的探测器实例，如果未提供则创建新实例
        vt_api_key: VirusTotal API 密钥

    Returns:
        tuple: (label: str, confidence: float, reason: str)
    """
    if model is None:
        model = PhishingDetector(vt_api_key=vt_api_key)
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

    return model.analyze(email_data, feature_vector)


def batch_analyze(email_data_list: List[Dict], feature_vectors: List[Dict], 
                  model: Optional[PhishingDetector] = None, vt_api_key: Optional[str] = None) -> List[Tuple[str, float, str]]:
    """
    批量分析多封邮件。

    Args:
        email_data_list: 解析后的邮件数据列表
        feature_vectors: 特征字典列表
        model: 探测器实例
        vt_api_key: VirusTotal API 密钥

    Returns:
        List[Tuple[str, float, str]]: [(label, confidence, reason), ...]
    """
    results = []
    for email_data, fv in zip(email_data_list, feature_vectors):
        result = analyze_phishing_risk(email_data, fv, model, vt_api_key)
        results.append(result)
    return results


if __name__ == "__main__":
    # 测试示例
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from features import build_feature_vector
    from parse_email import parse_email

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
    label, confidence, reason = detector.analyze(parsed, features)

    print("=" * 50)
    print("钓鱼邮件检测结果")
    print("=" * 50)
    print(f"判定结果：{label}")
    print(f"置信度：{confidence:.4f}")
    print(f"判定理由：{reason}")
    print(f"正常阈值：{detector.THRESHOLD_SAFE}")
    print(f"可疑阈值：{detector.THRESHOLD_SUSPICIOUS}")
    print("=" * 50)
