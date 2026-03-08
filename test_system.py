"""
邮件检测与溯源系统 - 快速测试脚本
用于验证系统各模块的正常工作
"""

from src.parse_email import parse_email
from src.features import build_feature_vector
from src.detector import PhishingDetector
from src.email_traceback import generate_traceback_report


# 测试样本 - 钓鱼邮件示例
PHISHING_EMAIL = """From: "PayPal Security Team" <security@paypa1-verify.com>
To: user@example.com
Subject: 【紧急】您的 PayPal 账户需要立即验证

Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>尊敬的 PayPal 用户，</p>
<p>我们检测到您的账户有异常活动。</p>
<p><a href="http://secure-login-verify.com/account/check?redirect=paypal.com">立即点击此处验证您的身份</a></p>
<p>如果不立即处理，您的账户将在 24 小时内被冻结！</p>
<p>此致<br>PayPal 安全团队</p>
</body>
</html>

-- boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

[malicious payload]

-- boundary123--
"""

# 测试样本 - 正常邮件示例
NORMAL_EMAIL = """From: "John Smith" <john.smith@company.com>
To: user@example.com
Subject: 项目进度更新 - 2024 年 Q1

Dear Team,

希望这封邮件找到您时一切顺利。

附件是本项目本季度的进度报告，请您查阅。如有任何疑问或建议，请随时与我联系。

感谢大家的支持和配合！

Best regards,
John Smith
项目经理
Company Inc.
Phone: +1 (555) 123-4567
"""


def test_module(module_name, func, *args):
    """测试模块函数"""
    print(f"\n{'='*60}")
    print(f"测试：{module_name}")
    print('='*60)
    try:
        result = func(*args)
        print("[PASS] 测试通过")
        return result
    except Exception as e:
        print(f"[FAIL] 测试失败：{e}")
        return None


def main():
    """主测试流程"""
    print("="*60)
    print("钓鱼邮件检测与溯源系统 - 快速测试")
    print("="*60)

    # 测试 1: 邮件解析
    parsed = test_module("邮件解析模块", parse_email, PHISHING_EMAIL)
    if not parsed:
        print("\n邮件解析失败，后续测试跳过")
        return

    print("\n[解析结果摘要]")
    print(f"发件人：{parsed.get('from_display_name')} <{parsed.get('from_email')}>")
    print(f"主题：{parsed.get('subject')}")
    print(f"URL 数量：{len(parsed.get('urls', []))}")
    print(f"附件数量：{len(parsed.get('attachments', []))}")

    # 测试 2: 特征提取
    features = test_module("特征工程模块", build_feature_vector, parsed)
    if not features:
        print("\n特征提取失败，后续测试跳过")
        return

    print(f"\n[特征向量维度]: {len(features)}维")
    risky_features = [k for k, v in features.items() if v and v != 0]
    print(f"风险特征数量：{len(risky_features)}")
    for f in risky_features[:10]:
        print(f"  - {f}: {features[f]}")

    # 测试 3: 检测预测
    # 使用训练好的模型
    model_path = 'models/phish_detector.txt'
    detector = PhishingDetector(model_path)
    is_phish, confidence = test_module(
        "检测模型模块",
        detector.predict,
        features
    )

    print(f"\n[检测结果]")
    print(f"是否钓鱼邮件：{'是' if is_phish else '否'}")
    print(f"置信度：{confidence:.4f}")
    print(f"判定阈值：{detector.threshold}")

    # 测试 4: 溯源分析
    traceback_report = test_module(
        "溯源分析模块",
        generate_traceback_report,
        parsed
    )

    print(f"\n[溯源报告摘要]")
    if traceback_report.get('email_source'):
        source_ip = traceback_report['email_source'].get('source_ip', 'Unknown')
        print(f"源 IP: {source_ip}")
    if traceback_report.get('url_analysis'):
        print(f"分析的 URL 数量：{len(traceback_report['url_analysis'])}")
    if traceback_report.get('risk_indicators'):
        print(f"发现的风险指标：{len(traceback_report['risk_indicators'])}")
        for indicator in traceback_report['risk_indicators']:
            print(f"  [{indicator.get('severity', '').upper()}] {indicator.get('description')}")

    # 总结
    print("\n" + "="*60)
    print("测试完成!")
    print("="*60)

    if is_phish:
        print("\n系统正确识别出这是一封钓鱼邮件")
    else:
        print("\n注意：系统未将测试样本识别为钓鱼邮件")
        print("  这可能是因为:")
        print("  1. 演示模式下的规则不够严格")
        print("  2. 需要加载真实的训练模型")
        print("  3. 测试样本的特征不够典型")


if __name__ == "__main__":
    main()
