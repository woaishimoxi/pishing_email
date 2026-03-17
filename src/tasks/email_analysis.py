import re
import json
import time
from utils.logging import get_logger
from utils.database import execute_update

logger = get_logger(__name__)

def analyze_email(email_data):
    """分析邮件"""
    try:
        logger.info(f"开始分析邮件: {email_data.get('subject', '无主题')}")
        
        # 模拟分析过程
        time.sleep(2)  # 模拟处理时间
        
        # 提取特征
        features = extract_features(email_data)
        
        # 检测结果
        result = detect_phishing(features)
        
        # 生成报告
        report = generate_report(email_data, result, features)
        
        # 保存到数据库
        save_analysis_result(email_data, result, report, features)
        
        logger.info(f"邮件分析完成: {email_data.get('subject', '无主题')}")
        return {
            'success': True,
            'result': result,
            'report': report,
            'features': features
        }
    except Exception as e:
        logger.error(f"邮件分析失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }

def extract_features(email_data):
    """提取邮件特征"""
    features = {}
    
    # 主题特征
    subject = email_data.get('subject', '')
    features['subject_length'] = len(subject)
    features['subject_has_urgent'] = int(any(keyword in subject.lower() for keyword in ['紧急', 'urgent', '重要', 'important']))
    features['subject_has_money'] = int(any(keyword in subject.lower() for keyword in ['钱', 'money', '付款', 'payment', '转账', 'transfer']))
    
    # 发件人特征
    sender = email_data.get('sender', '')
    features['sender_has_free_domain'] = int(any(domain in sender.lower() for domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']))
    
    # 正文特征
    body = email_data.get('body', '')
    features['body_length'] = len(body)
    features['body_has_url'] = int('http' in body.lower())
    features['body_has_attachment'] = int(len(email_data.get('attachments', [])) > 0)
    features['body_has_form'] = int('form' in body.lower() or 'input' in body.lower())
    
    # 链接特征
    urls = email_data.get('urls', [])
    features['url_count'] = len(urls)
    features['has_suspicious_url'] = int(any('bit.ly' in url or 'tinyurl' in url for url in urls))
    
    return features

def detect_phishing(features):
    """检测钓鱼邮件"""
    # 简单的评分系统
    score = 0
    
    if features['subject_has_urgent']:
        score += 20
    if features['subject_has_money']:
        score += 25
    if features['sender_has_free_domain']:
        score += 15
    if features['body_has_url']:
        score += 10
    if features['body_has_form']:
        score += 20
    if features['has_suspicious_url']:
        score += 30
    
    is_phishing = score >= 50
    confidence = min(score / 100, 1.0)
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'score': score
    }

def generate_report(email_data, result, features):
    """生成分析报告"""
    report = {
        '基本信息': {
            '主题': email_data.get('subject', '无主题'),
            '发件人': email_data.get('sender', '未知'),
            '收件人': email_data.get('recipient', '未知'),
            '发送时间': email_data.get('timestamp', '未知')
        },
        '检测结果': {
            '是否为钓鱼邮件': '是' if result['is_phishing'] else '否',
            '置信度': f"{result['confidence']:.2f}",
            '评分': result['score']
        },
        '主要致因': [],
        '详细分析': {}
    }
    
    # 分析主要致因
    if features['subject_has_urgent']:
        report['主要致因'].append('邮件主题包含紧急词汇，可能试图制造紧迫感')
        report['详细分析']['主题紧急性'] = '邮件主题中包含紧急相关词汇，这是钓鱼邮件的常见特征'
    
    if features['subject_has_money']:
        report['主要致因'].append('邮件主题涉及金钱相关内容，可能试图引诱用户')
        report['详细分析']['金钱引诱'] = '邮件主题中包含金钱相关词汇，钓鱼邮件常以此为诱饵'
    
    if features['sender_has_free_domain']:
        report['主要致因'].append('发件人使用免费邮箱域名，可信度较低')
        report['详细分析']['发件人域名'] = '发件人使用免费邮箱服务，正规企业通常使用企业域名'
    
    if features['body_has_form']:
        report['主要致因'].append('邮件正文中包含表单元素，可能试图收集用户信息')
        report['详细分析']['表单元素'] = '邮件中包含表单，这是钓鱼邮件收集用户信息的常见手段'
    
    if features['has_suspicious_url']:
        report['主要致因'].append('邮件中包含可疑短链接，可能指向恶意网站')
        report['详细分析']['可疑链接'] = '邮件中包含短链接服务，这些链接可能指向钓鱼网站'
    
    if features['url_count'] > 5:
        report['主要致因'].append('邮件中包含大量链接，增加了风险')
        report['详细分析']['链接数量'] = f'邮件中包含 {features["url_count"]} 个链接，数量较多'
    
    # 如果没有检测到明显致因
    if not report['主要致因']:
        report['主要致因'].append('未检测到明显的钓鱼特征')
    
    return report

def save_analysis_result(email_data, result, report, features):
    """保存分析结果到数据库（已合并到 alerts 表）"""
    try:
        # 注意：由于分析结果已通过 app.py 的 save_to_database 保存到 alerts 表
        # 此处仅记录日志，不再重复保存到旧表
        logger.info(f"邮件分析完成: {email_data.get('email_id')}, 判定: {result.get('label')}")
    except Exception as e:
        logger.error(f"记录分析结果失败: {e}")