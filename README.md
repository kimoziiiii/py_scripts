# 脚本关联配置
脚本参数：
1. {ALTER.SUBJECT} # 主题
2. {ALTER.MESSAGE} # 消息体

动作配置
```
# {ALTER.SUBJECT}
{TRIGGER.STATUS} {HOST.NAME}  

# {ALTER.MESSAGE}
当前状态: {TRIGGER.STATUS}

告警信息: {TRIGGER.NAME} 

告警主机: {HOST.NAME}

主机地址: {HOST.IP}

告警等级: {TRIGGER.SEVERITY}

告警时间: {EVENT.DATE} {EVENT.TIME}

事件ID: {EVENT.ID}

关联项目: {ITEM.NAME} 

项目KEY: {ITEM.KEY}
```