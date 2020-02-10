# PythonPersistence
python3 写的一些权限维持脚本

| ATT&CK 编号                                         | 名称                | 参数        |
| --------------------------------------------------- | ------------------- | ----------- |
| [T1060](https://attack.mitre.org/techniques/T1060/) | startup             | exe,command |
| [T1182](https://attack.mitre.org/techniques/T1182/) | AppCertDlls         | dll         |
| [T1103](https://attack.mitre.org/techniques/T1103/) | AppInit_DLLs        | dll         |
| [T1128](https://attack.mitre.org/techniques/T1128/) | NetSh               | dll         |
| [T1031](https://attack.mitre.org/techniques/T1031/) | modify_service      | exe         |
| [T1050](https://attack.mitre.org/techniques/T1050/) | add_service_cmd     | exe         |
| [T1050](https://attack.mitre.org/techniques/T1050/) | add_service_win32   | exe,command |
| [T1122](https://attack.mitre.org/techniques/T1122/) | com_Hijack          | dll         |
| [T1122](https://attack.mitre.org/techniques/T1122/) | com_explorer_Hijack | dll         |
| [T1004](https://attack.mitre.org/techniques/T1004/) | winlogon_helper_dll | exe         |
| [T1197](https://attack.mitre.org/techniques/T1197/) | bitsadmin           | exe,command |
| [T1136](https://attack.mitre.org/techniques/T1136/) | account             | user        |

注册表修改使用的是win32 api，可用在64和32为系统
