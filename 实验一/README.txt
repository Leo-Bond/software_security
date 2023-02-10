find_file.py运行说明：
1.需要以管理员身份打开该python文件，以获得读磁盘的权限
2.需要先自备一个FAT32格式的U盘，将随代码附上的两个测试文件拷贝到u盘中。
3.将代码中的‘name’项替换为要测试的文件名，如要查找'TEST.docx',则将其改为‘TEST‘
4.修改disk的目录，将其中的’PhysicalDrive x‘中的x改为当前u盘的盘序号
5.程序运行完成后会在与find_file.py同级的目录下生成一个result.doc文件，其中的内容应该与TEST.doc中的内容完全相同
