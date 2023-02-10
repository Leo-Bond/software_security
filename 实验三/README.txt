1）buf.bin是填充字段，最后的####是需要填充的位置
2）shellcode.bin是通过pebear抽取出的shellcode.cpp生成的二进制代码
3）需要在自己电脑上自行生成rop链，然后放在buf.bin填充字段的#所在位置，然后再将shellcode.bin接在rop链之后