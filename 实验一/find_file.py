import struct

def get_offset():
    disk = open(r"\\.\PhysicalDrive1","rb")
    disk.seek(0)
    index = 0
    while(1):
        index = index + 1
        test = disk.read(1)
        if test == b'\xEB':
            index = index + 1
            test2 = disk.read(1)
            if test2 == b'\x58':
                index = index + 1
                test3 = disk.read(1)
                if test3 == b'\x90':
                    index = index + 1
                    break
    return index

def get_info(index):
    disk.seek(0)
    temp = disk.read(index - 4)
    DBR = disk.read(0x1FE + 2)

    bytes_n_S_sector = DBR[int(0x0B):int(0x0B + 2)]
    n_S_sector = int.from_bytes(bytes_n_S_sector, byteorder='little')

    bytes_n_S_clus = DBR[int(0x0D):int(0x0D + 1)]
    n_S_clus = int.from_bytes(bytes_n_S_clus, byteorder='little')

    bytes_n_reserved_sectors = DBR[int(0x0E):int(0x0E + 2)]
    n_reserved_sectors = int.from_bytes(bytes_n_reserved_sectors, byteorder='little')

    bytes_n_FATS = DBR[int(0x10):int(0x10 + 1)]
    n_FATS = int.from_bytes(bytes_n_FATS, byteorder='little')

    bytes_n_S_FATS = DBR[int(0x24):int(0x24 + 4)]
    n_S_FATS = int.from_bytes(bytes_n_S_FATS, byteorder='little')

    bytes_BPB_RootClus = DBR[int(0x2C):int(0x2C + 4)]
    BPB_RootClus = int.from_bytes(bytes_BPB_RootClus, byteorder='little')

    return n_S_sector, n_S_clus, n_reserved_sectors, n_FATS, n_S_FATS, BPB_RootClus

def get_FirstSectorofCluster(n_S_clus, n_reserved_sectors, n_FAT, n_S_FATS, N):
    FirstDataSector = n_reserved_sectors + ( n_FAT * n_S_FATS )
    return ((N - 2) * n_S_clus + FirstDataSector)


def get_Begin_clus_and_length(index, name, FirstSectorofCluster):
    disk.seek(0)
    temp = disk.read(index - 4 + FirstSectorofCluster * n_S_sector)
    name_temp = disk.read(0xffffff)
    name_ascii = []
    for character in name:
        name_ascii.append(ord(character))
    sign = -1
    i = 0
    while (1):

        assert 0 <= i <= 0xffff  # Can't find file

        Entry = name_temp[0 + 32 * i:32 + 32 * i]
        for j in range(len(name_ascii)):
            if name_ascii[j] != Entry[j]:
                break
            else:
                if j == len(name_ascii) - 1:
                    print("短文件名目录项信息：", Entry)
                    sign = i
                    break
        i = i + 1
        if (sign != -1):
            break

    found_Entry = name_temp[0 + 32 * sign: 32 + 32 * sign]

    Begin_clus_high = found_Entry[int(0x14):int(0x14) + 2]
    Begin_clus_low = found_Entry[int(0x1A):int(0x1A) + 2]
    Begin_clus_byte = Begin_clus_low + Begin_clus_high
    Begin_clus = int.from_bytes(Begin_clus_byte, byteorder='little')

    file_length = int.from_bytes(found_Entry[int(0x1C):int(0x1C) + 4], byteorder='little')

    return Begin_clus, file_length

def get_file_clus(index, Begin_clus, n_reserved_sectors, n_S_sector, n_FATS, n_S_FATS):
    disk.seek(0)
    temp = disk.read(index - 4 + n_reserved_sectors * n_S_sector)
    FAT = disk.read(n_FATS * n_S_FATS * n_S_sector)
    file_clus = []
    file_clus.append(Begin_clus)
    next_file_clus = Begin_clus
    i = 1
    while(1):
        i = i + 1

        assert 0 <= i <= 0xffff

        if FAT[4*next_file_clus:4*next_file_clus+4] == b'\xff\xff\xff\x0f':
            break
        next_file_clus = int.from_bytes(FAT[4*Begin_clus:4*Begin_clus+4], byteorder='little')
        file_clus.append(next_file_clus)
    print("簇链:", file_clus)
    return file_clus

def save_to_file(file_name, contents):
    fh = open(file_name, 'ab+')
    for i in range(len(contents)):
        temp = struct.pack('B', contents[i])
        fh.write(temp)
    fh.close()

def find_file(index, file_clus, n_S_clus, n_S_sector, file_length, BPB_RootClus):
    disk.seek(0)
    temp = disk.read(index - 4 + FirstSectorofCluster * n_S_sector)
    data = disk.read((file_clus[0] - BPB_RootClus) * n_S_clus * n_S_sector + file_length + 2 * n_S_clus * n_S_sector)
    End_length = file_length % (n_S_clus * n_S_sector)

    if End_length == 0:
        End_length = n_S_clus * n_S_sector
    offset = (file_clus[0] - BPB_RootClus) * n_S_clus * n_S_sector
    file_byte = data[ offset : offset + End_length]

    for i in range(1, len(file_clus)):
        offset = (file_clus[i] - BPB_RootClus) * n_S_clus * n_S_sector
        if i == len(file_clus) - 1:
            temp_file = data[ offset : offset + End_length]
            file_byte = file_byte + temp_file


        else:
            temp_file = data[ offset : offset + n_S_clus * n_S_sector]
            file_byte = file_byte + temp_file


    save_to_file('result.doc', file_byte)

if __name__ == '__main__':
    name = 'TEST2'
    disk = open(r"\\.\PhysicalDrive1","rb")
    offset = get_offset()
    n_S_sector, n_S_clus, n_reserved_sectors, n_FATS, n_S_FATS, BPB_RootClus = get_info(offset)
    FirstSectorofCluster = get_FirstSectorofCluster(n_S_clus, n_reserved_sectors, n_FATS, n_S_FATS, BPB_RootClus)
    Begin_clus, file_length = get_Begin_clus_and_length(offset, name, FirstSectorofCluster)
    file_clus = get_file_clus(offset, Begin_clus, n_reserved_sectors, n_S_sector, n_FATS, n_S_FATS)
    find_file(offset, file_clus, n_S_clus, n_S_sector, file_length, BPB_RootClus)