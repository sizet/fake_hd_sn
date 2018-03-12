// ©
// https://github.com/sizet/fake_hd_sn

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/ata.h>
#include <linux/hdreg.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>




#if !(defined(CONFIG_X86_32) || defined(CONFIG_X86_64))
#error "error, it only work in x86 system"
#endif




#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DMSG(msg_fmt, msg_args...) \
    printk(KERN_ERR "%s(%04u): " msg_fmt "\n", FILE_NAME, __LINE__, ##msg_args)




// 要支援哪些方法.
#define SUPPORT_HDIO_GET_IDENTITY       1
#define SUPPORT_SCSI_IOCTL_SEND_COMMAND 1
#define SUPPORT_SG_IO                   1

// 紀錄 SCSI 回傳的序號的緩衝大小.
// http://www.staff.uni-mainz.de/tacke/scsi/SCSI2.html
// [Clause 8 - All device types].
//   [8.2.5 INQUIRY command].
//     [Table 44 - INQUIRY command].
//       <Allocation length> 的大小是 1byte, 所以直接使用最大長度 255.
#define SCSI_SN_BUFFER_SIZE 255




// SCSI INQUIRY 指令.
// http://www.staff.uni-mainz.de/tacke/scsi/SCSI2.html
// [Clause 8 - All device types].
//   [8.2.5 INQUIRY command].
//     [Table 44 - INQUIRY command].
struct scsi_inquiry_info
{
    unsigned char operation_code;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned char evpd:1,
                  reserved1:4,
                  logical_unit_number:3;
#elif defined (__BIG_ENDIAN_BITFIELD)
    unsigned char logical_unit_number:3,
                  reserved1:4,
                  evpd:1;
#else
#error "please check endian type"
#endif
    unsigned char page_code;
    unsigned char reserved2;
    unsigned char allocation_length;
    unsigned char control;
} __attribute__((packed));

// SCSI 回傳的序號的訊息格式.
// http://www.staff.uni-mainz.de/tacke/scsi/SCSI2.html
// [Clause 8 - All device types].
//   [8.3.4.5 Unit serial number page].
//     [Table 107 - Unit serial number page].
struct scsi_vpd_usn_info
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned char peripheral_device_type:4,
                  peripheral_qualifier:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    unsigned char peripheral_qualifier:4,
                  peripheral_device_type:4;
#else
#error "please check endian type"
#endif
    unsigned char page_code;
    unsigned char reserved1;
    unsigned char page_length;
    unsigned char product_serial_number[];
} __attribute__((packed));




// 紀錄 sys_call_table 的位址.
static void **sys_call_table;

// 紀錄系統原本的 ioctl() 函式的位址.
static asmlinkage int (*org_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);

// 紀錄偽造的硬碟序號.
static char fake_sn_con[SCSI_SN_BUFFER_SIZE + 1];
static int fake_sn_len;




static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos);

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos);

// 在 /proc 底下產生檔案 (fake_hd_sn) 來輸入偽造的硬碟序號.
static char *node_name = "fake_hd_sn";
static struct proc_dir_entry *node_entry;
static struct file_operations node_fops =
{
    .read  = node_read,
    .write = node_write,
};




// 找到 sys_call_table 的位址.
static void **find_sys_call_table(
    void)
{
    void **each_mem;
#if defined(CONFIG_X86_32)
    void **scan_end = (void **) ULONG_MAX;
#elif defined(CONFIG_X86_64)
    void **scan_end = (void **) ULLONG_MAX;
#endif


    // PAGE_OFFSET 是 kerenl 在記憶體的起始位址, 掃描記憶體內容找到儲存 sys_close() 位址的記憶體,
    // 以此找出 sys_call_table 的位址, 使用 sys_close() 是因為它是導出函式所以可以取得其位址.
    for(each_mem = (void **) PAGE_OFFSET; each_mem < scan_end; each_mem++)
        if(each_mem[__NR_close] == ((void *) sys_close))
        {
            // 可以使用以下 2 種方法導出 sys_call_table 的位址來檢查掃描到的位址是否正確.
            // cat /boot/System.map-$(uname -r) | grep sys_call_table
            // grep sys_call_table /proc/kallsyms
            //
            // 在 32bit 系統會顯示 :
            // c0931380 R sys_call_table
            //
            // 在 64bit 系統會顯示 :
            // ffffffff818001c0 R sys_call_table
            // ffffffff81801580 R ia32_sys_call_table
            // sys_call_table 是給 64bit 程式使用, ia32_sys_call_table 給 32bit 程式使用,
            // 在 64bit 系統上因為實體記憶體和虛擬記憶體映射的關係,
            // 導出的和掃描的位址可能會不太一樣, 需要額外做一些計算才能比對,
            // 例如掃描出來的是 ffff8800018001c0, 和找到的 ffffffff818001c0 不太一樣,
            // 在 64bit 系統上的虛擬記憶體的映射表 :
            // https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
            // ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
            // ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
            // 第一段是把實體記憶體映射到虛擬記憶體的 ffff880000000000,
            // 也就是掃描的開始位置, 所以掃描的位址在實體記憶體的位置是 :
            // ffff8800018001c0 - ffff880000000000 = 18001c0.
            // 第二段是核心程式會放在虛擬記憶體的 ffffffff80000000,
            // 也就是導出的位址, 所以導出的位址在實體記憶體的位置是 :
            // ffffffff818001c0 - ffffffff80000000 = 18001c0.
            // 可以發現 2 個位址其實是一樣的.
            // 參考 https://stackoverflow.com/questions/31396090/kernel-sys-call-table-address-does-not-match-address-specified-in-system-map
            return each_mem;
        }

    return NULL;
}

// 關閉或開啟記憶體防寫的保護.
// sys_call_table / ia32_sys_call_table 的記憶體區域 kernel 有做防寫保護,
// 必須先解除防寫保護才可修改.
// protect_mode :
//   0 : 關閉防寫保護.
//   1 : 開啟防寫保護.
static void config_write_protect(
    int protect_mode)
{
    unsigned long cr0;


    // cr0 是 x86 的控制暫存器, 位元 16 (0 ~ 31) 表示是否開啟寫入保護 (Write Protect : WP).
    // 0 = 關閉, 1 = 開啟.

    cr0 = read_cr0();

    // protect_mode == 0 表示關閉防寫保護允許寫入 :
    // clear_bit(nr, *addr) 表示把 addr 位址的值的 bit-nr (0 ~ 31) 設為 0.
    // protect_mode != 0 表示開啟防寫保護防止寫入 :
    // set_bit(nr, *addr) 表示把 addr 位址的值的 bit-nr (0 ~ 31) 設為 1.
    if(protect_mode == 0)
        clear_bit(16, &cr0);
    else
        set_bit(16, &cr0);

    write_cr0(cr0);
}

// 修改 sys_call_table 中紀錄 ioctl 的位址.
static void modify_sys_call_ioctl(
    void *target_addr)
{
    DMSG("%p -> %p", sys_call_table[__NR_ioctl], target_addr);
    // 關閉防寫保護.
    config_write_protect(0);
    // 修改.
    sys_call_table[__NR_ioctl] = target_addr;
    // 還原, 開啟防寫保護.
    config_write_protect(1);
    DMSG("%p", sys_call_table[__NR_ioctl]);
}

// 處理使用 ioctl(HDIO_GET_IDENTITY) 取得序號的情況.
#ifdef SUPPORT_HDIO_GET_IDENTITY
static int process_hdio_get_identity(
    unsigned int fd,
    unsigned int cmd,
    unsigned long arg,
    int *has_call_ioctl_buf)
{
    int cret;
    void __user *user_sn_addr;
    char sn_buf[ATA_ID_SERNO_LEN + 1];


    // 紀錄序號等資料的結構在 include/linux/hdreg.h 或 include/uapi/linux/hdreg.h,
    // struct hd_driveid {
    //     ...
    //     unsigned char serial_no[20];
    //     ...
    // };
    // 但是此結構被 #ifndef __KERNEL__ 此定義關閉, 在核心模組無法使用,
    // 改以其他方式存取 serial_no 的緩衝大小以及在 struct hd_driveid 的偏移植,
    // 在 linux/ata.h,
    // enum {
    //     ...
    //     ATA_ID_SERNO = 10, ** 在 struct hd_driveid 的偏移植, 基本單位是 [unsigned short],
    //                        ** 所以是 sizeof(unsigned short) * ATA_ID_SERNO.
    //     ...
    //     ATA_ID_SERNO_LEN = 20, ** 緩衝大小.
    //     ...
    // };

    DMSG("Detect get hard disk serial number use HDIO_GET_IDENTITY");

    // 先呼叫系統原本的 ioctl() 處理, 如果有錯誤則不進行偽造序號處理.
    *has_call_ioctl_buf = 1;
    cret = org_ioctl(fd, cmd, arg);
    if(cret == -1)
    {
        DMSG("call ioctl() fail, skip fake");
        goto FREE_01;
    }

    // 找到用戶空間的 (struct hd_driveid).serial_no 的位址.
    user_sn_addr = (void __user *) (((unsigned short *) arg) + ATA_ID_SERNO);

    // 取出用戶空間紀錄的原始序號 (這邊單純用來顯示原始序號).
    memset(sn_buf, 0, sizeof(sn_buf));
    if(copy_from_user(sn_buf, user_sn_addr, ATA_ID_SERNO_LEN) != 0)
    {
        DMSG("call copy_from_user() fail");
        goto FREE_01;
    }
    DMSG("real hard disk serial number [%s]", sn_buf);

    // 重新填入偽造的序號並寫入用戶空間.
    memset(sn_buf, 0, sizeof(sn_buf));
    memcpy(sn_buf, fake_sn_con,
           fake_sn_len < ATA_ID_SERNO_LEN ? fake_sn_len : ATA_ID_SERNO_LEN);
    DMSG("fake hard disk serial number [%s]", sn_buf);
    if(copy_to_user(user_sn_addr, sn_buf, ATA_ID_SERNO_LEN) != 0)
    {
        DMSG("call copy_to_user() fail");
        goto FREE_01;
    }

FREE_01:
    return cret;
}
#endif

// 檢查是否是要求取得序號的 SCSI 指令.
#if defined(SUPPORT_SCSI_IOCTL_SEND_COMMAND) || defined(SUPPORT_SG_IO)
static int check_scsi_cmd(
    struct scsi_inquiry_info *scsi_cmd_buf)
{
    // http://www.staff.uni-mainz.de/tacke/scsi/SCSI2.html
    // [Clause 8 - All device types].
    //   [8.2.5 INQUIRY command].
    //     [Table 44 - INQUIRY command].

    // <Operation code> = 0x12 (標準查詢).
    if(scsi_cmd_buf->operation_code != 0x12)
        return 0;

    // <EVPD> = 1 (要求 <Page code> 指定的資料).
    if(scsi_cmd_buf->evpd != 0x1)
        return 0;

    // <Page code> = 0x80 (要求取得序號).
    // [Clause 8 - All device types].
    //   [8.3.4 Vital product data parameters].
    //     [Table 102 - Vital product data page codes].
    //       [80h - Unit serial number page].
    if(scsi_cmd_buf->page_code != 0x80)
        return 0;

    return 1;
}
#endif

// 處理使用 ioctl(SCSI_IOCTL_SEND_COMMAND) 取得序號的情況.
#ifdef SUPPORT_SCSI_IOCTL_SEND_COMMAND
static int process_scsi_ioctl_send_command(
    unsigned int fd,
    unsigned int cmd,
    unsigned long arg,
    int *has_call_ioctl_buf)
{
    int cret = -1;
    void __user *user_addr;
    unsigned char req_buf[sizeof(Scsi_Ioctl_Command) + sizeof(struct scsi_inquiry_info)];
    unsigned char rep_buf[sizeof(struct scsi_vpd_usn_info) + SCSI_SN_BUFFER_SIZE + 1];
    Scsi_Ioctl_Command *scsi_io_cmd;
    struct scsi_vpd_usn_info *usn_data;
    size_t rep_len, sn_len;


    // 取出用戶端送出的 SCSI 資料.
    // 取出 (Scsi_Ioctl_Command).inlen + (Scsi_Ioctl_Command).outlen + SCSI 指令.
    // 取得序號的 SCSI 指令是 6byte.
    user_addr = (void __user *) arg;
    if(copy_from_user(&req_buf, user_addr, sizeof(req_buf)) != 0)
    {
        DMSG("call copy_from_user() fail");
        goto FREE_01;
    }
    scsi_io_cmd = (Scsi_Ioctl_Command *) req_buf;

    // 檢查是否是要求取得序號的 SCSI 指令 不是則不處理.
    if(check_scsi_cmd((struct scsi_inquiry_info *) scsi_io_cmd->data) == 0)
        goto FREE_01;

    // 先呼叫系統原本的 ioctl() 處理.
    *has_call_ioctl_buf = 1;
    cret = org_ioctl(fd, cmd, arg);
    if(cret == -1)
    {
        DMSG("call ioctl() fail, skip fake");
        goto FREE_01;
    }

    // 如果用戶端提供的緩衝大小太小則不處理.
    if(scsi_io_cmd->outlen <= sizeof(struct scsi_vpd_usn_info))
    {
        DMSG("user space buffer too smaller, skip fake");
        goto FREE_01;
    }

    DMSG("Detect get hard disk serial number use SCSI_IOCTL_SEND_COMMAND");

    // 取出用戶空間的 SCSI 回應資料重新修改.
    user_addr = (void __user *) (((unsigned char *) arg) + sizeof(Scsi_Ioctl_Command));
    // 取出 [SCSI 回應資料的頭部] + [SCSI 回應資料的序號].
    // scsi_io_cmd->outlen 會紀錄用戶端提供的緩衝大小,
    // rep_buf 的大小是 [SCSI 回應資料的頭部] + [SCSI 回應資料的序號] + [1],
    // [SCSI 回應資料的序號] 的部分因為 SCSI 請求指令的 allocation_length 欄位會紀錄提供的緩衝大小,
    // 而 allocation_length 是 1byte 最大值是 255, 所以即使用戶提供的緩衝空間大小大於 255,
    // 原始序號長度還是不會超過 255,
    // [1] 是預留給 '\0' 做除錯顯示用 (SCSI 回應的序號尾端並不會補上 '\0').
    // 盡可能取出用戶空間的 SCSI 回應資料.
    rep_len = scsi_io_cmd->outlen < sizeof(rep_buf) ? scsi_io_cmd->outlen : sizeof(rep_buf);
    if(copy_from_user(rep_buf, user_addr, rep_len) != 0)
    {
        DMSG("call copy_from_user() fail");
        goto FREE_01;
    }
    usn_data = (struct scsi_vpd_usn_info *) rep_buf;

    // 顯示原始序號.
    usn_data->product_serial_number[usn_data->page_length] = '\0';
    DMSG("real hard disk serial number [%s]", usn_data->product_serial_number);

    // 設定新的 SCSI 回應資料.
    // 填入偽造序號的長度.
    usn_data->page_length = fake_sn_len;
    // 先把用戶空間記錄的原始序號清除才填入偽造序號.
    memset(usn_data->product_serial_number, 0,
           sizeof(rep_buf) - sizeof(struct scsi_vpd_usn_info));
    // 填入偽造的序號, 先計算用戶端提供多少空間記錄序號部分.
    sn_len = scsi_io_cmd->outlen - sizeof(struct scsi_vpd_usn_info);
    sn_len = fake_sn_len < sn_len ? fake_sn_len : sn_len;
    // 填入偽造的序號.
    memcpy(usn_data->product_serial_number, fake_sn_con, sn_len);
    DMSG("fake hard disk serial number [%s]", usn_data->product_serial_number);
    // 把修改後的 SCSI 回應資料寫入用戶空間.
    if(copy_to_user(user_addr, usn_data, rep_len) != 0)
    {
        DMSG("call copy_to_user() fail");
        goto FREE_01;
    }

FREE_01:
    return cret;
}
#endif

// 處理使用 ioctl(SG_IO) 取得序號的情況.
#ifdef SUPPORT_SG_IO
static int process_sg_io(
    unsigned int fd,
    unsigned int cmd,
    unsigned long arg,
    int *has_call_ioctl_buf)
{
    int cret = -1;
    void __user *user_addr;
    unsigned char rep_buf[sizeof(struct scsi_vpd_usn_info) + SCSI_SN_BUFFER_SIZE + 1];
    struct sg_io_hdr sg_info;
    struct scsi_inquiry_info scsi_cmd;
    struct scsi_vpd_usn_info *usn_data;
    size_t rep_len, sn_len;


    // 取出用戶端送出的 SCSI 資料.
    user_addr = (void __user *) arg;
    if(copy_from_user(&sg_info, user_addr, sizeof(sg_info)) != 0)
    {
        DMSG("call copy_from_user() fail");
        goto FREE_01;
    }

    // 取出用戶端送出的 SCSI 指令部分.
    if(copy_from_user(&scsi_cmd, sg_info.cmdp, sizeof(scsi_cmd)) != 0)
    {
        DMSG("call copy_from_user() fail");
        goto FREE_01;
    }

    // 檢查是否是要求取得序號的 SCSI 指令, 不是則不處理.
    if(sg_info.interface_id != 'S')
        goto FREE_01;
    if(sg_info.dxfer_direction != SG_DXFER_FROM_DEV)
        goto FREE_01;
    if(check_scsi_cmd(&scsi_cmd) == 0)
        goto FREE_01;

    // 先呼叫系統原本的 ioctl() 處理.
    *has_call_ioctl_buf = 1;
    cret = org_ioctl(fd, cmd, arg);
    if(cret == -1)
    {
        DMSG("call ioctl() fail, skip fake");
        goto FREE_01;
    }

    // 如果用戶端提供的緩衝大小太小則不處理.
    if(sg_info.dxfer_len <= sizeof(struct scsi_vpd_usn_info))
    {
        DMSG("user space buffer too smaller, skip fake");
        goto FREE_01;
    }

    DMSG("Detect get hard disk serial number use SG_IO");

    // 取出用戶空間的 SCSI 回應資料重新修改.
    user_addr = (void __user *) sg_info.dxferp;
    // 取出 [SCSI 回應資料的頭部] + [SCSI 回應資料的序號].
    // scsi_io_cmd->outlen 會紀錄用戶端提供的緩衝大小,
    // rep_buf 的大小是 [SCSI 回應資料的頭部] + [SCSI 回應資料的序號] + [1],
    // [SCSI 回應資料的序號] 的部分因為 SCSI 請求指令的 allocation_length 欄位會紀錄提供的緩衝大小,
    // 而 allocation_length 是 1byte 最大值是 255, 所以即使用戶提供的緩衝空間大小大於 255,
    // 原始序號長度還是不會超過 255,
    // [1] 是預留給 '\0' 做除錯顯示用 (SCSI 回應的序號尾端並不會補上 '\0').
    // 盡可能取出用戶空間的 SCSI 回應資料.
    rep_len = sg_info.dxfer_len < sizeof(rep_buf) ? sg_info.dxfer_len : sizeof(rep_buf);
    if(copy_from_user(rep_buf, user_addr, rep_len) != 0)
    {
        DMSG("call copy_from_user() fail");
        goto FREE_01;
    }
    usn_data = (struct scsi_vpd_usn_info *) rep_buf;

    // 顯示原始序號.
    usn_data->product_serial_number[usn_data->page_length] = '\0';
    DMSG("real hard disk serial number [%s]", usn_data->product_serial_number);

    // 設定新的 SCSI 回應資料.
    // 填入偽造序號的長度.
    usn_data->page_length = fake_sn_len;
    // 先把用戶空間記錄的原始序號清除才填入偽造序號.
    memset(usn_data->product_serial_number, 0,
           sizeof(rep_buf) - sizeof(struct scsi_vpd_usn_info));
    // 填入偽造的序號, 先計算用戶端提供多少空間記錄序號部分.
    sn_len = sg_info.dxfer_len - sizeof(struct scsi_vpd_usn_info);
    sn_len = fake_sn_len < sn_len ? fake_sn_len : sn_len;
    // 填入偽造的序號.
    memcpy(usn_data->product_serial_number, fake_sn_con, sn_len);
    DMSG("fake hard disk serial number [%s]", usn_data->product_serial_number);
    // 把修改後的 SCSI 回應資料寫入用戶空間.
    if(copy_to_user(user_addr, usn_data, rep_len) != 0)
    {
        DMSG("call copy_to_user() fail");
        goto FREE_01;
    }

FREE_01:
    return cret;
}
#endif

// 自訂的 ioctl().
static asmlinkage int new_ioctl(
    unsigned int fd,
    unsigned int cmd,
    unsigned long arg)
{
    int cret, has_call_ioctl = 0;


    switch(cmd)
    {
#ifdef SUPPORT_HDIO_GET_IDENTITY
        case HDIO_GET_IDENTITY:
            cret = process_hdio_get_identity(fd, cmd, arg, &has_call_ioctl);
            break;
#endif
#ifdef SUPPORT_SCSI_IOCTL_SEND_COMMAND
        case SCSI_IOCTL_SEND_COMMAND:
            cret = process_scsi_ioctl_send_command(fd, cmd, arg, &has_call_ioctl);
            break;
#endif
#ifdef SUPPORT_SG_IO
        case SG_IO:
            cret = process_sg_io(fd, cmd, arg, &has_call_ioctl);
            break;
#endif
    }

    if(has_call_ioctl == 0)
        cret = (*org_ioctl)(fd, cmd, arg);

    return cret;
}

// 顯示偽造的硬碟序號.
static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos)
{
    DMSG("fake hard disk serial number [%s]/[%zd]", fake_sn_con, fake_sn_len);

    return 0;
}

// 紀錄要偽造的硬碟序號.
static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos)
{
    size_t len;


    len = sizeof(fake_sn_con) - 1;
    if(count >= len)
    {
        DMSG("hard disk serial number too long, [%zd/%zd]", count, len);
        return count;
    }

    if(copy_from_user(fake_sn_con, buffer, count) != 0)
    {
        DMSG("call copy_to_user() fail");
        return count;
    }

    // 檢查用戶端傳來的序號尾端是否已填入 '\0',
    // 如果有 '\0', 序號長度 - 1,
    // 如果無 '\0', 序號尾端補上 '\0'.
    len = count - 1;
    if(fake_sn_con[len] == '\0')
    {
        fake_sn_len--;
    }
    else
    {
        fake_sn_len = count;
        fake_sn_con[fake_sn_len] = '\0';
    }

    // 去掉序號尾端的 '\n' (如果有的話).
    if(fake_sn_con[fake_sn_len - 1] == '\n')
    {
        fake_sn_len--;
        fake_sn_con[fake_sn_len] = '\0';
    }

    DMSG("fake hard disk serial number [%s]/[%zd]", fake_sn_con, fake_sn_len);

    return count;
}

static int __init main_init(
    void)
{
    // 預設的偽造硬碟序號.
    snprintf(fake_sn_con, sizeof(fake_sn_con), "fake-????");
    fake_sn_len = strlen(fake_sn_con);

    // 尋找 sys_call_table 位址.
    sys_call_table = find_sys_call_table();
    DMSG("sys_call_table = %p", sys_call_table);
    if(sys_call_table == NULL)
    {
        DMSG("call find_sys_call_table() fail");
        goto FREE_01;
    }

    // 修改 sys_call_table 中紀錄 ioctl 的位址,
    // 讓程式使用 ioctl() 時改呼叫自訂的 ioctl() 函式.
    DMSG("modify sys_call_table[ioctl]");
    // 先記錄系統原本的 ioctl() 位址.
    org_ioctl = sys_call_table[__NR_ioctl];
    // 修改.
    modify_sys_call_ioctl(new_ioctl);

    node_entry = proc_create(node_name, S_IFREG | S_IRUGO | S_IWUGO, NULL, &node_fops);
    if(node_entry == NULL)
    {
        DMSG("call proc_create(%s) fail", node_name);
        goto FREE_02;
    }

    return 0;
FREE_02:
    // 如果發生問題結束前要先還原對 sys_call_table 的修改.
    modify_sys_call_ioctl(org_ioctl);
FREE_01:
    return 0;
}

static void __exit main_exit(
    void)
{
    remove_proc_entry(node_name, NULL);

    // 結束前要先還原對 sys_call_table 的修改.
    DMSG("recover sys_call_table[ioctl]");
    modify_sys_call_ioctl(org_ioctl);

    return;
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Che-Wei Hsu");
MODULE_DESCRIPTION("fake hard disk serial number");
