package com.kbox.core.shield;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * PeImage — PE32/PE32+ 解析器（由 packer/pe_image.cpp 移植）。
 *
 * <p>原注释：pe_image.h — PE32/PE32+ 解析器。只读解析 + 校验，供 packer 使用。
 * 所有目录字段均做边界检查，返回错误字符串而不是越界崩溃。</p>
 *
 * <p>移植说明（类型与接口映射，逐行对应 pe_image.cpp）：
 * <ul>
 *   <li>结构体不建实体类：ImageDosHeader / ImageFileHeader / ImageOptionalHeader32/64 /
 *       ImageSectionHeader / ImageImportDescriptor / ImageImportByName 均按 pack(1)
 *       字段偏移用 {@link Bin} 直接读取（C++ 侧也是按字段偏移访问同一份字节）。</li>
 *   <li>{@code const uint8_t*} → {@code int} 数据偏移，nullptr → {@code -1}
 *       （见 {@link #directoryData(int, int[])}）；{@code size_t*} 输出参数 → {@code int[]}
 *       单元素槽（可为 null，对应 C++ 允许传 nullptr）。</li>
 *   <li>{@code bool f(..., std::string* err)} → {@code boolean f(..., StringBuilder err)}，
 *       err 可为 null，赋值语义等价于 C++ 的 {@code if (err) *err = "...";}。</li>
 *   <li>{@code std::vector<ImportDll>*} → {@code List<ImportDll>}；
 *       {@code std::vector<uint8_t>*} → {@link ByteArrayOutputStream}（clear/assign 语义一致）。</li>
 *   <li>无符号语义：uint32_t 逻辑右移用 {@code >>>}，无符号比较用
 *       {@link Integer#compareUnsigned(int, int)} / {@link Long#compareUnsigned(long, long)}。</li>
 * </ul>
 *
 * <p>注：{@code section_contains} 在原 pe_image.h 中有声明但 pe_image.cpp 未给出定义
 * （全工程无调用点），本移植按 section_by_rva 的区间语义补全，以保持头文件 API 完整。</p>
 */
public class PeImage {

    // ---- 原 pe_image.cpp 匿名命名空间常量 ----

    private static final int DOS_MAGIC = 0x5A4D;            // "MZ"
    private static final int NT_SIGNATURE = 0x00004550;     // "PE\0\0"
    private static final int OPT_MAGIC32 = 0x10B;
    private static final int OPT_MAGIC64 = 0x20B;
    private static final int MAX_RVA_AND_SIZES = 16;

    // ---- 目录索引（原 enum DirectoryIndex） ----

    public static final int DIR_EXPORT = 0;
    public static final int DIR_IMPORT = 1;
    public static final int DIR_RESOURCE = 2;
    public static final int DIR_EXCEPTION = 3;
    public static final int DIR_SECURITY = 4;
    public static final int DIR_BASERELOC = 5;
    public static final int DIR_DEBUG = 6;
    public static final int DIR_ARCHITECTURE = 7;
    public static final int DIR_GLOBALPTR = 8;
    public static final int DIR_TLS = 9;
    public static final int DIR_LOADCONFIG = 10;
    public static final int DIR_BOUNDIMPORT = 11;
    public static final int DIR_IAT = 12;
    public static final int DIR_DELAYIMPORT = 13;
    public static final int DIR_CLR = 14;
    public static final int DIR_RESERVED = 15;

    // ---- 节特征位（原 pe_image.h 命名空间常量） ----

    public static final int SCN_MEM_EXECUTE = 0x20000000;
    public static final int SCN_MEM_READ = 0x40000000;
    public static final int SCN_MEM_WRITE = 0x80000000;
    public static final int SCN_CNT_CODE = 0x00000020;
    public static final int SCN_CNT_INITIALIZED = 0x00000040;
    public static final int SCN_CNT_UNINITIALIZED = 0x00000080;

    public static final int DllCharDynamicBase = 0x0040;

    // ---- 结构体字段偏移与 sizeof（pack(1)，按 pe_image.h 结构定义逐字段累加） ----

    // ImageDosHeader
    private static final int DOS_E_MAGIC = 0;
    private static final int DOS_E_LFANEW = 60;
    private static final int SIZEOF_DOS_HEADER = 64;

    // ImageFileHeader
    private static final int FH_MACHINE = 0;
    private static final int FH_NUMBER_OF_SECTIONS = 2;
    private static final int FH_SIZE_OF_OPTIONAL_HEADER = 16;
    private static final int FH_CHARACTERISTICS = 18;
    private static final int SIZEOF_FILE_HEADER = 20;
    /** FileHeader.Characteristics 位：DLL 映像。 */
    public static final int IMAGE_FILE_DLL = 0x2000;

    // ImageDataDirectory（数组元素内部偏移）
    private static final int DD_VIRTUAL_ADDRESS = 0;
    private static final int DD_SIZE = 4;
    private static final int SIZEOF_DATA_DIRECTORY = 8;

    // ImageOptionalHeader32
    private static final int OH32_ADDRESS_OF_ENTRY_POINT = 16;
    private static final int OH32_IMAGE_BASE = 28;
    private static final int OH32_SECTION_ALIGNMENT = 32;
    private static final int OH32_FILE_ALIGNMENT = 36;
    private static final int OH32_SIZE_OF_IMAGE = 56;
    private static final int OH32_SIZE_OF_HEADERS = 60;
    private static final int OH32_SUBSYSTEM = 68;
    private static final int OH32_DLL_CHARACTERISTICS = 70;
    private static final int OH32_NUMBER_OF_RVA_AND_SIZES = 92;
    private static final int OH32_DATA_DIRECTORY = 96;
    private static final int SIZEOF_OPTIONAL_HEADER32 = 224;

    // ImageOptionalHeader64
    private static final int OH64_ADDRESS_OF_ENTRY_POINT = 16;
    private static final int OH64_IMAGE_BASE = 24;
    private static final int OH64_SECTION_ALIGNMENT = 32;
    private static final int OH64_FILE_ALIGNMENT = 36;
    private static final int OH64_SIZE_OF_IMAGE = 56;
    private static final int OH64_SIZE_OF_HEADERS = 60;
    private static final int OH64_SUBSYSTEM = 68;
    private static final int OH64_DLL_CHARACTERISTICS = 70;
    private static final int OH64_NUMBER_OF_RVA_AND_SIZES = 108;
    private static final int OH64_DATA_DIRECTORY = 112;
    private static final int SIZEOF_OPTIONAL_HEADER64 = 240;

    // SubsystemVersion 在两种架构的 optional header 中均位于 48/50（两个 WORD）
    private static final int OH_MAJOR_SUBSYSTEM_VERSION = 48;
    private static final int OH_MINOR_SUBSYSTEM_VERSION = 50;

    // ImageSectionHeader
    private static final int SH_NAME = 0;
    private static final int SH_VIRTUAL_SIZE = 8;
    private static final int SH_VIRTUAL_ADDRESS = 12;
    private static final int SH_SIZE_OF_RAW_DATA = 16;
    private static final int SH_POINTER_TO_RAW_DATA = 20;
    private static final int SH_CHARACTERISTICS = 36;
    private static final int SIZEOF_SECTION_HEADER = 40;

    // ImageImportDescriptor
    private static final int ID_ORIGINAL_FIRST_THUNK = 0;
    private static final int ID_NAME = 12;
    private static final int ID_FIRST_THUNK = 16;
    private static final int SIZEOF_IMPORT_DESCRIPTOR = 20;

    // ImageImportByName
    private static final int IBN_HINT = 0;
    private static final int IBN_NAME = 2;
    private static final int SIZEOF_IMPORT_BY_NAME = 3;

    // ================= 内部类型 =================

    /** 对应 C++ enum Arch { Arch32, Arch64 }。 */
    public enum Arch {
        Arch32, Arch64
    }

    /** 对应 pe_image.h 的 struct SectionInfo。 */
    public static final class SectionInfo {
        public String name = "";
        public int virtualSize = 0;
        public int virtualAddress = 0;
        public int rawSize = 0;
        public int rawPtr = 0;
        public int characteristics = 0;

        /** 对应 C++ has_raw()：{@code raw_size > 0}（uint32_t 无符号比较）。 */
        public boolean hasRaw() {
            return Integer.compareUnsigned(rawSize, 0) > 0;
        }
    }

    /** 对应 pe_image.h 的 struct ImportEntry。 */
    public static final class ImportEntry {
        public int ordinal = 0;    // 0 = 按名
        public int hint = 0;
        public String name = "";   // 按名时的函数名
    }

    /** 对应 pe_image.h 的 struct ImportDll。 */
    public static final class ImportDll {
        public String name = "";
        public int intRva = 0;     // OriginalFirstThunk
        public int iatRva = 0;     // FirstThunk（重建 IAT 时的写入目标）
        public List<ImportEntry> entries = new ArrayList<ImportEntry>();
    }

    /** x64 异常目录（.pdata）的 IMAGE_RUNTIME_FUNCTION_ENTRY（12 字节/条）。 */
    public static final class RfEntry {
        /** 函数起始 RVA（BeginAddress）。 */
        public int begin = 0;
        /** 函数结束 RVA（EndAddress，独占）。 */
        public int end = 0;
        /** 展开信息 RVA（UnwindInfoAddress）。 */
        public int unwind = 0;
    }

    // ================= 状态 =================

    private byte[] data = null;   // const uint8_t* data_
    private int size = 0;         // size_t size_
    private Arch arch = Arch.Arch32;
    private int machine = 0;
    /** FileHeader.Characteristics（含 {@link #IMAGE_FILE_DLL}）。 */
    private int fileCharacteristics = 0;
    private long imageBase = 0;
    private int entryRva = 0;
    private int sectionAlignment = 0x1000;
    private int fileAlignment = 0x200;
    private int sizeOfImage = 0;
    private int sizeOfHeaders = 0;
    private int subsystem = 0;
    private int dllCharacteristics = 0;
    /** OptionalHeader.SubsystemVersion（主/次）。Win11 24H2 加载器对 sv>=7 镜像强制校验 SecurityCookie。 */
    private int majorSubsystemVersion = 0;
    private int minorSubsystemVersion = 0;
    /** ImageDataDirectory directories_[16]（拆成两个并列数组，索引即目录项序号）。 */
    private final int[] dirVirtualAddress = new int[16];
    private final int[] dirSize = new int[16];
    private final List<SectionInfo> sections = new ArrayList<SectionInfo>();

    /** 对应 C++ 的 {@code if (err) *err = msg;}（err 可为 null，赋值 = 清空后写入）。 */
    private static void setErr(StringBuilder err, String msg) {
        if (err != null) {
            err.setLength(0);
            err.append(msg);
        }
    }

    /** 对应 C++ 的 {@code in_bounds(off, len)}：off <= size_ && len <= size_ - off。 */
    private boolean inBounds(int off, int len) {
        return Integer.compareUnsigned(off, size) <= 0
                && Integer.compareUnsigned(len, size - off) <= 0;
    }

    /** 对应 C++ 的 {@code read_bytes(off, len, out)}：只做边界检查（Java 侧按偏移直接读）。 */
    private boolean readBytes(int off, int len) {
        return inBounds(off, len);
    }

    /**
     * 对应 C++ 匿名命名空间的 {@code valid_ascii_import_name(p, avail)}。
     * 导入名是 '\0' 结尾 ASCII，限制长度避免越界。
     */
    private static boolean validAsciiImportName(byte[] data, int off, int avail) {
        for (int i = 0; i < avail; ++i) {
            int c = data[off + i] & 0xFF;
            if (c == 0) return true;
            if (c < 0x20 || c > 0x7E) return false;
        }
        return false; // 没找到结尾
    }

    /** 对应 {@code std::memcpy(directories_, oh->DataDirectory, n * 8)}（directories_ 已清零）。 */
    private void copyDirectories(int off, int n) {
        for (int i = 0; i < n; ++i) {
            int e = off + i * SIZEOF_DATA_DIRECTORY;
            dirVirtualAddress[i] = Bin.i32(data, e + DD_VIRTUAL_ADDRESS);
            dirSize[i] = Bin.i32(data, e + DD_SIZE);
        }
    }

    // ================= 解析 =================

    /** 解析 data[0,size)。失败返回 false 并写入 err。 */
    public boolean parse(byte[] data, int size, StringBuilder err) {
        this.data = data;
        this.size = size;
        sections.clear();
        arch = Arch.Arch32;
        imageBase = 0;
        entryRva = 0;
        sectionAlignment = 0x1000;
        fileAlignment = 0x200;
        sizeOfImage = 0;
        sizeOfHeaders = 0;
        subsystem = 0;
        dllCharacteristics = 0;
        machine = 0;
        for (int i = 0; i < 16; ++i) {
            dirVirtualAddress[i] = 0;
            dirSize[i] = 0;
        }

        // const ImageDosHeader* dos = nullptr;
        if (!readBytes(0, SIZEOF_DOS_HEADER) || Bin.u16(data, DOS_E_MAGIC) != DOS_MAGIC) {
            setErr(err, "not a DOS header (MZ)");
            return false;
        }
        int eLfanew = Bin.i32(data, DOS_E_LFANEW);
        if (eLfanew == 0 || Integer.compareUnsigned(eLfanew, size) >= 0) {
            setErr(err, "invalid e_lfanew");
            return false;
        }

        if (!readBytes(eLfanew, 4)) {
            setErr(err, "NT headers out of bounds");
            return false;
        }
        int sig = Bin.i32(data, eLfanew);
        if (sig != NT_SIGNATURE) {
            setErr(err, "not a PE image");
            return false;
        }

        int nt = eLfanew;
        // const ImageFileHeader* fh = nullptr;
        if (!readBytes(nt + 4, SIZEOF_FILE_HEADER)) {
            setErr(err, "file header out of bounds");
            return false;
        }
        machine = Bin.u16(data, nt + 4 + FH_MACHINE);
        fileCharacteristics = Bin.u16(data, nt + 4 + FH_CHARACTERISTICS);
        if (machine != 0x14C && machine != 0x8664) {
            setErr(err, "unsupported machine (need i386 or x86-64)");
            return false;
        }
        arch = (machine == 0x8664) ? Arch.Arch64 : Arch.Arch32;

        int optOff = nt + 4 + SIZEOF_FILE_HEADER;
        if (!readBytes(optOff, 2)) {
            setErr(err, "optional header out of bounds");
            return false;
        }
        int optMagic = Bin.u16(data, optOff);
        if (optMagic != OPT_MAGIC32 && optMagic != OPT_MAGIC64) {
            setErr(err, "unrecognized optional header magic");
            return false;
        }
        if ((optMagic == OPT_MAGIC32) != (arch == Arch.Arch32)) {
            setErr(err, "optional header magic / machine mismatch");
            return false;
        }

        if (arch == Arch.Arch32) {
            // const ImageOptionalHeader32* oh = nullptr;
            if (!readBytes(optOff, SIZEOF_OPTIONAL_HEADER32)) {
                setErr(err, "optional header (32) out of bounds");
                return false;
            }
            entryRva = Bin.i32(data, optOff + OH32_ADDRESS_OF_ENTRY_POINT);
            imageBase = Bin.u32(data, optOff + OH32_IMAGE_BASE); // uint32_t → uint64_t 零扩展
            sectionAlignment = Bin.i32(data, optOff + OH32_SECTION_ALIGNMENT);
            fileAlignment = Bin.i32(data, optOff + OH32_FILE_ALIGNMENT);
            sizeOfImage = Bin.i32(data, optOff + OH32_SIZE_OF_IMAGE);
            sizeOfHeaders = Bin.i32(data, optOff + OH32_SIZE_OF_HEADERS);
            subsystem = Bin.u16(data, optOff + OH32_SUBSYSTEM);
            dllCharacteristics = Bin.u16(data, optOff + OH32_DLL_CHARACTERISTICS);
            majorSubsystemVersion = Bin.u16(data, optOff + OH_MAJOR_SUBSYSTEM_VERSION);
            minorSubsystemVersion = Bin.u16(data, optOff + OH_MINOR_SUBSYSTEM_VERSION);
            int n = Bin.i32(data, optOff + OH32_NUMBER_OF_RVA_AND_SIZES);
            if (Integer.compareUnsigned(n, MAX_RVA_AND_SIZES) > 0) n = MAX_RVA_AND_SIZES;
            copyDirectories(optOff + OH32_DATA_DIRECTORY, n);
        } else {
            // const ImageOptionalHeader64* oh = nullptr;
            if (!readBytes(optOff, SIZEOF_OPTIONAL_HEADER64)) {
                setErr(err, "optional header (64) out of bounds");
                return false;
            }
            entryRva = Bin.i32(data, optOff + OH64_ADDRESS_OF_ENTRY_POINT);
            imageBase = Bin.i64(data, optOff + OH64_IMAGE_BASE);
            sectionAlignment = Bin.i32(data, optOff + OH64_SECTION_ALIGNMENT);
            fileAlignment = Bin.i32(data, optOff + OH64_FILE_ALIGNMENT);
            sizeOfImage = Bin.i32(data, optOff + OH64_SIZE_OF_IMAGE);
            sizeOfHeaders = Bin.i32(data, optOff + OH64_SIZE_OF_HEADERS);
            subsystem = Bin.u16(data, optOff + OH64_SUBSYSTEM);
            dllCharacteristics = Bin.u16(data, optOff + OH64_DLL_CHARACTERISTICS);
            majorSubsystemVersion = Bin.u16(data, optOff + OH_MAJOR_SUBSYSTEM_VERSION);
            minorSubsystemVersion = Bin.u16(data, optOff + OH_MINOR_SUBSYSTEM_VERSION);
            int n = Bin.i32(data, optOff + OH64_NUMBER_OF_RVA_AND_SIZES);
            if (Integer.compareUnsigned(n, MAX_RVA_AND_SIZES) > 0) n = MAX_RVA_AND_SIZES;
            copyDirectories(optOff + OH64_DATA_DIRECTORY, n);
        }

        // 节表
        int secOff = optOff + Bin.u16(data, nt + 4 + FH_SIZE_OF_OPTIONAL_HEADER);
        int nsec = Bin.u16(data, nt + 4 + FH_NUMBER_OF_SECTIONS);
        if (Integer.compareUnsigned(nsec, 96) > 0
                || !inBounds(secOff, nsec * SIZEOF_SECTION_HEADER)) {
            setErr(err, "section table out of bounds");
            return false;
        }
        for (int i = 0; i < nsec; ++i) {
            int shOff = secOff + i * SIZEOF_SECTION_HEADER;
            readBytes(shOff, SIZEOF_SECTION_HEADER); // 表整体已校验，同原 read_bytes 调用
            SectionInfo s = new SectionInfo();
            s.name = Bin.sectionName(data, shOff + SH_NAME); // char name[8] + name[8]=0
            s.virtualSize = Bin.i32(data, shOff + SH_VIRTUAL_SIZE);
            s.virtualAddress = Bin.i32(data, shOff + SH_VIRTUAL_ADDRESS);
            s.rawSize = Bin.i32(data, shOff + SH_SIZE_OF_RAW_DATA);
            s.rawPtr = Bin.i32(data, shOff + SH_POINTER_TO_RAW_DATA);
            s.characteristics = Bin.i32(data, shOff + SH_CHARACTERISTICS);
            sections.add(s);
        }
        return true;
    }

    // ================= 访问器 =================

    public Arch arch() {
        return arch;
    }

    public boolean is64Bit() {
        return arch == Arch.Arch64;
    }

    public byte[] raw() {
        return data;
    }

    public int size() {
        return size;
    }

    public long imageBase() {
        return imageBase;
    }

    public int entryRva() {
        return entryRva;
    }

    public int sectionAlignment() {
        return sectionAlignment;
    }

    public int fileAlignment() {
        return fileAlignment;
    }

    public int sizeOfImage() {
        return sizeOfImage;
    }

    public int sizeOfHeaders() {
        return sizeOfHeaders;
    }

    public int subsystem() {
        return subsystem;
    }

    /** OptionalHeader.MajorSubsystemVersion（如 10.0 的 10；6.1 的 6）。 */
    public int majorSubsystemVersion() {
        return majorSubsystemVersion;
    }

    /** OptionalHeader.MinorSubsystemVersion。 */
    public int minorSubsystemVersion() {
        return minorSubsystemVersion;
    }

    public int dllCharacteristics() {
        return dllCharacteristics;
    }

    public int machine() {
        return machine;
    }

    /** FileHeader.Characteristics（位含义见 {@link #IMAGE_FILE_DLL} 等）。 */
    public int characteristics() {
        return fileCharacteristics;
    }

    /** 是否为 DLL 映像（FileHeader.Characteristics 含 IMAGE_FILE_DLL）。 */
    public boolean isDll() {
        return (fileCharacteristics & IMAGE_FILE_DLL) != 0;
    }

    public int numberOfSections() {
        return sections.size();
    }

    public int pointerSize() {
        return is64Bit() ? 8 : 4;
    }

    public List<SectionInfo> sections() {
        return sections;
    }

    /** 该 rva 落在哪个节（无则返回 null，对应 C++ nullptr）。 */
    public SectionInfo sectionByRva(int rva) {
        for (SectionInfo s : sections) {
            int vsz = (s.virtualSize != 0) ? s.virtualSize : s.rawSize;
            if (Integer.compareUnsigned(rva, s.virtualAddress) >= 0
                    && Integer.compareUnsigned(rva, s.virtualAddress + vsz) < 0) {
                return s;
            }
        }
        return null;
    }

    /** 按节名查找（对应 {@code std::strncmp(s.name, name, 8) == 0}），无则返回 null。 */
    public SectionInfo sectionByName(String name) {
        for (SectionInfo s : sections) {
            if (s.name.equals(name)) return s;
        }
        return null;
    }

    // ================= 数据目录 =================

    /**
     * 目录数据（只读访问）。返回目录数据在 {@link #raw()} 中的起始偏移，越界/不存在返回 -1
     * （对应 C++ 返回 nullptr）。outSize 可为 null，输出目录长度（size_t* out_size）。
     */
    public int directoryData(int idx, int[] outSize) {
        if (idx < 0 || idx >= 16) return -1;
        int va = dirVirtualAddress[idx];
        int sz = dirSize[idx];
        if (va == 0 || sz == 0) return -1;
        int[] off = new int[1];
        if (!rvaToOffset(va, off)) return -1;
        if (!inBounds(off[0], sz)) return -1;
        if (outSize != null) outSize[0] = sz;
        return off[0];
    }

    public boolean hasDirectory(int idx) {
        return idx >= 0 && idx < 16 && dirVirtualAddress[idx] != 0
                && dirSize[idx] != 0;
    }

    public int directoryRva(int idx) {
        return (idx >= 0 && idx < 16) ? dirVirtualAddress[idx] : 0;
    }

    public int directorySize(int idx) {
        return (idx >= 0 && idx < 16) ? dirSize[idx] : 0;
    }

    // ================= RVA/文件偏移互转 =================

    /** RVA → 文件偏移（越界返回 false）。off 为单元素输出槽（size_t* off）。 */
    public boolean rvaToOffset(int rva, int[] off) {
        // 目录可落在头部（SizeOfHeaders 内）
        if (Integer.compareUnsigned(rva, sizeOfHeaders) < 0) {
            if (Integer.compareUnsigned(rva, size) >= 0) return false;
            off[0] = rva;
            return true;
        }
        for (SectionInfo s : sections) {
            if (!s.hasRaw()) continue;
            int vsz = (s.virtualSize != 0) ? s.virtualSize : s.rawSize;
            if (Integer.compareUnsigned(rva, s.virtualAddress) >= 0
                    && Integer.compareUnsigned(rva, s.virtualAddress + vsz) < 0) {
                int o = s.rawPtr + (rva - s.virtualAddress);
                if (!inBounds(o, 1)) return false;
                off[0] = o;
                return true;
            }
        }
        return false;
    }

    /** 文件偏移 → RVA（越界返回 false）。rva 为单元素输出槽（uint32_t* rva）。 */
    public boolean offsetToRva(int off, int[] rva) {
        if (Integer.compareUnsigned(off, sizeOfHeaders) < 0) {
            rva[0] = off;
            return true;
        }
        for (SectionInfo s : sections) {
            if (!s.hasRaw()) continue;
            if (Integer.compareUnsigned(off, s.rawPtr) >= 0
                    && Integer.compareUnsigned(off, s.rawPtr + s.rawSize) < 0) {
                rva[0] = s.virtualAddress + (off - s.rawPtr);
                return true;
            }
        }
        return false;
    }

    /**
     * 解析 x64 异常目录（.pdata）为 RUNTIME_FUNCTION 表。
     *
     * <p>仅 x64 有意义（x86 使用 SEH，无该目录）；无异常目录时返回 true 且 out 为空。
     * 条目为 12 字节定长：{BeginAddress, EndAddress, UnwindInfoAddress}（均为 RVA）。
     * 目录长度非 12 的整数倍时按整条解析并忽略尾部余数。</p>
     */
    public boolean parseRuntimeFunctions(List<RfEntry> out, StringBuilder err) {
        out.clear();
        if (!hasDirectory(DIR_EXCEPTION)) {
            return true;
        }
        int[] off = new int[1];
        if (!rvaToOffset(directoryRva(DIR_EXCEPTION), off)) {
            setErr(err, "exception dir rva invalid");
            return false;
        }
        int sz = directorySize(DIR_EXCEPTION);
        if (!inBounds(off[0], sz)) {
            setErr(err, "exception dir out of bounds");
            return false;
        }
        final int entrySize = 12;
        final int n = sz / entrySize;
        for (int i = 0; i < n; ++i) {
            int e = off[0] + i * entrySize;
            RfEntry rf = new RfEntry();
            rf.begin = Bin.i32(data, e);
            rf.end = Bin.i32(data, e + 4);
            rf.unwind = Bin.i32(data, e + 8);
            out.add(rf);
        }
        return true;
    }

    /**
     * 该 rva 是否落在给定 RUNTIME_FUNCTION 区间内（begin &lt;= rva &lt; end）。
     * 用于跳过入口点函数等不允许虚拟化的目标。
     */
    public boolean rfContains(RfEntry rf, int rva) {
        return Integer.compareUnsigned(rva, rf.begin) >= 0
                && Integer.compareUnsigned(rva, rf.end) < 0;
    }

    /** RUNTIME_FUNCTION 的字节长度（end - begin，无符号）。 */
    public static int rfLength(RfEntry rf) {
        return Integer.compareUnsigned(rf.end, rf.begin) > 0 ? rf.end - rf.begin : 0;
    }

    // ================= 目录级解析 =================

    /**
     * 解析导入表。out 先被清空；无导入目录时返回 true 且 out 为空。
     * err 可为 null（对应 C++ {@code std::string* err}）。
     */
    public boolean parseImports(List<ImportDll> out, StringBuilder err) {
        out.clear();
        int[] dirSizeSlot = new int[1];
        int dir = directoryData(DIR_IMPORT, dirSizeSlot);
        if (dir < 0) return true; // 无导入

        final int descSize = SIZEOF_IMPORT_DESCRIPTOR;
        final int maxDesc = dirSizeSlot[0] / descSize;
        for (int i = 0; i < maxDesc; ++i) {
            int dOff = dir + i * descSize;
            // ImageImportDescriptor d; std::memcpy(&d, dir + i*desc_size, desc_size);
            int dOriginalFirstThunk = Bin.i32(data, dOff + ID_ORIGINAL_FIRST_THUNK);
            int dName = Bin.i32(data, dOff + ID_NAME);
            int dFirstThunk = Bin.i32(data, dOff + ID_FIRST_THUNK);
            if (dName == 0 && dFirstThunk == 0 && dOriginalFirstThunk == 0) break;

            ImportDll idll = new ImportDll();
            {
                int[] noff = new int[1];
                if (!rvaToOffset(dName, noff)) {
                    setErr(err, "import dll name rva invalid");
                    return false;
                }
                if (!readBytes(noff[0], 1)) {
                    setErr(err, "import dll name out of bounds");
                    return false;
                }
                // 长度受限的 ASCII 校验
                int avail = size - noff[0];
                if (!validAsciiImportName(data, noff[0], avail)) {
                    setErr(err, "import dll name not ascii");
                    return false;
                }
                idll.name = Bin.cstr(data, noff[0], avail);
                idll.intRva = dOriginalFirstThunk;
                idll.iatRva = dFirstThunk;
            }

            int thunkRva = (dOriginalFirstThunk != 0) ? dOriginalFirstThunk : dFirstThunk;
            final int thunkSize = pointerSize();
            int[] thunkOffSlot = new int[1];
            if (!rvaToOffset(thunkRva, thunkOffSlot)) {
                setErr(err, "import thunk rva invalid");
                return false;
            }
            int thunkOff = thunkOffSlot[0];

            for (;;) {
                long val = 0;
                if (!readBytes(thunkOff, thunkSize)) break;
                if (thunkSize == 4) {
                    val = Bin.u32(data, thunkOff); // uint32_t v; val = v;（零扩展）
                } else {
                    val = Bin.i64(data, thunkOff);
                }
                if (val == 0) break;

                final long ordFlag = (pointerSize() == 8) ? (1L << 63) : (1L << 31);
                ImportEntry e = new ImportEntry();
                if ((val & ordFlag) != 0) {
                    e.ordinal = (int) (val & 0xFFFF);
                } else {
                    int[] noff = new int[1];
                    if (!rvaToOffset((int) val, noff)) {
                        setErr(err, "import by-name rva invalid");
                        return false;
                    }
                    // const ImageImportByName* in = nullptr;
                    if (!readBytes(noff[0], SIZEOF_IMPORT_BY_NAME)) {
                        setErr(err, "import by-name out of bounds");
                        return false;
                    }
                    e.hint = Bin.u16(data, noff[0] + IBN_HINT);
                    int nameOff = noff[0] + IBN_NAME;
                    int avail = size - nameOff;
                    if (!validAsciiImportName(data, nameOff, avail)) {
                        setErr(err, "import function name not ascii");
                        return false;
                    }
                    e.name = Bin.cstr(data, nameOff, avail);
                }
                idll.entries.add(e);
                thunkOff += thunkSize;
            }

            if (!idll.entries.isEmpty()) out.add(idll);
        }
        return true;
    }

    /**
     * dir(5) 原始字节。对应 C++ {@code bool reloc_raw(std::vector<uint8_t>* out)}：
     * out 用 {@link ByteArrayOutputStream}（先 reset 再写入）；无重定位目录时返回 true 且 out 为空。
     */
    public boolean relocRaw(ByteArrayOutputStream out) {
        out.reset();
        if (!hasDirectory(DIR_BASERELOC)) return true;
        int[] off = new int[1];
        if (!rvaToOffset(directoryRva(DIR_BASERELOC), off)) return false;
        int sz = directorySize(DIR_BASERELOC);
        if (!inBounds(off[0], sz)) return false;
        out.write(data, off[0], sz);
        return true;
    }

    public boolean tlsPresent() {
        return hasDirectory(DIR_TLS);
    }

    public boolean loadConfigPresent() {
        return hasDirectory(DIR_LOADCONFIG);
    }

    /**
     * 该节覆盖的虚拟区间 [rva, rva+vsize)。
     *
     * <p>注：pe_image.h 声明了本方法但 pe_image.cpp 无定义（全工程无调用点），
     * 此处按 section_by_rva 的区间判定等价实现。</p>
     */
    public boolean sectionContains(int rva) {
        return sectionByRva(rva) != null;
    }

    // ================= 自由函数 =================

    /** 由节特征位推导解壳后应恢复的内存保护属性（PAGE_*）。 */
    public static int sectionPermissions(SectionInfo s) {
        int p = 0;
        boolean exec = (s.characteristics & SCN_MEM_EXECUTE) != 0;
        boolean write = (s.characteristics & SCN_MEM_WRITE) != 0;
        if (exec && write) p = KboxFormat.PAGE_EXECUTE_READWRITE;
        else if (exec) p = KboxFormat.PAGE_EXECUTE_READ;
        else if (write) p = KboxFormat.PAGE_READWRITE;
        else p = KboxFormat.PAGE_READONLY;
        return p;
    }
}
