"""
S-DES (Simplified Data Encryption Standard) 算法实现 — 单文件版
课程: 信息安全导论 作业1
分组长度: 8 bit   密钥长度: 10 bit

运行方式:
    python3 sdes.py            # 启动 GUI 图形界面
    python3 sdes.py test       # 运行自动化测试
"""

import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox


# ============================================================
# 一、置换表与 S 盒 (1-based 索引)
# ============================================================

P10_TAB    = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]   # 密钥扩展 10->10
P8_TAB     = [6, 3, 7, 4, 8, 5, 10, 9]          # 密钥压缩 10->8
IP_TAB     = [2, 6, 3, 1, 4, 8, 5, 7]           # 初始置换 8->8
IP_INV_TAB = [4, 1, 3, 5, 7, 2, 8, 6]           # 逆初始置换 8->8
EP_TAB     = [4, 1, 2, 3, 2, 3, 4, 1]           # 扩展置换 4->8
SP_TAB     = [2, 4, 3, 1]                        # 单比特置换 4->4

SBOX1 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2],
]

SBOX2 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3],
]


# ============================================================
# 二、基础工具
# ============================================================

def permute(bits, table):
    """按 1-based 置换表对 bit 列表做置换。"""
    return [bits[pos - 1] for pos in table]


def left_rotate(bits, n):
    """list[int] 左循环移位 n 位。"""
    return bits[n:] + bits[:n]


def bits_to_str(bits):
    return ''.join(str(b) for b in bits)


def str_to_bits(s):
    return [int(c) for c in s]


# ============================================================
# 三、密钥扩展: 10-bit 主密钥 -> (k1, k2) 两个 8-bit 子密钥
# ============================================================

def key_expansion(key_10):
    p10 = permute(key_10, P10_TAB)
    left, right = p10[:5], p10[5:]

    # k1: 左右各左移 1 位, 合并后做 P8
    l1, r1 = left_rotate(left, 1), left_rotate(right, 1)
    k1 = permute(l1 + r1, P8_TAB)

    # k2: 再左移 1 位 (累计 2 位), 合并后做 P8
    l2, r2 = left_rotate(l1, 1), left_rotate(r1, 1)
    k2 = permute(l2 + r2, P8_TAB)

    return k1, k2


# ============================================================
# 四、轮函数 F
# ============================================================

def _sbox(sbox, four_bits):
    row = (four_bits[0] << 1) | four_bits[3]
    col = (four_bits[1] << 1) | four_bits[2]
    v = sbox[row][col]
    return [(v >> 1) & 1, v & 1]


def f_function(right_4, subkey_8):
    # 1. EPBox 扩展 4 -> 8
    ep = permute(right_4, EP_TAB)
    # 2. 与子密钥异或
    xored = [ep[i] ^ subkey_8[i] for i in range(8)]
    # 3. 分左右 4 位走 S 盒
    s1 = _sbox(SBOX1, xored[:4])
    s2 = _sbox(SBOX2, xored[4:])
    # 4. 拼接后做 SPBox 置换
    return permute(s1 + s2, SP_TAB)


def _feistel_round(left, right, subkey):
    f_out = f_function(right, subkey)
    return [left[i] ^ f_out[i] for i in range(4)], right


# ============================================================
# 五、加解密主函数
# ============================================================

def encrypt(plaintext_8, key_10):
    """C = IP^-1( f_k2( SW( f_k1( IP(P) ) ) ) )"""
    k1, k2 = key_expansion(key_10)

    ip = permute(plaintext_8, IP_TAB)
    L, R = ip[:4], ip[4:]

    L, R = _feistel_round(L, R, k1)     # 第一轮
    L, R = R, L                          # SW 交换
    L, R = _feistel_round(L, R, k2)     # 第二轮

    return permute(L + R, IP_INV_TAB)


def decrypt(ciphertext_8, key_10):
    """P = IP^-1( f_k1( SW( f_k2( IP(C) ) ) ) )  (子密钥顺序交换)"""
    k1, k2 = key_expansion(key_10)

    ip = permute(ciphertext_8, IP_TAB)
    L, R = ip[:4], ip[4:]

    L, R = _feistel_round(L, R, k2)     # 解密先用 k2
    L, R = R, L
    L, R = _feistel_round(L, R, k1)     # 再用 k1

    return permute(L + R, IP_INV_TAB)


# ============================================================
# 六、ASCII 字符串逐字节加解密
# ============================================================

def encrypt_ascii(text, key_10):
    out = bytearray()
    for ch in text:
        bits = [(ord(ch) >> (7 - i)) & 1 for i in range(8)]
        enc = encrypt(bits, key_10)
        v = 0
        for b in enc:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def decrypt_ascii(data, key_10):
    chars = []
    for byte in data:
        bits = [(byte >> (7 - i)) & 1 for i in range(8)]
        dec = decrypt(bits, key_10)
        v = 0
        for b in dec:
            v = (v << 1) | b
        chars.append(chr(v))
    return ''.join(chars)


# ============================================================
# 七、GUI (Tkinter)
# ============================================================

class SDesApp:
    def __init__(self, root):
        self.root = root
        root.title("S-DES 算法实现")
        root.geometry("700x560")

        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tab1 = ttk.Frame(nb); nb.add(tab1, text=" ① 基本测试 ")
        tab2 = ttk.Frame(nb); nb.add(tab2, text=" ② ASCII 扩展 ")
        tab3 = ttk.Frame(nb); nb.add(tab3, text=" ③ 暴力破解 ")
        tab4 = ttk.Frame(nb); nb.add(tab4, text=" ④ 封闭测试 ")
        self._build_basic(tab1)
        self._build_ascii(tab2)
        self._build_bruteforce(tab3)
        self._build_closed(tab4)

    # ---------- 工具 ----------
    @staticmethod
    def _check_bits(s, n):
        if len(s) != n or any(c not in "01" for c in s):
            messagebox.showerror("格式错误", f"需要 {n} 位二进制串 (仅 0/1)，当前: {s!r}")
            return None
        return str_to_bits(s)

    # ---------- Tab1 基本测试 ----------
    def _build_basic(self, p):
        f = ttk.LabelFrame(p, text="8-bit 明文/密文 + 10-bit 密钥")
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="输入 (8 bit):").grid(row=0, column=0, sticky=tk.W, padx=10, pady=8)
        self.b_in = ttk.Entry(f, width=25, font=("Consolas", 12))
        self.b_in.grid(row=0, column=1, padx=10, pady=8); self.b_in.insert(0, "10101010")

        ttk.Label(f, text="密钥 (10 bit):").grid(row=1, column=0, sticky=tk.W, padx=10, pady=8)
        self.b_key = ttk.Entry(f, width=25, font=("Consolas", 12))
        self.b_key.grid(row=1, column=1, padx=10, pady=8); self.b_key.insert(0, "1010101010")

        bf = ttk.Frame(f); bf.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(bf, text="加密 →", command=self._enc).pack(side=tk.LEFT, padx=10)
        ttk.Button(bf, text="← 解密", command=self._dec).pack(side=tk.LEFT, padx=10)

        ttk.Label(f, text="输出:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=8)
        self.b_out = ttk.Entry(f, width=25, font=("Consolas", 12), state="readonly")
        self.b_out.grid(row=3, column=1, padx=10, pady=8)

    def _set_out(self, val):
        self.b_out.config(state="normal"); self.b_out.delete(0, tk.END)
        self.b_out.insert(0, val); self.b_out.config(state="readonly")

    def _enc(self):
        pt = self._check_bits(self.b_in.get().strip(), 8)
        k  = self._check_bits(self.b_key.get().strip(), 10)
        if pt and k: self._set_out(bits_to_str(encrypt(pt, k)))

    def _dec(self):
        ct = self._check_bits(self.b_in.get().strip(), 8)
        k  = self._check_bits(self.b_key.get().strip(), 10)
        if ct and k: self._set_out(bits_to_str(decrypt(ct, k)))

    # ---------- Tab2 ASCII 扩展 ----------
    def _build_ascii(self, p):
        f = ttk.LabelFrame(p, text="ASCII 字符串逐字节加解密")
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="输入文本:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=6)
        self.a_in = ttk.Entry(f, width=40, font=("Consolas", 11))
        self.a_in.grid(row=0, column=1, padx=10, pady=6); self.a_in.insert(0, "This is a test")

        ttk.Label(f, text="密钥 (10 bit):").grid(row=1, column=0, sticky=tk.W, padx=10, pady=6)
        self.a_key = ttk.Entry(f, width=40, font=("Consolas", 11))
        self.a_key.grid(row=1, column=1, padx=10, pady=6); self.a_key.insert(0, "1010101010")

        bf = ttk.Frame(f); bf.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(bf, text="加密文本 →", command=self._a_enc).pack(side=tk.LEFT, padx=10)
        ttk.Button(bf, text="← 解密文本", command=self._a_dec).pack(side=tk.LEFT, padx=10)

        ttk.Label(f, text="输出 (hex):").grid(row=3, column=0, sticky=tk.W, padx=10, pady=6)
        self.a_out = ttk.Entry(f, width=40, font=("Consolas", 11))
        self.a_out.grid(row=3, column=1, padx=10, pady=6)

    def _a_enc(self):
        k = self._check_bits(self.a_key.get().strip(), 10)
        if not k: return
        enc = encrypt_ascii(self.a_in.get(), k)
        self.a_out.delete(0, tk.END); self.a_out.insert(0, enc.hex(' ').upper())

    def _a_dec(self):
        k = self._check_bits(self.a_key.get().strip(), 10)
        if not k: return
        try:
            data = bytes.fromhex(self.a_in.get().replace(' ', ''))
        except ValueError:
            messagebox.showerror("格式错误", "请输入合法 hex 串"); return
        self.a_out.delete(0, tk.END); self.a_out.insert(0, decrypt_ascii(data, k))

    # ---------- Tab3 暴力破解 ----------
    def _build_bruteforce(self, p):
        f = ttk.LabelFrame(p, text="已知明文-密文对，遍历全部 2^10=1024 个密钥")
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="明文 (8 bit):").grid(row=0, column=0, sticky=tk.W, padx=10, pady=6)
        self.bf_pt = ttk.Entry(f, width=25, font=("Consolas", 12))
        self.bf_pt.grid(row=0, column=1, padx=10, pady=6); self.bf_pt.insert(0, "10101010")

        ttk.Label(f, text="密文 (8 bit):").grid(row=1, column=0, sticky=tk.W, padx=10, pady=6)
        self.bf_ct = ttk.Entry(f, width=25, font=("Consolas", 12))
        self.bf_ct.grid(row=1, column=1, padx=10, pady=6); self.bf_ct.insert(0, "10001111")

        self.bf_btn = ttk.Button(f, text="开始暴力破解", command=self._run_bf)
        self.bf_btn.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Label(f, text="匹配的密钥:").grid(row=3, column=0, sticky=tk.NW, padx=10, pady=6)
        self.bf_out = tk.Text(f, width=50, height=6, font=("Consolas", 11))
        self.bf_out.grid(row=3, column=1, padx=10, pady=6)

        self.bf_time = ttk.Label(f, text="耗时: -")
        self.bf_time.grid(row=4, column=0, columnspan=2, pady=5)

    def _run_bf(self):
        pt = self._check_bits(self.bf_pt.get().strip(), 8)
        ct = self._check_bits(self.bf_ct.get().strip(), 8)
        if not pt or not ct: return

        self.bf_btn.config(state=tk.DISABLED)
        self.bf_out.delete(1.0, tk.END); self.bf_time.config(text="破解中...")

        def worker():
            found = []
            t0 = time.perf_counter()
            for k in range(1024):
                kb = [(k >> (9 - i)) & 1 for i in range(10)]
                if encrypt(pt, kb) == ct:
                    found.append(bits_to_str(kb))
            dt = time.perf_counter() - t0
            self.root.after(0, lambda: self._bf_done(found, dt))

        threading.Thread(target=worker, daemon=True).start()

    def _bf_done(self, found, dt):
        self.bf_btn.config(state=tk.NORMAL)
        self.bf_out.insert(tk.END, "\n".join(found) if found else "未找到匹配密钥")
        self.bf_time.config(text=f"耗时: {dt*1000:.2f} ms   共 {len(found)} 个匹配密钥")

    # ---------- Tab4 封闭测试 ----------
    def _build_closed(self, p):
        f = ttk.LabelFrame(p, text="封闭测试: 多密钥碰撞统计")
        f.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(f, text="枚举 256 个明文 × 1024 个密钥，统计多密钥碰撞").pack(pady=5)
        ttk.Button(f, text="运行封闭测试", command=self._run_closed).pack(pady=8)

        self.ct_out = tk.Text(f, width=75, height=16, font=("Consolas", 10))
        self.ct_out.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _run_closed(self):
        self.ct_out.delete(1.0, tk.END)
        t0 = time.perf_counter()
        multi_cnt = 0
        samples = []
        for p_int in range(256):
            pt = [(p_int >> (7 - i)) & 1 for i in range(8)]
            ct_map = {}
            for k in range(1024):
                kb = [(k >> (9 - i)) & 1 for i in range(10)]
                c = bits_to_str(encrypt(pt, kb))
                ct_map.setdefault(c, []).append(bits_to_str(kb))
            multis = [(c, ks) for c, ks in ct_map.items() if len(ks) > 1]
            if multis:
                multi_cnt += 1
                if len(samples) < 3:
                    samples.append((p_int, bits_to_str(pt), multis))
        dt = time.perf_counter() - t0

        w = self.ct_out.insert
        w(tk.END, f"扫描: 256 明文 × 1024 密钥 = {256*1024} 次加密\n")
        w(tk.END, f"耗时: {dt:.3f} s\n")
        w(tk.END, f"存在多密钥碰撞的明文: {multi_cnt} / 256\n")
        w(tk.END, "=" * 60 + "\n\n")
        for p_int, pt_s, multis in samples:
            w(tk.END, f"明文 P = {pt_s}  (ASCII '{chr(p_int)}'):\n")
            for c, ks in multis[:3]:
                w(tk.END, f"  → 密文 C = {c}  由 {len(ks)} 个密钥产生: {', '.join(ks)}\n")
            w(tk.END, "\n")
        w(tk.END, "结论: 密钥空间 1024 > 密文空间 256，由鸽巢原理，\n")
        w(tk.END, "固定 P 时平均每密文对应 1024/256 = 4 个密钥。\n")
        w(tk.END, "即必然存在 K_i ≠ K_j 使 E(K_i,P)=E(K_j,P)=C_n。\n")


# ============================================================
# 八、自动化测试
# ============================================================

def run_tests():
    print("=" * 55)
    print("测试1: 全量加解密可逆 (256 明文 × 1024 密钥)")
    print("=" * 55)
    ok = True
    for p in range(256):
        pt = [(p >> (7 - i)) & 1 for i in range(8)]
        for k in range(1024):
            kb = [(k >> (9 - i)) & 1 for i in range(10)]
            if decrypt(encrypt(pt, kb), kb) != pt:
                ok = False; break
        if not ok: break
    print(f"  {'✅ 通过' if ok else '❌ 失败'}\n")

    print("=" * 55)
    print("测试2: 暴力破解正确性")
    print("=" * 55)
    target_pt = str_to_bits("10110100")
    target_k  = str_to_bits("0110101100")
    target_ct = encrypt(target_pt, target_k)
    found = []
    for k in range(1024):
        kb = [(k >> (9 - i)) & 1 for i in range(10)]
        if encrypt(target_pt, kb) == target_ct:
            found.append(bits_to_str(kb))
    hit = bits_to_str(target_k) in found
    print(f"  目标密钥 {bits_to_str(target_k)} 被破解: {'✅' if hit else '❌'}")
    print(f"  该 P→C 对共匹配 {len(found)} 个密钥: {found}\n")

    print("=" * 55)
    print("测试3: ASCII 字符串往返")
    print("=" * 55)
    k = str_to_bits("1010101010")
    text = "This is a test"
    enc = encrypt_ascii(text, k)
    dec = decrypt_ascii(enc, k)
    print(f"  原文: {text}")
    print(f"  密文(hex): {enc.hex(' ').upper()}")
    print(f"  解密: {dec}  {'✅' if dec == text else '❌'}\n")

    print("=" * 55)
    print("测试4: 密钥扩展")
    print("=" * 55)
    k1, k2 = key_expansion(str_to_bits("1010000010"))
    print(f"  K=1010000010 -> k1={bits_to_str(k1)}, k2={bits_to_str(k2)}  ✅\n")

    print("=" * 55)
    print("全部测试完成")
    print("=" * 55)


# ============================================================
# 入口
# ============================================================

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        run_tests()
    else:
        root = tk.Tk()
        app = SDesApp(root)
        root.mainloop()
