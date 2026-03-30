# RC4 Keystream Bias Attack and Mitigation using Drop-N and Enhanced KSA

📌 **Project Overview**

This project demonstrates a real-world cryptographic vulnerability in the RC4 stream cipher **statistical bias in early keystream bytes** and shows how attackers can exploit it to recover secret information.

We implement:
* RC4 from scratch (KSA + PRGA)
* A bias-based attack model (Mantin-Shamir)
* Multiple prevention mechanisms
* A highly interactive `Tkinter` GUI tool for visualization and analysis


##  Attack Model

The attack exploits the fact that **RC4 keystream bytes are not uniformly random in the first few outputs.**
* **Byte 0** → strongly biased toward `0x00`
* **Byte 1** → biased toward specific predictable values

###  Attack Idea:
1. Encrypt the same plaintext byte multiple times using different random keys.
2. Observe ciphertext frequencies across thousands of packets.
3. The most frequent ciphertext reveals the likely true keystream byte.
4. Recover the plaintext using the property: `P = C ⊕ K`

 **Target Goal:** Recover the first byte of the secret message purely using statistical bias inference.

 **Requirement:** 
* 20–25 automated test cases per simulation
* **≥ 90% success rate** before prevention 

---

##  Prevention Mechanisms Implemented

### 1. Drop-N 1024 (Main Fix)
* Discards the first **1024 keystream bytes**.
* Effectively flushes out the entire biased region.

### 2. RC4 + IV (WEP-style)
* Adds a random Initialization Vector to the key input.
* Modestly reduces predictability, but does not fully eliminate the bias.

### 3. Double KSA
* Runs the Key Scheduling Algorithm (KSA) twice, utilizing a bitwise-inverted mod key.
* Improves permutation mixing significantly.

---

##  Mathematical Justification

❗ **Why the Attack Works**

In the RC4 Key Scheduling Algorithm (KSA):
```text
j = (j + S[i] + K[i % n]) % 256
```
Early indices suffer from **insufficient state mixing**. There is a strong, proven mathematical correlation between the Key, the State array `S`, and the final output keystream in the first few PRGA cycles.

👉 Therefore, the probability of guessing the keystream byte is NOT perfectly uniform:
```text
P(KS[i] = x) ≠ 1 / 256
```
Because the bias exists, an attacker can reliably exploit frequency tracking to intercept the message!

 **Why Drop-N Works**

After approximately 1000 keystream generations, the PRGA swaps fully randomize the state `S`. The distribution approaches mathematical uniformity:
```text
lim (i→∞) P(KS[i] = x) = 1 / 256
```
Thus, the vulnerability disappears and the attack success mathematically approaches `~0%`.

---

##  Implementation Details

✔ **From-Scratch Cryptography**
* No external crypto libraries used.
* Built utilizing strictly Python basics (loops, lists, XOR mapping).

✔ **File Structure**
* `rc4_logic.py` → Core RC4 calculations + attack logic simulation engine.
* `main.py` → Tkinter GUI interface + Matplotlib rendering blocks.

 **Test Case Execution**
* **Total tests:** 25 independent automated simulations per click.
* Custom parameters dynamically scale to ensure organic statistical decay.

 **Success Rate Formula:**
```
Success Rate = (Correct Predictions / 25) * 100
```

---

##  Analytical Graphs

**Mandatory Suite** 
1. Before vs After Attack Success Rate
2. Time vs Key / Parameter Size
3. Confidentiality / Integrity / Authentication Matrix
4. Encryption Latency Overhead (ms)

**Extended Research Suite** 
1. Prevention Effectiveness (Vulnerable vs Protected %)
2. Security Improvement % Overlay
3. Resource Usage (Execution Time vs State Array Bytes)
4. Multi-Axis Radar Rating (Security vs Latency vs Memory)

---

##  Requirements

**Software:**
* Python 3.10+

**Libraries:**
```bash
pip install matplotlib numpy
```
*(Note: `tkinter` usually comes pre-installed with standard Python distributions).*

---

##  Step-by-Step Execution Guide

🔹 **Step 1: Clone Repository**
```bash
git clone <your-repo-link>
cd <repo-folder>
```

🔹 **Step 2: Install Dependencies**
```bash
pip install matplotlib numpy
```

🔹 **Step 3: Run the Application**
```bash
python main.py
```

🔹 **Step 4: Use the Application (Base Simulation)**
1. Click ** Generate Keystream** to establish baselines.
2. Click ** Base RC4 Attack**.
3. Enter a secret message.
4. Observe the high success rate (`>90%`) and **Red** vulnerability logs.

🔹 **Step 5: Apply Prevention Mechanisms**
Run the same attack sequence using the mitigation strategies:
* `Prevention (RC4 + IV)`
* `Prevention (Double KSA)`
* `Prevention (Drop-N 1024)` → (Watch the success rate plummet to 0%)

🔹 **Step 6: View Graph Analysis**
1. Click ** Show Graphs**.
2. Analyze the two comparative tabs demonstrating attack efficiency vs execution overhead trade-offs!

