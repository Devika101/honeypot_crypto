# 🍯 HONEYPOT SECURITY DEMO

## What is This?

This is a **simple demonstration** of how honeypots work to catch hackers. A honeypot is a **FAKE website** that looks real but is actually a trap!

## 🎯 The Problem We Solve

**Hackers** attack websites every day trying to:
- Steal passwords
- Break into admin panels  
- Hack bank accounts
- Steal cryptocurrency

**Our Solution:** Create FAKE websites that look real. When hackers attack them, we catch them and learn their techniques!

---

## 🚀 How to Run the Demo

### Super Simple Method:

1. Open Terminal/Command Prompt
2. Navigate to this folder:
   ```bash
   cd demo
   ```

3. Run the start script:
   ```bash
   chmod +x start_demo.sh
   ./start_demo.sh
   ```

### Alternative Method:

If the script doesn't work, just run:
```bash
python3 honeypot_server.py
```

---

## 📱 What to Do Next

Once the server is running:

1. **Open your web browser** (Chrome, Firefox, Safari, etc.)

2. **Go to:** http://localhost:8080

3. **You'll see the main presentation page** explaining everything

4. **Try the demo honeypots:**
   - Fake Bank: http://localhost:8080/bank
   - Fake Admin Panel: http://localhost:8080/admin
   - Fake Crypto Wallet: http://localhost:8080/wallet

5. **On each fake site:** 
   - Type ANY username and password
   - Click "Login" or "Access"
   - Then check your Terminal!

6. **Watch the Terminal** where your server is running - you'll see:
   ```
   🚨 HACKER CAUGHT! Attack #1
   ============================================
   Type: BANK_LOGIN
   Time: 2026-02-13 14:25:30
   Username: admin
   IP Address: 127.0.0.1
   ============================================
   ```

---

## 📊 What Files Are Included?

| File | Description |
|------|-------------|
| `honeypot_server.py` | Main server that catches hackers |
| `demo_presentation.html` | Main presentation page |
| `fake_bank.html` | Fake bank login honeypot |
| `fake_admin.html` | Fake admin panel honeypot |
| `fake_crypto_wallet.html` | Fake crypto wallet honeypot |
| `start_demo.sh` | Easy start script |
| `attack_log.json` | Stores all caught attacks (created when hackers try to login) |

---

## 🎓 For Your Teacher Presentation

### What to Show:

1. **Start with the problem:**
   - "Hackers attack websites constantly"
   - "We need a way to catch them before they do damage"

2. **Explain the solution:**
   - "We create fake websites (honeypots)"
   - "Hackers think they're real and attack them"
   - "We catch them and log everything"

3. **Live Demo:**
   - Open http://localhost:8080 on the projector
   - Click through the presentation
   - Go to one of the fake sites
   - Try to "hack" it by logging in
   - Show the Terminal catching the "attack"

4. **Explain the benefits:**
   - Learn hacker techniques
   - Protect real websites
   - Block bad actors early
   - Gather intelligence

### Key Points to Mention:

✅ **Proactive Defense** - We don't wait for attacks, we trap hackers  
✅ **Real-World Use** - Banks, governments, and companies use this  
✅ **Safe Learning** - We learn about attacks without risking real data  
✅ **Automated** - Works 24/7 without human intervention  

---

## 🛡️ How It Protects Real Websites

1. **Hacker tries our fake bank** → We log their IP address
2. **We see what passwords they try** → Learn common attack patterns
3. **We detect their tools** → Understand their techniques
4. **We block their IP** → Prevent them from reaching real websites
5. **We share data** → Help other websites defend themselves

---

## 💡 Technical Details

### What Gets Logged:
- Attacker's IP address
- Time of attack
- Username tried
- Password tried (we see it but it's fake data!)
- Browser/device info

### Technologies Used:
- **Python** - Backend server
- **HTML/CSS/JavaScript** - Fake websites
- **HTTP Server** - Serves the pages
- **JSON** - Stores attack data

---

## ⚠️ Important Notes

🔴 **These are FAKE websites for educational purposes only**  
🔴 **Never use honeypots for illegal activities**  
🔴 **All "attacks" in this demo are just demonstrations**  
🔴 **No real data is at risk**  

---

## 🎬 Demo Script for Presentation

**Say this when presenting:**

> "Today we're solving a major cybersecurity problem. Hackers attack websites every minute of every day. Our solution is called a 'honeypot' - it's a fake website that looks real but is actually a trap.
>
> Let me show you how it works. [Open browser to localhost:8080]
>
> Here we have three honeypots: a fake bank, a fake admin panel, and a fake cryptocurrency wallet. To a hacker, these look like real targets.
>
> Watch what happens when I try to 'hack' the fake bank. [Enter credentials and click login]
>
> Now look at our server terminal. [Show terminal] It caught everything - my IP address, what I entered, and when I did it.
>
> In the real world, we use this data to protect actual websites. We can block these hackers, learn their techniques, and make real systems more secure.
>
> This is proactive defense - we're catching hackers before they can do real damage. Companies like banks, governments, and tech firms all use honeypots to protect their systems."

---

## ❓ Troubleshooting

**Problem:** Port 8080 already in use  
**Solution:** Stop other programs using port 8080, or edit `honeypot_server.py` and change `8080` to `8081`

**Problem:** Python not found  
**Solution:** Install Python 3 from python.org

**Problem:** Can't access http://localhost:8080  
**Solution:** Make sure the server is running (check terminal for "Server Status: RUNNING")

---

## 📧 Questions?

If you have questions about the demo, check:
- The presentation page at http://localhost:8080
- The source code in each .html and .py file
- The attack_log.json file to see caught attacks

---

## ✅ Quick Checklist for Teacher Demo

- [ ] Server is running (see "RUNNING" in terminal)
- [ ] Browser is open to http://localhost:8080
- [ ] You understand how honeypots work
- [ ] You've tested one fake site
- [ ] You can show the attack log in terminal
- [ ] You can explain the benefits

**You're ready to present!** 🎉

---

Made with ❤️ for Cybersecurity Education  
Remember: Use this knowledge for good, never for harm!
