"""
Script to generate the complete SecureMail sample email test suite and mock malicious attachments.
"""

import os
import io
import base64
import qrcode
from PIL import Image

SAMPLE_DIR = os.path.dirname(os.path.abspath(__file__))
ATT_DIR = os.path.join(SAMPLE_DIR, "attachments")

os.makedirs(ATT_DIR, exist_ok=True)

# ── 1. Create Standalone Attachments ─────────────────────────────

# Standard safe EICAR Anti-Virus Test File string (68 bytes)
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
eicar_bytes = EICAR_STRING.encode("ascii")

# EICAR .com file
with open(os.path.join(ATT_DIR, "eicar_antivirus_test_file.com"), "wb") as f:
    f.write(eicar_bytes)

# EICAR .exe file
with open(os.path.join(ATT_DIR, "invoice_remittance.exe"), "wb") as f:
    f.write(eicar_bytes)

# Mock macro document (.docm)
with open(os.path.join(ATT_DIR, "purchase_order_macro.docm"), "wb") as f:
    f.write(b"MOCK_OFFICE_OPENXML_MACRO_PAYLOAD_VBA_TESTING_PURPOSES_ONLY\r\n" + eicar_bytes)

# Standalone Quishing QR Code Image
qr_url = "http://micros0ft-mfa.ru/portal/login?user=security"
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_M,
    box_size=10,
    border=4
)
qr.add_data(qr_url)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
buf = io.BytesIO()
img.save(buf, format="PNG")
qr_png_bytes = buf.getvalue()
qr_b64 = base64.b64encode(qr_png_bytes).decode("ascii")

with open(os.path.join(ATT_DIR, "quishing_mfa_qr.png"), "wb") as f:
    f.write(qr_png_bytes)

print(f"Generated standalone attachments in {ATT_DIR}")

# ── 2. Create Sample .EML Files ──────────────────────────────────

# Sample 01: Credential Phishing with Homograph Lookalike & SPF/DKIM Fail
sample_01 = """From: "PayPal Security Operations" <service@paypa1-security.com>
To: account-holder@example.com
Subject: URGENT: Your PayPal Account Has Been Suspended - Action Required Immediately
Date: Sun, 04 Oct 2026 10:15:30 +0000
Message-ID: <sec-alert-89214710@paypa1-security.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of service@paypa1-security.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=service@paypa1-security.com;
    dkim=fail header.i=@paypa1-security.com;
    dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypa1-security.com
Received: from mail.paypa1-security.com (185.220.101.5) by mx.google.com with ESMTPS id phish123; Sun, 04 Oct 2026 10:15:30 +0000
X-Originating-IP: 185.220.101.5

<!DOCTYPE html>
<html>
<head>
  <title>Security Alert</title>
</head>
<body style="font-family: Arial, sans-serif; color: #333;">
  <h2 style="color: #c00;">Urgent Notice: Account Suspended Within 24 Hours</h2>
  <p>Dear Customer,</p>
  <p>We detected unauthorized access to your PayPal account from a new, unrecognized device.</p>
  <p>To prevent loss of transaction privileges and protect your bank account, your account has been temporarily restricted.</p>
  <p><strong>Immediate Action Required:</strong> You must verify your account identity within 24 hours to restore full access. Failure to validate will result in permanent suspension.</p>
  <p>
    <a href="http://login.paypa1-security.com/restore-access?token=98234821" 
       style="background: #0070ba; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">
      Verify Your Identity Now
    </a>
  </p>
  <p>Thank you,<br>PayPal Security Operations</p>
</body>
</html>
"""

# Sample 02: Malicious Attachment (EICAR executable)
eicar_b64 = base64.b64encode(eicar_bytes).decode("ascii")
boundary_02 = "----=_Part_88491_0921820491.1728038100"

sample_02 = f"""From: "Accounting Department" <billing@overdue-invoices-notice.com>
To: target-user@example.com
Subject: OVERDUE INVOICE #99214 - IMMEDIATE PAYMENT REQUIRED
Date: Sun, 04 Oct 2026 11:00:00 +0000
Message-ID: <invoice-overdue-99214@overdue-invoices-notice.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary_02}"
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=billing@overdue-invoices-notice.com;
    dkim=fail;
    dmarc=fail

--{boundary_02}
Content-Type: text/plain; charset="UTF-8"

Dear Client,

Your payment for Invoice #99214 is 60 days overdue.
Immediate remittance is required to prevent legal escalation and collection fees.
Please review the complete accounting itemization and remittance form in the attached file.

Accounting Operations Team
Billing & Remittance Services

--{boundary_02}
Content-Type: application/x-msdownload; name="invoice_remittance.exe"
Content-Disposition: attachment; filename="invoice_remittance.exe"
Content-Transfer-Encoding: base64

{eicar_b64}
--{boundary_02}--
"""

# Sample 03: Optical Quishing (QR Code Phishing)
boundary_03 = "----=_Part_77192_1829102918.1728038200"

sample_03 = f"""From: "IT Service Desk" <support@micros0ft-mfa.ru>
To: target-employee@enterprise.com
Subject: URGENT: Microsoft 365 MFA Re-Authentication Required Within 24 Hours
Date: Sun, 04 Oct 2026 11:30:00 +0000
Message-ID: <mfa-reset-77291@micros0ft-mfa.ru>
MIME-Version: 1.0
Content-Type: multipart/related; boundary="{boundary_03}"
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=support@micros0ft-mfa.ru;
    dkim=fail;
    dmarc=fail

--{boundary_03}
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; text-align: center; color: #222;">
  <div style="max-width: 500px; margin: 0 auto; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
    <h2 style="color: #0078d4;">Microsoft 365 Security Alert</h2>
    <p>Your Multi-Factor Authentication (MFA) certificate will expire within <strong>24 hours</strong>.</p>
    <p>To avoid being locked out of your email and corporate applications, use your mobile camera to scan the secure QR verification code below:</p>
    <div style="margin: 20px 0;">
      <img src="data:image/png;base64,{qr_b64}" alt="MFA Verification QR Code" style="width: 200px; height: 200px; border: 1px solid #ccc; padding: 5px;"/>
    </div>
    <p style="font-size: 12px; color: #666;">Do not share this QR code. It is encrypted specifically for your enterprise account credentials.</p>
    <p style="font-size: 11px; color: #999;">Microsoft Corporation | IT Security Operations Center</p>
  </div>
</body>
</html>

--{boundary_03}
Content-Type: image/png; name="quishing_mfa_qr.png"
Content-ID: <quishing_mfa_qr>
Content-Disposition: inline; filename="quishing_mfa_qr.png"
Content-Transfer-Encoding: base64

{qr_b64}
--{boundary_03}--
"""

# Sample 04: Extortion / Sextortion / Bitcoin Ransom
sample_04 = """From: "System Alert" <hacker-zero@onion-network.org>
To: target-user@example.com
Subject: I know what you did last month - Final Warning: Bitcoin Payment Required
Date: Sun, 04 Oct 2026 08:30:00 +0000
Message-ID: <extort-88310@onion-network.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

I will make this brief. I have access to your device.
Several weeks ago I installed a remote spyware trojan on your computer while you visited an adult website.
I recorded you through your webcam while you were watching explicit content, and I captured a split-screen video of you and what you were viewing.
I also harvested your entire contact list, social media accounts, and family members.

If you want me to delete everything and not send this video to all your contacts, friends, and coworkers:
You must send payment of $1,200 in bitcoin within 48 hours.

Send bitcoin to my btc crypto wallet address below:
1BoatSLRHtKNngkdXEeobR76b53LETtpyT

Do not reply to this email, do not contact authorities or I will immediately send these recordings to everyone.
Once payment is confirmed, I will destroy the footage and disappear. Your time is running.
"""

# Sample 05: CEO Impersonation / BEC (Business Email Compromise)
sample_05 = """From: "Satya Nadella" <exec-notice@cloud-sys-temp.org>
To: finance-director@target-corp.com
Reply-To: executive-wire-escrow@offshore-holdings.cc
Subject: URGENT: Action Required - Immediate Wire Transfer Authorization Needed
Date: Sun, 04 Oct 2026 12:00:00 +0000
Message-ID: <bec-exec-99214@cloud-sys-temp.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=exec-notice@cloud-sys-temp.org;
    dkim=fail;
    dmarc=fail

Are you at your desk right now?

I am currently tied up in an offsite executive board meeting regarding a confidential acquisition. We need an urgent wire transfer of $74,500 authorized immediately before bank cutoff today to finalize the escrow deposit.

Please confirm you can process this wire transfer immediately, and I will forward the beneficiary routing details. Due to strict SEC non-disclosure agreements, do not discuss this transaction with anyone else on the finance team until the official press release is issued tomorrow morning.

Sent from my iPhone
Satya Nadella
Chief Executive Officer
"""

# Sample 06: Macro Malware (.docm attachment)
docm_b64 = base64.b64encode(b"MOCK_MACRO_PAYLOAD_VBA_TESTING_PURPOSES_ONLY\r\n" + eicar_bytes).decode("ascii")
boundary_06 = "----=_Part_99182_1204910291.1728038400"

sample_06 = f"""From: "Supplier Vendor Desk" <orders@procurement-logistics-portal.com>
To: accounts-payable@target-company.com
Subject: Purchase Order PO# 883011 - Delivery Schedule & Billing Authorization
Date: Sun, 04 Oct 2026 12:30:00 +0000
Message-ID: <po-order-883011@procurement-logistics-portal.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary_06}"
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=orders@procurement-logistics-portal.com;
    dkim=fail;
    dmarc=fail

--{boundary_06}
Content-Type: text/plain; charset="UTF-8"

Please find attached the official purchase order PO# 883011 for Q3 billing and dispatch.
Review the vendor contract details in the attached document.
Please ensure you click 'Enable Content' and 'Enable Macros' in Microsoft Word to allow the automated digital signature macros to run.

Procurement Operations
Global Supply Chain Services

--{boundary_06}
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="PO_883011_Billing_Statement.docm"
Content-Disposition: attachment; filename="PO_883011_Billing_Statement.docm"
Content-Transfer-Encoding: base64

{docm_b64}
--{boundary_06}--
"""

# Sample 07: Clean Legitimate Email Baseline (Passes all checks)
sample_07 = """From: "GitHub Notifications" <notifications@github.com>
To: developer@example.com
Subject: [GitHub] Security advisory alerts and release digest for your repositories
Date: Sun, 04 Oct 2026 06:00:00 +0000
Message-ID: <digest-99128@github.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of notifications@github.com designates 192.30.252.204 as permitted sender) smtp.mailfrom=notifications@github.com;
    dkim=pass header.i=@github.com header.s=s2024 header.b=CleanDkimSig;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=s2024; h=from:to:subject:date:message-id:mime-version:content-type; bh=abcd1234efgh5678=; b=CleanDkimSigPass123==
Received: from smtp.github.com (192.30.252.204) by mx.google.com with ESMTPS id clean992; Sun, 04 Oct 2026 06:00:00 +0000

<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; color: #24292f; line-height: 1.5;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2>GitHub Weekly Summary</h2>
    <p>Hello Developer,</p>
    <p>Here is your weekly summary of activity across your watched open-source repositories:</p>
    <ul>
      <li><a href="https://github.com/torvalds/linux">torvalds/linux</a> - Kernel update 6.12 release candidates available</li>
      <li><a href="https://github.com/python/cpython">python/cpython</a> - Python maintenance and security updates published</li>
    </ul>
    <hr style="border: none; border-top: 1px solid #d0d7de; margin: 24px 0;"/>
    <p style="font-size: 12px; color: #57606a;">
      You can manage your notification preferences anytime at 
      <a href="https://github.com/settings/notifications">GitHub Notification Settings</a>.
    </p>
    <p style="font-size: 12px; color: #57606a;">© 2026 GitHub, Inc. 88 Colin P Kelly Jr St, San Francisco, CA 94107</p>
  </div>
</body>
</html>
"""

samples = {
    "01_credential_phishing.eml": sample_01,
    "02_eicar_malware_attachment.eml": sample_02,
    "03_quishing_qr_code.eml": sample_03,
    "04_extortion_blackmail_btc.eml": sample_04,
    "05_ceo_impersonation_bec.eml": sample_05,
    "06_macro_malware_docm.eml": sample_06,
    "07_clean_legitimate_newsletter.eml": sample_07,
}

for filename, content in samples.items():
    filepath = os.path.join(SAMPLE_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Created {filepath} ({len(content)} bytes)")

print("\nAll sample emails and attachments created successfully!")
