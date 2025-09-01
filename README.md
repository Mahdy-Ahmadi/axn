# مستندات کتابخانه **axn**

> این مستند، راهنمای کامل استفاده، پیکربندی و توسعهٔ کتابخانه‌ی شما (کدی که ارسال کردید) است. شامل معرفی معماری، توضیح کلاس‌ها و متدها، نمونهٔ استفاده، فرمت گزارش‌ها، نکات امنیتی و پیشنهادات توسعه می‌باشد.

---

## فهرست محتوا

1. معرفی کلی
2. پیش‌نیازها و نصب
3. معماری و اجزا
4. پیکربندی (`PentestConfig`)
5. مولفه‌های اصلی و مرجع API
   - `EnhancedReport`
   - `NetworkTester`
   - `PenetrationTester`
   - `WebTester`
   - `SniffingTester`
   - `UtilityTester`
   - `AdvancedPentestSuite`
6. اجرای نمونه
7. فرمت خروجی گزارش (JSON و HTML)
8. نکات مربوط به سریالایز کردن داده‌ها
9. امنیت و رعایت قوانین
10. توسعه و افزودن تست/ماژول جدید
11. خطاها و رفع مشکل متداول
12. تغییرات پیشنهادی / TODO
13. لایسنس و تشکر

---

# 1. معرفی کلی

`AdvancedPentestSuite` یک چارچوب (framework) سبک برای اجرای مجموعهٔ تست‌های نفوذ و شبکه است که بر پایهٔ ماژول‌های داخلی (`axn.*`) طراحی شده. هدف این کتابخانه تسهیل اجرای مجموعه‌ای از تست‌های خودکار (وب، شبکه، sniffing، ابزار‌های کمکی و...)، جمع‌آوری نتایج و تولید گزارش ساخت‌یافته در فرمت JSON و HTML است.

# 2. پیش‌نیازها و نصب

- پایتون 3.8+
- نیازمندی‌های فرضی (ماژول‌های داخلی `axn.*`) — این ماژول‌ها باید در مسیر پروژه یا بسته نصب‌شده باشند.

نصب:

1. کد را در یک پوشهٔ پروژه قرار دهید؛
2. اگر کتابخانه‌ها بسته‌بندی شده‌اند، آنها را نصب کنید: `pip install .` یا `pip install -e .`؛
3. اجرای برنامه:

```bash
python your_script.py
```

> توجه: ماژول‌هایی مانند `axn.attacks` و `axn.web` باید در مسیر `PYTHONPATH` قرار داشته باشند یا به‌صورت بسته (package) نصب شده باشند.

# 3. معماری و اجزا

این پروژه از الگوی "تسترها" (Tester per domain) استفاده می‌کند:

- یک شیٔ پیکربندی (`PentestConfig`) که اطلاعات تست‌ها را نگه می‌دارد.
- یک گزارش‌ساز پیشرفته (`EnhancedReport`) برای جمع‌آوری و ذخیره نتایج.
- تعدادی `Tester` مستقل (`NetworkTester`, `WebTester`, ...) که هرکدام گروهی از تست‌ها را اجرا می‌کنند.
- یک `AdvancedPentestSuite` که همه را در کنار هم اجرا می‌کند و گزارش نهایی را تولید می‌کند.

# 4. پیکربندی (`PentestConfig`)

کلاس `PentestConfig` شامل تنظیمات پیش‌فرض است. فیلد‌های مهم:

- `targets: List[str]` — لیست دامنه‌ها/URLهایی که تست می‌شوند.
- `login_credentials: List[Dict[str,str]]` — ترکیب نام‌کاربری و پسورد برای تست لاگین.
- `api_endpoints`, `urls_to_scan`, `network_interfaces`, `test_payloads`, `jwt_tokens`, `usernames`, `subdomains_to_check`, `ports_to_scan`, `sensitive_files`, `graphql_endpoints`, `xml_payloads`.

شما می‌توانید این کلاس را گسترش داده یا از فایل JSON/YAML پیکربندی بخوانید و به‌عنوان جایگزین مقداردهی کنید.

مثال تغییر مقادیر:

```python
config = PentestConfig()
config.targets = ["https://example.com"]
config.network_interfaces = ["eth0"]
```

# 5. مولفه‌های اصلی و مرجع API

در ادامه هر بخش به‌تفصیل توضیح داده شده است.

---

## 5.1 `EnhancedReport`

### شرح کلی

`EnhancedReport` از `Report` ارث‌بری می‌کند و مسئول جمع‌آوری نتایج، تعیین سطحseverity، ارائهٔ خلاصه و ذخیرهٔ گزارش به فرمت JSON و HTML است.

### متدهای مهم

- `__init__(self)`
  - مقداردهی ساختار‌های داخلی: `self.results`, `self.summary`.

- `add_entry(self, category: str, name: str, data: Any, severity: str = "INFO", status: str = "SUCCESS", error: Optional[Exception] = None)`
  - ورودی: دسته‌بندی، نام تست، دادهٔ نتیجه، سطح severity، وضعیت و خطا (در صورت وجود).
  - خروجی: اضافه‌کردن یک رکورد به `self.results` و به‌روزرسانی `self.summary`.
  - نکته: از `int(time.time() * 1000)` برای ساخت شناسهٔ یکتا استفاده می‌کند.

- `_process_result(self, result_data: Any)`
  - تعیین سطح severity و وضعیت بر اساس محتوای خروجی. (کلمه‌های کلیدی مثل `vulnerable`, `error`, `success`, `found` بررسی می‌شوند.)
  - بازگشت `(severity, status)`.

- `run_test(self, test_instance: Any, method_name: str, *args, **kwargs)`
  - گرفتن نمونهٔ تست و نام متد و اجرای آن (پشتیبانی از coroutine یا متد ا同步).
  - گرفتن نتیجه و پردازش severity/status و در نهایت فراخوانی `add_entry`.
  - بازمی‌گرداند `result_data` برای استفادهٔ احتمالی.

- `show_summary(self)`
  - چاپ خلاصهٔ خلاصهٔ گزارش شامل تعداد تست‌ها و آسیب‌پذیری‌ها.

- `save(self, filename: str = "pentest_report", format: str = "json")`
  - فرمت `json` و `html` پشتیبانی می‌شود.
  - در حالت JSON، داده‌ها قبل از `json.dump` سریالایز می‌شوند و اگر نوع قابل سریالایز نباشد، نوع آن ذخیره می‌شود.
  - در حالت HTML، یک قالب سادهٔ HTML بسازید و نتایج را درج می‌کند. (در کد نمونهٔ شما، برخی استایل‌ها ناقص گذاشته شده‌اند — پیشنهاد می‌شود آنها را کامل کنید.)

### نکات و پیشنهادات

- `save(..., format="html")` در بخش CSS مقادیر رنگی به‌صورت جای‌خالی وجود دارد — بهتر است مقداردهی صریح انجام شود تا در نمایش مشکلی پیش نیاید.
- در زمان اضافه‌کردن `error`، همواره آن را به رشته تبدیل کنید تا JSON مشکلی نداشته باشد.

---

## 5.2 `NetworkTester`

### شرح کلی

اجرای تست‌های شبیه‌سازی شبکه، افزودن سرور mock به `NetworkSimulator` و اجرای آنالیز ترافیک، تشخیص VPN، شبیه‌سازی ARP/DNS spoofing و تزریق پکت‌ها.

### متدها

- `__init__(self, report: EnhancedReport, config: PentestConfig)` — تنظیم وابستگی‌ها.
- `run_all(self)` — مجموعهٔ تست‌های شبکه را اجرا می‌کند و نتایج را به گزارش اضافه می‌کند.

### نکات پیاده‌سازی

- در بخشی که `net_simulator.add_server` فراخوانی می‌شود، فرض بر داشتن متد `add_server` است که می‌تواند async باشد.
- بررسی استثنا‌ها و افزودن رکورد با severity مناسب انجام شده است.

---

## 5.3 `PenetrationTester`

### شرح کلی

شامل تست‌های حملات کلاسیک: brute force، SQLi (انواع مختلف)، XSS، LFI/Directory Traversal، Command Injection، Remote File Upload، SSRF، Open Redirect، HTTP Parameter Pollution، NoSQLi، OAuth/JWT checks و غیره.

### متدها

- `__init__(self, report: EnhancedReport, config: PentestConfig)`
- `run_all(self)` — اجرای مجموعهٔ تست‌ها روی `config.targets` و استفاده از متد `run_test` گزارش برای هر تست.

### نکات

- مراقب payloadهای خطرناک باشید (مثلاً `; rm -rf /`) — اینها تنها باید در محیط‌های ایزوله و تستی اجرا شوند.
- برای تست‌های واقعی، از sandbox یا محیط staging استفاده کنید.

---

## 5.4 `WebTester`

### شرح کلی

اجرای تست‌های مرتبط با اپلیکیشن‌های وب: خزنده، تجزیه هدر، فرم‌ها، WAF، CORS، Subdomain takeover، لاگین، Broken Auth، fuzzing API، تحلیل JSON و موارد مرتبط.

### متدها

- `run_all(self)` — نمونه‌هایی از اجرای `WebScraper`, `HeaderAnalyzer`, `FormAnalyzer`, `SecurityHeadersChecker`, `WAFDetector`, `CORSTester`, `SubdomainTakeoverDetector`, `LoginTester`, `BrokenAuthTester`, `APIEndpointTester`, `RateLimitTester`, `JSONResponseAnalyzer`, `APIFuzzer`, `CookieAnalyzer`, `RateLimitBypassTester`, `APIKeyExposureChecker`, `GraphQLAnalyzer`, `DOMHijackingDetector`, `CAPTCHASimulator`, `TwoFactorAuthTester`, `TLSChecker`, `RateLimiterBypass`.

### نکات

- برخی متدها (مثل `LoginTester.test`) نیاز به credentials دارند — دقت کنید که credentialهای پیش‌فرض امن نباشند و صرفاً برای تست هستند.

---

## 5.5 `SniffingTester`

### شرح کلی

شامل اجرای `PacketSniffer` روی اینترفیس‌های پیکربندی‌شده و سپس ذخیرهٔ داده‌های پکِت (سعی شده داده‌ها سریالایز شوند).

### متدها

- `run_all(self)` — اجرای sniffer و `MITMSimulator`.

### نکات

- دسترسی به اینترفیس‌های شبکه ممکن است نیاز به دسترسی root/administrator داشته باشد.
- اجرای sniffing در شبکه‌های غیرمجاز می‌تواند از نظر قانونی مشکل‌ساز باشد — فقط در محیط‌های آزمایشی یا با اجازه صریح مالک شبکه انجام دهید.

---

## 5.6 `UtilityTester`

### شرح کلی

تولید رمز عبور، ایجاد User-Agent تصادفی، اسکن پورت و یافتن زیر دامنه‌ها.

### متدها

- `run_all(self)` — اجرای `PasswordGenerator.generate`, `RandomUserAgent.generate`, `PortScanner.scan`, `SubdomainFinder.find`.

### نکات

- `RandomUserAgent().generate()` و `PasswordGenerator.generate()` در کد شما به‌صورت `await` فراخوانی می‌شوند، لذا فرض بر async بودن آنهاست. اگر نسخهٔ sync دارند باید wrapper یا تبدیل صورت گیرد.

---

## 5.7 `AdvancedPentestSuite`

### شرح کلی

مدیریت کلیۀ اجزا، مقداردهی اولیهٔ `PentestConfig` و `EnhancedReport` و ایجاد testerها. متدهای مهم:

- `run_all_tests(self)` — اجرای همزمان (`asyncio.gather`) تمام `tester.run_all()`ها.
- `generate_report(self)` — نمایش خلاصه و ذخیرهٔ گزارش در فرمت JSON و HTML.

# 6. اجرای نمونه

فایل نمونهٔ `main()` در کد شما وجود دارد. یک نمونهٔ ساده برای اجرا:

```python
async def main():
    suite = AdvancedPentestSuite()
    # سفارشی‌سازی پیکربندی پیش از اجرا
    suite.config.targets = ["https://staging.example.com"]
    suite.config.network_interfaces = ["eth0"]

    await suite.run_all_tests()
    await suite.generate_report()

if __name__ == '__main__':
    try:
        import asyncio
        asyncio.run(main())
    except KeyboardInterrupt:
        print('Stopped by user')
```

# 7. فرمت خروجی گزارش (JSON و HTML)

## JSON

ساختار کلی فایل `pentest_report.json`:

```json
{
  "results": {
    "<entry_id>": {
      "timestamp": 1690000000.0,
      "category": "Web",
      "name": "WebScraper.fetch",
      "data": { /* دادهٔ سریالایز شده یا پیام نوع داده */ },
      "severity": "INFO",
      "status": "SUCCESS",
      "error": null
    }
  },
  "summary": {
    "total_tests": 123,
    "passed": 0, /* توجه: فیلد passed در حال حاضر محاسبه نمیشود در کد */
    "failed": 1,
    "vulnerabilities": 2,
    "information": 120
  }
}
```

> نکته: در کد فعلی `summary['passed']` مقداردهی نشده؛ ممکن است لازم باشد مترکزی برای "passed" تعریف کنید یا فرمول محاسبه آن را اضافه کنید.

## HTML

- HTML یک صفحهٔ ساده با بخشِ Summary و Detailed Results تولید می‌کند.
- در کد فعلی CSS برخی مقادیر خالی هستند؛ برای نمایش بهتر، مقادیر رنگ و پس‌زمینه باید کامل شوند.

# 8. نکات مربوط به سریالایز کردن داده‌ها

- برخی ابزارها ممکن است اشیاء غیرقابل سریالایز (مثل پکِت‌های خام، socket objects یا انواع پیچیده) برگردانند. راهکارها:
  1. قبل از ذخیره، تلاش برای `json.dumps` و در صورت شکست، مقدار جایگزینی مانند `f"Non-serializable data of type: {type(...).__name__}"` ذخیره شود (همان کاری که شما انجام داده‌اید).
  2. برای اشیاء پیچیده، تابع کمکی `to_dict()` یا `to_json()` پیاده‌سازی کنید تا داده‌های کلیدی استخراج شوند.

# 9. امنیت و رعایت قوانین

- هرگز اسکن یا تست نفوذ را روی سامانه‌ای که مالک یا اجازهٔ صریح ندارید اجرا نکنید.
- تست‌های خطرناک مانند `; rm -rf /` فقط در محیط ایزوله و کانتینری اجرا شوند.
- لاگ‌ها و خروجی‌ها ممکن است شامل اطلاعات حساس (توکن‌ها، JWT، credential) باشند؛ فایل‌های گزارش را محافظت و در صورت نیاز رمزنگاری کنید.

# 10. توسعه و افزودن تست/ماژول جدید

برای افزودن تست جدید:

1. یک کلاس تست جدید در ماژول مناسب (`axn.attacks`, `axn.web`, ...) بسازید.
2. در `PentestConfig` فیلد‌های موردنیاز را اضافه کنید.
3. در Tester مربوطه (`PenetrationTester`, `WebTester`, ...) متد `run_all` را ویرایش کرده و `await self.report.run_test(NewTest(), "method", args...)` را اضافه کنید.

نکته: برای سازگاری با `EnhancedReport.run_test`، کلاس‌های تست باید متدهایی داشته باشند که یا `async def` باشند یا متدهای sync؛ `run_test` هر دو را پشتیبانی می‌کند.

# 11. خطاها و رفع مشکل متداول

- **مشکل:** `TypeError: Object of type X is not JSON serializable` — راه‌حل: برای آن نوع، `to_dict()` پیاده‌سازی کنید یا قبل از ذخیره مقدار جایگزین نصبت به نوع بنویسید.
- **مشکل:** دسترسی به اینترفیس شبکه رد شد — رفع: اجرای اسکریپت با مجوز ریشه یا استفاده از capabilityهای مناسب.
- **مشکل:** متدهای assumed-async در کتابخانه‌ها sync هستند — بررسی امضای متدها و در صورت نیاز از `asyncio.to_thread` یا wrapper استفاده کنید.

# 12. تغییرات پیشنهادی / TODO

- تکمیل CSS قالب HTML و طراحی بهتر گزارش (فیلتر، مرتب‌سازی، گروه‌بندی بر اساس severity).
- افزودن exporter های CSV و PDF.
- محاسبهٔ خودکار `summary['passed']` و سایر متریک‌ها.
- قابلیت تنظیم سطح لاگ و خروجی در زمان اجرا (CLI arguments یا فایل پیکربندی).
- اضافه کردن خط‌مشی نگهداری (rotation) برای فایل گزارش و رمزنگاری آن.
- تبدیل برخی ابزار به پلاگین قابل بارگذاری داینامیک (plugin architecture).

# 13. لایسنس و تشکر

- در صورت تقسیم کد، یک فایل `LICENSE` اضافه کنید (مثلاً MIT یا Apache-2.0) و در مستندات ذکر کنید.

---

## پیوست: مثال کامل فایل `run_pentest.py`

```python
import asyncio
from yourpackage import AdvancedPentestSuite, PentestConfig

async def main():
    suite = AdvancedPentestSuite()
    suite.config.targets = ["https://staging.example.com"]
    suite.config.network_interfaces = ["eth0"]
    # شخصی‌سازی دیگر پیکربندی

    await suite.run_all_tests()
    await suite.generate_report()

if __name__ == '__main__':
    asyncio.run(main())
```

---
