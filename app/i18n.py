"""Lightweight dict-based translations for the English/Persian bilingual UI.

Not Flask-Babel/gettext on purpose: with ~250 short strings and two locales,
a plain key->string lookup keeps translations easy to read and diff in git,
with no compile step and no new dependency.
"""

from flask import request, session

DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES = ("en", "fa")
COOKIE_NAME = "lang"

_TRANSLATIONS = {
    "en": {
        "site.name": "NouriShop",

        # --- nav / header (base.html) ---
        "nav.home": "Home",
        "nav.search_placeholder": "Search NouriShop, e.g. saffron or wireless earbuds...",
        "nav.search_btn": "Search",
        "nav.cart": "Cart",
        "nav.login_register": "Login / Register",
        "nav.logout": "Logout",
        "brand.tagline": "From NouriSec Academy",

        # --- footer (base.html) ---
        "footer.about_heading": "About NouriShop",
        "footer.about_text_html": (
            "An Iranian online marketplace for genuine goods you can trust, from handicrafts and "
            "traditional groceries to the latest digital gear, backed by an authenticity guarantee "
            "and real support. Proudly part of the "
            '<a href="https://nourisec.com" rel="noopener" target="_blank" style="color:#fff; text-decoration:underline;">NouriSec</a> family.'
        ),
        "footer.customer_service_heading": "Customer Service",
        "footer.academy_heading": "NouriSec Academy",
        "footer.link_about_safety": "About Us & Safety Notice",
        "footer.link_contact": "Contact Us",
        "footer.link_careers": "Careers",
        "footer.link_order_tracking": "Order Tracking",
        "footer.link_return_policy": "Return Policy",
        "footer.link_faq": "FAQ",
        "footer.link_terms": "Terms & Conditions",
        "footer.academy_text": (
            "NouriShop is a product of NouriSec Academy — the same team that teaches ethical "
            "cybersecurity and penetration testing with real, hands-on labs."
        ),
        "footer.youtube_channel": "NouriSec YouTube Channel",
        "footer.copyright_html": (
            "© 2025 NouriShop — All rights reserved. A product of "
            '<a href="https://nourisec.com" rel="noopener" target="_blank">NouriSec Academy</a>.'
        ),
        "footer.safety_notice_link": "Safety Notice & Educational Purpose",

        # --- home page ---
        "home.support_line": "24/7 Support: 021-91000770",
        "home.hero_eyebrow": "This Week's Special Offer",
        "home.hero_title_html": "From the Traditional Bazaar,<br>To Your Door",
        "home.hero_desc": (
            "Handicrafts, authentic Iranian groceries, and genuine digital goods — with fast "
            "shipping from Tehran, Mashhad, and Isfahan."
        ),
        "home.hero_cta": "Start Shopping",
        "home.promo_tag": "Up to 40% Off",
        "home.promo_title": "Nowruz Festival",
        "home.promo_desc": "Haft-sin, gifts, and traditional items for spring cleaning",
        "home.promo_link": "View Festival",
        "home.ad_brand_sub": "Cybersecurity & Penetration Testing Training",
        "home.ad_copy": (
            "The very store you're browsing right now is NouriSec Academy's training lab. Learn "
            "ethical hacking hands-on, from zero to professional reporting."
        ),
        "home.ad_youtube": "YouTube Channel",
        "home.trust_fast_shipping": "Fast Shipping",
        "home.trust_fast_shipping_desc": "24 to 72 hour delivery nationwide",
        "home.trust_authenticity": "Authenticity Guarantee",
        "home.trust_authenticity_desc": "Money-back guarantee if not as described",
        "home.trust_returns": "7-Day Return Policy",
        "home.trust_returns_desc": "No questions asked",
        "home.trust_secure_payment": "Secure Payment",
        "home.trust_secure_payment_desc": "Direct Central Bank gateway",
        "home.bestsellers_title": "NouriShop Bestsellers",
        "home.section_sub": "Based on real customer ratings and reviews",
        "home.view_all": "View all products →",
        "home.no_products": "No products to display.",

        # --- product card / detail ---
        "product.discount_pct": "{pct}% off",
        "product.no_reviews_short": "No reviews yet",
        "product.reviews_count": "({count} reviews)",
        "product.add_to_cart_short": "Add to Cart",
        "product.genuine_badge": "Genuine & Guaranteed Product",
        "product.no_reviews_for_product": "No reviews yet for this product",
        "product.sold_count": "{count}+ sold",
        "product.category_label": "Category",
        "product.status_label": "Status",
        "product.in_stock": "In Stock",
        "product.shipping_label": "Shipping",
        "product.shipping_value": "From central warehouse; 2-3 business day delivery",
        "product.discount_today": "{pct}% off today",
        "product.quantity_label": "Quantity",
        "product.add_to_cart": "Add to Cart",
        "product.cod_available": "Cash on delivery available",
        "product.return_policy_7day": "7-day return policy",
        "product.reviews_heading": "User Reviews ({count})",
        "product.no_reviews_be_first": "No reviews yet for this product. Be the first!",
        "product.your_rating": "Your Rating",
        "product.rating_5": "★★★★★ (Excellent)",
        "product.rating_4": "★★★★☆ (Good)",
        "product.rating_3": "★★★☆☆ (Average)",
        "product.rating_2": "★★☆☆☆ (Poor)",
        "product.rating_1": "★☆☆☆☆ (Bad)",
        "product.your_review": "Your Review",
        "product.review_placeholder": "Write your experience with this product...",
        "product.submit_review": "Submit Review",
        "product.login_prompt_suffix": " to write a review for this product.",
        "product.related_heading": "You might also like these products",

        # --- cart ---
        "cart.title": "Your Cart ({count} items)",
        "cart.qty_label": "Qty: {qty}",
        "cart.remove": "Remove",
        "cart.order_summary": "Order Summary",
        "cart.items_total": "Items Total",
        "cart.shipping_label": "Shipping",
        "cart.free": "Free",
        "cart.total_payable": "Total Payable",
        "cart.checkout_btn": "Proceed to Checkout",
        "cart.ad_copy": (
            "NouriShop is a product of NouriSec Academy. Curious how the security of a real "
            "online store is actually tested? Learn it at NouriSec Academy."
        ),
        "cart.view_nourisec": "View nourisec.com",
        "cart.empty": "Your cart is empty.",
        "cart.view_products": "View Products",

        # --- checkout ---
        "checkout.title": "Checkout",
        "checkout.info_alert": (
            "This is a test payment for educational purposes. No real amount will be charged - "
            "please do not enter real card information."
        ),
        "checkout.card_number": "Card Number (test)",
        "checkout.expiry": "Expiry Date (test)",
        "checkout.cvv": "CVV2 (test)",
        "checkout.submit": "Place Test Order",

        # --- profile ---
        "profile.title": "Profile: {username}",
        "profile.email_label": "Email:",
        "profile.role_label": "Role:",
        "profile.account_settings": "Account Settings",
        "profile.change_email": "Change Email",
        "profile.change_password": "Change Password",
        "profile.upload_avatar": "Upload Profile Picture",
        "profile.orders_heading": "Orders",
        "profile.no_orders": "No orders yet.",

        # --- auth pages ---
        "auth.login_title": "Login to Your Account",
        "auth.username_label": "Username",
        "auth.password_label": "Password",
        "auth.login_btn": "Login",
        "auth.forgot_password_link": "Forgot your password?",
        "auth.no_account": "Don't have an account?",
        "auth.register_link": "Register",
        "auth.register_title": "Create an Account",
        "auth.email_label": "Email",
        "auth.register_btn": "Register",
        "auth.already_registered": "Already registered?",
        "auth.login_link": "Log in",
        "auth.forgot_title": "Password Recovery",
        "auth.send_reset_link": "Send Recovery Link",
        "auth.reset_title": "Set New Password",
        "auth.new_password_label": "New Password",
        "auth.update_password_btn": "Update Password",

        # --- search ---
        "search.title": "Search results for: {query}",
        "search.no_results": "No products found matching this term.",
        "search.view_product": "View Product",

        # --- orders / order detail ---
        "orders.title": "My Orders",
        "orders.order_link": "Order #{id} - {total} {currency} - {status}",
        "order_detail.title": "Order #{id}",
        "order_detail.subtitle": "For user #{user_id} · Status: {status} · Total: {total} {currency}",
        "order_detail.product_col": "Product",
        "order_detail.qty_col": "Quantity",
        "order_detail.price_col": "Price",

        # --- contact ---
        "contact.title": "Contact Us",
        "contact.name_label": "Name",
        "contact.message_label": "Message",
        "contact.send_btn": "Send Message",

        # --- dev debug page ---
        "dev.debug_notice": "(This debug page should not exist in a real deployment.)",
        "dev.last_request_for": "Last password reset request for user:",
        "dev.link_label": "Link:",
        "dev.no_request_yet": "No password reset request yet.",

        # --- admin ---
        "admin.panel_title": "Admin Panel",
        "admin.users_count": "Users: {count}",
        "admin.products_count": "Products: {count}",
        "admin.orders_count": "Orders: {count}",
        "admin.manage_users": "Manage Users",
        "admin.manage_products": "Manage Products",
        "admin.view_orders": "View Orders",
        "admin.server_health": "Server Health Check",
        "admin.fetch_image_title": "Fetch Product Image from URL",
        "admin.reset_confirm": "Reset database to initial state?",
        "admin.reset_btn": "Reset Database",
        "admin.fetch_image_desc": "Enter a URL for the server to download the image from.",
        "admin.fetch_btn": "Fetch",
        "admin.saved_to": "Saved to:",
        "admin.all_orders": "All Orders",
        "admin.col_id": "ID",
        "admin.col_user": "User",
        "admin.col_total": "Total",
        "admin.col_status": "Status",
        "admin.col_date": "Date",
        "admin.ping_desc": "Ping an internal host to check connectivity.",
        "admin.ping_btn": "Ping",
        "admin.products_title": "Products",
        "admin.col_name": "Name",
        "admin.col_category": "Category",
        "admin.col_price": "Price",
        "admin.price_toman_label": "Price (Toman)",
        "admin.description_label": "Description",
        "admin.add_product_btn": "Add Product",
        "admin.delete_btn": "Delete",
        "admin.users_title": "Users",
        "admin.col_username": "Username",
        "admin.col_email": "Email",
        "admin.col_role": "Role",
        "admin.col_password_hash": "Password Hash",

        # --- shared / common ---
        "common.update_btn": "Update",
        "common.upload_btn": "Upload",
        "common.flash_login_required": "Please log in first.",
        "common.order_link": "Order #{id} - {total} {currency}",

        "currency.toman": "Toman",

        # --- flash messages ---
        "auth.flash_username_password_required": "Username and password are required.",
        "auth.flash_username_taken": "This username is already taken.",
        "auth.flash_account_created": "Your account has been created. You can now log in.",
        "auth.flash_welcome": "Welcome, {username}!",
        "auth.flash_invalid_login": "Incorrect username or password.",
        "auth.flash_logged_out": "You have been logged out.",
        "auth.flash_reset_link_sent": "If this account exists, a password reset link has been sent to the registered email.",
        "auth.flash_reset_invalid": "This reset link is invalid or has expired.",
        "auth.flash_password_changed": "Your password has been changed successfully. Please log in.",

        "admin.flash_product_added": "Product added.",
        "admin.flash_product_deleted": "Product deleted.",
        "admin.flash_db_reset": "Database has been reset to its initial state.",

        "shop.flash_product_not_found": "The requested product was not found.",
        "shop.flash_added_to_cart": "Added to cart.",
        "shop.flash_login_to_checkout": "Please log in to your account to continue checkout.",
        "shop.flash_cart_empty": "Your cart is empty.",
        "shop.flash_order_success": "Your order was placed successfully! (This is a test payment; no real amount was charged.)",

        "account.flash_user_not_found": "The requested user was not found.",
        "account.flash_order_not_found": "The requested order was not found.",
        "account.flash_email_updated": "Email updated successfully.",
        "account.flash_password_updated": "Password updated successfully.",

        "reviews.flash_login_to_review": "Please log in to your account to write a review.",
        "reviews.flash_review_submitted": "Your review has been submitted successfully.",

        "contact.flash_message_sent": "Your message has been received - our (test) support team will reply soon.",

        "uploads.flash_no_file": "No file was selected.",
        "uploads.flash_file_type_not_allowed": "This file type is not allowed.",
        "uploads.flash_avatar_updated": "Profile picture updated.",
    },
    "fa": {
        "site.name": "نوری‌شاپ",

        "nav.home": "خانه",
        "nav.search_placeholder": "جستجو در نوری‌شاپ؛ مثلا زعفران یا هدفون بی‌سیم...",
        "nav.search_btn": "جستجو",
        "nav.cart": "سبد خرید",
        "nav.login_register": "ورود / ثبت‌نام",
        "nav.logout": "خروج",
        "brand.tagline": "از آکادمی NouriSec",

        "footer.about_heading": "درباره نوری‌شاپ",
        "footer.about_text_html": (
            "بازار آنلاین ایرانی برای خرید مطمئن کالای اصل، از صنایع‌دستی و خواربار سنتی تا دیجیتال روز؛ "
            "با ضمانت اصالت و پشتیبانی واقعی. با افتخار، بخشی از خانواده "
            '<a href="https://nourisec.com" rel="noopener" target="_blank" style="color:#fff; text-decoration:underline;">نوری‌سک</a>.'
        ),
        "footer.customer_service_heading": "خدمات مشتریان",
        "footer.academy_heading": "آکادمی نوری‌سک",
        "footer.link_about_safety": "درباره ما و بیانیه ایمنی",
        "footer.link_contact": "تماس با ما",
        "footer.link_careers": "فرصت‌های شغلی",
        "footer.link_order_tracking": "پیگیری سفارش",
        "footer.link_return_policy": "راهنمای بازگشت کالا",
        "footer.link_faq": "پرسش‌های متداول",
        "footer.link_terms": "قوانین و مقررات",
        "footer.academy_text": (
            "نوری‌شاپ محصولی از آکادمی نوری‌سک است — همان تیمی که امنیت سایبری و تست نفوذ قانونمند را با "
            "آزمایشگاه‌های عملی واقعی آموزش می‌دهد."
        ),
        "footer.youtube_channel": "کانال یوتیوب NouriSec",
        "footer.copyright_html": (
            "© ۱۴۰۴ نوری‌شاپ — کلیه حقوق محفوظ است. محصولی از "
            '<a href="https://nourisec.com" rel="noopener" target="_blank">آکادمی نوری‌سک</a>.'
        ),
        "footer.safety_notice_link": "بیانیه ایمنی و اهداف آموزشی",

        "home.support_line": "پشتیبانی ۲۴ ساعته: ۰۲۱-۹۱۰۰۰۷۷۰",
        "home.hero_eyebrow": "فروش ویژه هفته",
        "home.hero_title_html": "از دل بازار سنتی،<br>به دست شما",
        "home.hero_desc": (
            "صنایع‌دستی، خواربار اصیل ایرانی و کالای دیجیتال اورجینال؛ با ارسال سریع از تهران، مشهد و اصفهان."
        ),
        "home.hero_cta": "شروع خرید",
        "home.promo_tag": "تا ۴۰٪ تخفیف",
        "home.promo_title": "جشنواره نوروز ۱۴۰۴",
        "home.promo_desc": "هفت‌سین، عیدی و محصولات سنتی برای خانه‌تکانی بهاره",
        "home.promo_link": "مشاهده جشنواره",
        "home.ad_brand_sub": "آموزش امنیت سایبری و تست نفوذ",
        "home.ad_copy": (
            "همین فروشگاهی که در حال گشتن آن هستید، آزمایشگاه آموزشی آکادمی نوری‌سک است. دوره‌های عملی "
            "هک قانونمند را از صفر تا گزارش‌نویسی حرفه‌ای یاد بگیرید."
        ),
        "home.ad_youtube": "کانال یوتیوب",
        "home.trust_fast_shipping": "ارسال سریع",
        "home.trust_fast_shipping_desc": "تحویل ۲۴ تا ۷۲ ساعته در سراسر کشور",
        "home.trust_authenticity": "ضمانت اصالت کالا",
        "home.trust_authenticity_desc": "تضمین بازگشت وجه در صورت مغایرت",
        "home.trust_returns": "۷ روز ضمانت بازگشت",
        "home.trust_returns_desc": "بدون پرسش، بدون دردسر",
        "home.trust_secure_payment": "پرداخت امن",
        "home.trust_secure_payment_desc": "درگاه مستقیم بانک مرکزی",
        "home.bestsellers_title": "پرفروش‌ترین‌های نوری‌شاپ",
        "home.section_sub": "بر اساس امتیاز و نظرات واقعی مشتریان",
        "home.view_all": "مشاهده همه محصولات ←",
        "home.no_products": "محصولی برای نمایش وجود ندارد.",

        "product.discount_pct": "{pct}٪ تخفیف",
        "product.no_reviews_short": "هنوز نظری ثبت نشده",
        "product.reviews_count": "({count} نظر)",
        "product.add_to_cart_short": "افزودن به سبد",
        "product.genuine_badge": "کالای اصل و تضمینی",
        "product.no_reviews_for_product": "هنوز نظری برای این محصول ثبت نشده",
        "product.sold_count": "{count}+ فروش",
        "product.category_label": "دسته‌بندی",
        "product.status_label": "وضعیت",
        "product.in_stock": "موجود در انبار",
        "product.shipping_label": "ارسال",
        "product.shipping_value": "از انبار مرکزی؛ تحویل ۲ تا ۳ روز کاری",
        "product.discount_today": "{pct}٪ تخفیف امروز",
        "product.quantity_label": "تعداد",
        "product.add_to_cart": "افزودن به سبد خرید",
        "product.cod_available": "امکان پرداخت در محل",
        "product.return_policy_7day": "۷ روز ضمانت بازگشت کالا",
        "product.reviews_heading": "نظرات کاربران ({count})",
        "product.no_reviews_be_first": "هنوز نظری برای این محصول ثبت نشده. اولین نفر باشید!",
        "product.your_rating": "امتیاز شما",
        "product.rating_5": "★★★★★ (عالی)",
        "product.rating_4": "★★★★☆ (خوب)",
        "product.rating_3": "★★★☆☆ (متوسط)",
        "product.rating_2": "★★☆☆☆ (ضعیف)",
        "product.rating_1": "★☆☆☆☆ (بد)",
        "product.your_review": "نظر شما",
        "product.review_placeholder": "تجربه خود از این محصول را بنویسید...",
        "product.submit_review": "ثبت نظر",
        "product.login_prompt_suffix": " تا بتوانید برای این محصول نظر ثبت کنید.",
        "product.related_heading": "شاید این محصولات را هم دوست داشته باشید",

        "cart.title": "سبد خرید شما ({count} کالا)",
        "cart.qty_label": "تعداد: {qty}",
        "cart.remove": "حذف",
        "cart.order_summary": "خلاصه سفارش",
        "cart.items_total": "جمع کل کالاها",
        "cart.shipping_label": "هزینه ارسال",
        "cart.free": "رایگان",
        "cart.total_payable": "مبلغ قابل پرداخت",
        "cart.checkout_btn": "ادامه فرآیند خرید",
        "cart.ad_copy": (
            "نوری‌شاپ محصولی از آکادمی نوری‌سک است. کنجکاوید بدونید امنیت یک فروشگاه اینترنتی واقعی چطور "
            "تضمین می‌شه؟ در آکادمی نوری‌سک یاد بگیرید."
        ),
        "cart.view_nourisec": "مشاهده nourisec.com",
        "cart.empty": "سبد خرید شما خالی است.",
        "cart.view_products": "مشاهده محصولات",

        "checkout.title": "تسویه حساب",
        "checkout.info_alert": (
            "این یک پرداخت آزمایشی برای اهداف آموزشی است. هیچ مبلغ واقعی کسر نمی‌شود - لطفا اطلاعات "
            "کارت واقعی وارد نکنید."
        ),
        "checkout.card_number": "شماره کارت (آزمایشی)",
        "checkout.expiry": "تاریخ انقضا (آزمایشی)",
        "checkout.cvv": "CVV2 (آزمایشی)",
        "checkout.submit": "ثبت سفارش آزمایشی",

        "profile.title": "پروفایل: {username}",
        "profile.email_label": "ایمیل:",
        "profile.role_label": "نقش:",
        "profile.account_settings": "تنظیمات حساب",
        "profile.change_email": "تغییر ایمیل",
        "profile.change_password": "تغییر رمز عبور",
        "profile.upload_avatar": "آپلود تصویر پروفایل",
        "profile.orders_heading": "سفارش‌ها",
        "profile.no_orders": "هنوز سفارشی ثبت نشده.",

        "auth.login_title": "ورود به حساب کاربری",
        "auth.username_label": "نام کاربری",
        "auth.password_label": "رمز عبور",
        "auth.login_btn": "ورود",
        "auth.forgot_password_link": "رمز عبور را فراموش کرده‌اید؟",
        "auth.no_account": "حساب کاربری ندارید؟",
        "auth.register_link": "ثبت‌نام کنید",
        "auth.register_title": "ساخت حساب کاربری",
        "auth.email_label": "ایمیل",
        "auth.register_btn": "ثبت‌نام",
        "auth.already_registered": "قبلا ثبت‌نام کرده‌اید؟",
        "auth.login_link": "وارد شوید",
        "auth.forgot_title": "بازیابی رمز عبور",
        "auth.send_reset_link": "ارسال لینک بازیابی",
        "auth.reset_title": "تعیین رمز عبور جدید",
        "auth.new_password_label": "رمز عبور جدید",
        "auth.update_password_btn": "به‌روزرسانی رمز عبور",

        "search.title": "نتایج جستجو برای: {query}",
        "search.no_results": "هیچ محصولی با این عبارت پیدا نشد.",
        "search.view_product": "مشاهده محصول",

        "orders.title": "سفارش‌های من",
        "orders.order_link": "سفارش #{id} - {total} {currency} - {status}",
        "order_detail.title": "سفارش #{id}",
        "order_detail.subtitle": "مربوط به کاربر شماره {user_id} · وضعیت: {status} · مبلغ کل: {total} {currency}",
        "order_detail.product_col": "محصول",
        "order_detail.qty_col": "تعداد",
        "order_detail.price_col": "قیمت",

        "contact.title": "تماس با ما",
        "contact.name_label": "نام",
        "contact.message_label": "پیام",
        "contact.send_btn": "ارسال پیام",

        "dev.debug_notice": "(این صفحه دیباگ نباید در نسخه واقعی وجود داشته باشد.)",
        "dev.last_request_for": "آخرین درخواست بازیابی برای کاربر:",
        "dev.link_label": "لینک:",
        "dev.no_request_yet": "هنوز درخواست بازیابی رمزی ثبت نشده است.",

        "admin.panel_title": "پنل مدیریت",
        "admin.users_count": "کاربران: {count}",
        "admin.products_count": "محصولات: {count}",
        "admin.orders_count": "سفارش‌ها: {count}",
        "admin.manage_users": "مدیریت کاربران",
        "admin.manage_products": "مدیریت محصولات",
        "admin.view_orders": "مشاهده سفارش‌ها",
        "admin.server_health": "بررسی سلامت سرور",
        "admin.fetch_image_title": "دریافت تصویر محصول از URL",
        "admin.reset_confirm": "پایگاه‌داده به حالت اولیه بازنشانی شود؟",
        "admin.reset_btn": "بازنشانی پایگاه‌داده",
        "admin.fetch_image_desc": "یک آدرس وارد کنید تا سرور تصویر را دانلود کند.",
        "admin.fetch_btn": "دریافت",
        "admin.saved_to": "ذخیره شد در:",
        "admin.all_orders": "همه سفارش‌ها",
        "admin.col_id": "شناسه",
        "admin.col_user": "کاربر",
        "admin.col_total": "مبلغ کل",
        "admin.col_status": "وضعیت",
        "admin.col_date": "تاریخ ثبت",
        "admin.ping_desc": "یک هاست داخلی را برای بررسی اتصال پینگ کنید.",
        "admin.ping_btn": "پینگ",
        "admin.products_title": "محصولات",
        "admin.col_name": "نام",
        "admin.col_category": "دسته‌بندی",
        "admin.col_price": "قیمت",
        "admin.price_toman_label": "قیمت (تومان)",
        "admin.description_label": "توضیحات",
        "admin.add_product_btn": "افزودن محصول",
        "admin.delete_btn": "حذف",
        "admin.users_title": "کاربران",
        "admin.col_username": "نام کاربری",
        "admin.col_email": "ایمیل",
        "admin.col_role": "نقش",
        "admin.col_password_hash": "هش رمز عبور",

        "common.update_btn": "به‌روزرسانی",
        "common.upload_btn": "آپلود",
        "common.flash_login_required": "لطفا ابتدا وارد شوید.",
        "common.order_link": "سفارش #{id} - {total} {currency}",

        "currency.toman": "تومان",

        "auth.flash_username_password_required": "نام کاربری و رمز عبور الزامی است.",
        "auth.flash_username_taken": "این نام کاربری قبلا استفاده شده است.",
        "auth.flash_account_created": "حساب کاربری شما ساخته شد. اکنون می‌توانید وارد شوید.",
        "auth.flash_welcome": "خوش آمدید، {username}!",
        "auth.flash_invalid_login": "نام کاربری یا رمز عبور اشتباه است.",
        "auth.flash_logged_out": "از حساب کاربری خود خارج شدید.",
        "auth.flash_reset_link_sent": "در صورت وجود این حساب کاربری، لینک بازیابی رمز عبور به ایمیل ثبت‌شده ارسال شد.",
        "auth.flash_reset_invalid": "لینک بازیابی نامعتبر یا منقضی شده است.",
        "auth.flash_password_changed": "رمز عبور با موفقیت تغییر کرد. لطفا وارد شوید.",

        "admin.flash_product_added": "محصول اضافه شد.",
        "admin.flash_product_deleted": "محصول حذف شد.",
        "admin.flash_db_reset": "پایگاه‌داده به حالت اولیه بازنشانی شد.",

        "shop.flash_product_not_found": "محصول مورد نظر پیدا نشد.",
        "shop.flash_added_to_cart": "به سبد خرید اضافه شد.",
        "shop.flash_login_to_checkout": "برای ادامه خرید ابتدا وارد حساب کاربری خود شوید.",
        "shop.flash_cart_empty": "سبد خرید شما خالی است.",
        "shop.flash_order_success": "سفارش شما با موفقیت ثبت شد! (این یک پرداخت آزمایشی است و مبلغ واقعی کسر نشده.)",

        "account.flash_user_not_found": "کاربر مورد نظر پیدا نشد.",
        "account.flash_order_not_found": "سفارش مورد نظر پیدا نشد.",
        "account.flash_email_updated": "ایمیل با موفقیت به‌روزرسانی شد.",
        "account.flash_password_updated": "رمز عبور با موفقیت به‌روزرسانی شد.",

        "reviews.flash_login_to_review": "برای ثبت نظر ابتدا وارد حساب کاربری خود شوید.",
        "reviews.flash_review_submitted": "نظر شما با موفقیت ثبت شد.",

        "contact.flash_message_sent": "پیام شما ثبت شد - تیم پشتیبانی (آزمایشی) به‌زودی پاسخ می‌دهد.",

        "uploads.flash_no_file": "فایلی انتخاب نشده است.",
        "uploads.flash_file_type_not_allowed": "این نوع فایل مجاز نیست.",
        "uploads.flash_avatar_updated": "تصویر پروفایل به‌روزرسانی شد.",
    },
}


# Product categories are stored in the DB / matched in URLs by their Persian value
# (see CATEGORIES in app/shop.py), so only the displayed label is translated here -
# the underlying value used for filtering and matching stays Persian in both locales.
_CATEGORY_LABELS = {
    "موبایل و دیجیتال": "Mobile & Electronics",
    "خواربار ایرانی": "Iranian Groceries",
    "مد و پوشاک": "Fashion & Apparel",
    "زیبایی و سلامت": "Beauty & Health",
    "صنایع‌دستی": "Handicrafts",
}


def get_locale():
    lang = session.get("lang") or request.cookies.get(COOKIE_NAME)
    return lang if lang in SUPPORTED_LOCALES else DEFAULT_LOCALE


def t(key, **kwargs):
    locale = get_locale()
    text = _TRANSLATIONS.get(locale, {}).get(key)
    if text is None:
        text = _TRANSLATIONS[DEFAULT_LOCALE].get(key, key)
    return text.format(**kwargs) if kwargs else text


def category_label(category):
    if not category:
        return category
    if get_locale() == "en":
        return _CATEGORY_LABELS.get(category, category)
    return category
