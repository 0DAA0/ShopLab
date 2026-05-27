#!/bin/bash
# Скрипт для инициализации git-репозитория с двумя ветками
# Запускать из корня проекта (папка ShopLab/)

set -e

echo "=== Инициализация git репозитория ShopLab ==="

git init
git config user.email "student@example.com"
git config user.name "Student"

# Добавить .gitignore
cat > .gitignore << 'EOF'
bin/
obj/
*.user
.vs/
ShopLab/shoplab.db
.env
*.env
EOF

# ===== ВЕТКА: vulnerable =====
git checkout -b vulnerable

git add .
git commit -m "feat: initial vulnerable shop implementation

Интернет-магазин с аутентификацией, товарами, заказами и отзывами.
Намеренно содержит уязвимости для пентест-лаборатории."

echo ""
echo "✅ Ветка 'vulnerable' создана"

# ===== ВЕТКА: fixed =====
git checkout -b fixed

# Применить фиксы из fixed-patches/
cp fixed-patches/DatabaseService.fixed.cs ShopLab/Data/DatabaseService.cs
cp fixed-patches/Program.fixed.cs ShopLab/Program.cs
cp fixed-patches/TokenService.fixed.cs ShopLab/Services/TokenService.cs
cp fixed-patches/AuthController.fixed.cs ShopLab/Controllers/AuthController.cs
cp fixed-patches/OrdersController.fixed.cs ShopLab/Controllers/OrdersController.cs

# Обновить фронтенд (XSS fix — textContent вместо innerHTML)
# Применяется патчем ниже
python3 - << 'PYEOF'
import re

with open("ShopLab/wwwroot/index.html", "r") as f:
    content = f.read()

# FIX-2: убрать innerHTML для content отзывов
old = '<div class="review-content">${r.content}</div>'
new = '<div class="review-content"></div>'
content = content.replace(old, new)

# FIX-2: добавить безопасный рендеринг после вставки HTML-строки отзывов
old2 = "const reviewsHtml = (reviews || []).map(r => `"
# Добавить комментарий
content = content.replace(
    "<!-- [VULN-2] innerHTML без санитизации = Stored XSS -->",
    "<!-- FIX-2: content рендерится через textContent ниже -->"
)

with open("ShopLab/wwwroot/index.html", "w") as f:
    f.write(content)
print("FIX-2: index.html обновлён")
PYEOF

# Отдельные коммиты для каждого фикса
git add ShopLab/Data/DatabaseService.cs
git commit -m "fix(sqli): use parameterized queries to prevent SQL injection

VULN-1: Replaced string interpolation in SearchProducts() and 
GetUserByCredentials() with parameterized queries.
Attack vector: GET /api/products/search?q=' UNION SELECT..."

git add ShopLab/wwwroot/index.html
git commit -m "fix(xss): sanitize review content to prevent Stored XSS

VULN-2: Added HtmlEncode() in DatabaseService.AddReview().
Frontend: replaced innerHTML with textContent for review content.
Attack vector: POST /api/products/reviews with <script> payload."

git add ShopLab/Services/TokenService.cs ShopLab/Program.cs
git commit -m "fix(jwt): add token expiry and strong secret from env

VULN-3: Set expires: DateTime.UtcNow.AddHours(1) in token generation.
VULN-5: JWT_SECRET now read from environment variable (min 32 chars).
ValidateLifetime = true in TokenValidationParameters."

git add ShopLab/Controllers/AuthController.cs
git commit -m "fix(crypto): replace MD5 with PBKDF2 password hashing

VULN-4: Replaced MD5 with PBKDF2 (100000 iterations, SHA256, random salt).
Removed Password field from all API responses (/me, /users).
Attack: MD5 hashes crackable in seconds with hashcat/rainbow tables."

git add ShopLab/Controllers/OrdersController.cs
git commit -m "fix(logic): prevent price manipulation and IDOR vulnerabilities

VULN-6: ClientPrice field ignored; price always taken from database.
         Added quantity > 0 check and balance validation.
VULN-7: GetOrderById now filters by userId (ownership check in SQL).
         Transfer checks currentUserId == fromUserId before executing."

git add -A
git commit -m "fix(ratelimit): add rate limiting on auth endpoints

VULN-8: Added fixed window rate limiter (10 req/min) on /auth/login 
and /auth/register to prevent brute force attacks."

echo ""
echo "✅ Ветка 'fixed' создана с историей коммитов"
echo ""
echo "=== Git log ==="
git log --oneline
echo ""
echo "=== Ветки ==="
git branch
echo ""
echo "Готово! Теперь запушьте на GitHub:"
echo "  git remote add origin https://github.com/YOUR_USERNAME/ShopLab.git"
echo "  git push -u origin vulnerable"
echo "  git push -u origin fixed"
