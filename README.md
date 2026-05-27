# ShopLab — Личная кибер-лаборатория

Учебный интернет-магазин-заглушка на **C# / ASP.NET Core 8** + **SQLite**.  
Создан как мишень для пентеста в рамках лабораторной работы по кибербезопасности.

---

## 🚀 Быстрый старт — два варианта

### Вариант 1: Демо-режим (без установки, прямо сейчас)

Откройте файл **`ShopLab_HackingLab.html`** в браузере — он работает автономно!

> **Встроенный Mock API** автоматически симулирует все уязвимости без запущенного сервера.  
> Подходит для ознакомления, презентации и демонстрации.

### Вариант 2: Полный режим (реальный C# сервер)

**Требования:** [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8) — Windows / macOS / Linux

```bash
# 1. Запустить уязвимую версию
cd ShopLab
dotnet run

# Приложение доступно:
# http://localhost:5000        — фронтенд
# http://localhost:5000/swagger — Swagger UI
```

После запуска откройте **`ShopLab_HackingLab.html`** — он автоматически подключится к серверу.

---

## Тестовые аккаунты

| Пользователь | Пароль   | Роль  | Баланс    |
|-------------|---------|-------|-----------| 
| admin       | admin123 | admin | 9 999 ₽   |
| alice       | alice123 | user  | 1 000 ₽   |
| bob         | bob123   | user  | 500 ₽     |

---

## Структура проекта

```
Proekt/
├── ShopLab/                        ← C# ASP.NET Core приложение
│   ├── Controllers/
│   │   ├── AuthController.cs       # /api/auth/*
│   │   ├── ProductsController.cs   # /api/products/*
│   │   └── OrdersController.cs     # /api/orders/*
│   ├── Data/
│   │   └── DatabaseService.cs      # SQLite + уязвимые SQL-запросы
│   ├── Models/
│   │   └── Models.cs               # Модели данных
│   ├── Services/
│   │   └── TokenService.cs         # JWT (намеренно без exp)
│   ├── wwwroot/
│   │   └── index.html              # Фронтенд магазина
│   ├── Program.cs                  # Конфигурация
│   └── ShopLab.csproj
├── fixed-patches/                  ← Исправленные версии файлов
│   ├── DatabaseService.fixed.cs
│   ├── Program.fixed.cs
│   ├── TokenService.fixed.cs
│   ├── AuthController.fixed.cs
│   └── OrdersController.fixed.cs
├── ShopLab_HackingLab.html         ← 🎯 ГЛАВНЫЙ ФАЙЛ ЛАБОРАТОРИИ
├── PENTEST_REPORT.md               ← Подробный отчёт с PoC
├── HACKING_GUIDE.md                ← Пошаговое руководство
├── setup-git.sh                    ← Скрипт для git-веток
└── README.md
```

---

## Уязвимости

| # | Класс | Серьёзность | Где |
|---|-------|-------------|-----|
| 1 | SQL Injection | 🔴 Critical | GET /api/products/search |
| 2 | Stored XSS | 🟠 High | POST /api/products/reviews |
| 3 | JWT без срока жизни | 🟡 Medium | Все защищённые эндпоинты |
| 4 | Слабое хеширование (MD5) | 🟠 High | Регистрация / хранение паролей |
| 5 | Hardcoded JWT Secret | 🟠 High | Program.cs |
| 6 | Логическая ошибка (цена) | 🟡 Medium | POST /api/orders/purchase |
| 7 | IDOR | 🟡 Medium | GET /api/orders/{id}, /transfer |

Подробный PoC — в файле `PENTEST_REPORT.md`.

---

## Применить исправления (git-ветка fixed)

```bash
cd ShopLab
bash ../setup-git.sh

# Переключиться на исправленную версию
git checkout fixed
export JWT_SECRET="super-secure-random-secret-key-2024"
dotnet run
```

---

## API Endpoints

| Метод | Endpoint | Auth | Описание |
|-------|----------|------|----------|
| POST | /api/auth/register | — | Регистрация |
| POST | /api/auth/login | — | Вход, JWT токен |
| GET | /api/auth/me | ✓ | Профиль пользователя |
| GET | /api/auth/users | Admin | Все пользователи |
| GET | /api/products | — | Список товаров |
| GET | /api/products/search?q=... | — | Поиск (SQLi) |
| GET | /api/products/{id}/reviews | — | Отзывы |
| POST | /api/products/reviews | ✓ | Добавить отзыв (XSS) |
| POST | /api/orders/purchase | ✓ | Купить (price manipulation) |
| GET | /api/orders/my | ✓ | Мои заказы |
| GET | /api/orders/{id} | ✓ | Заказ по ID (IDOR) |
| POST | /api/orders/transfer | ✓ | Перевод (IDOR) |
