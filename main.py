import sqlite3, os, subprocess, tempfile
import hashlib
from fastapi import FastAPI, Request, Form, HTTPException, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional
import re

app = FastAPI()

# Подключение шаблонов и статики
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Пути к БД
DB_USERS = "users.db"
DB_TASKS = "tasks.db"


# === Утилиты ===

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def validate_username(username: str) -> bool:
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username) is not None


def validate_password(password: str) -> bool:
    return len(password) >= 6


# === Инициализация БД ===

def init_db():
    # Пользователи
    with sqlite3.connect(DB_USERS) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)
        # Создаём admin по умолчанию (пароль: admin123)
        try:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", hash_password("admin123"), "admin")
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Уже существует

    # Задачи и тесты
    with sqlite3.connect(DB_TASKS) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER,
                input_data TEXT NOT NULL,
                expected_output TEXT NOT NULL,
                FOREIGN KEY (task_id) REFERENCES tasks (id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                task_id INTEGER,
                code TEXT,
                passed_tests INTEGER DEFAULT 0,
                total_tests INTEGER DEFAULT 0,
                status TEXT DEFAULT 'failed',
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (task_id) REFERENCES tasks (id)
            )
        """)


init_db()


# === Роуты ===

@app.get("/")
def root():
    return RedirectResponse("/login")


# --- Авторизация ---

@app.get("/register")
def get_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
def post_register(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...)
):
    if password != confirm_password:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пароли не совпадают."},
            status_code=400
        )
    if not validate_username(username):
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Логин: 3-20 символов, только буквы, цифры, _."},
            status_code=400
        )
    if not validate_password(password):
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пароль должен быть не короче 6 символов."},
            status_code=400
        )

    with sqlite3.connect(DB_USERS) as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(password), "user")  # Только user!
            )
            conn.commit()
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "success": "✅ Регистрация успешна Войдите в систему."},
                status_code=201
            )
        except sqlite3.IntegrityError:
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Пользователь с таким логином уже существует."},
                status_code=400
            )


@app.get("/login")
def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def post_login(
        request: Request,
        response: Response,
        username: str = Form(...),
        password: str = Form(...)
):
    hpass = hash_password(password)
    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
            (username, hpass)
        ).fetchone()

    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный логин или пароль."},
            status_code=401
        )

    # Сохраняем сессию в cookie
    response = RedirectResponse("/home", status_code=302)
    response.set_cookie(key="user_id", value=str(user[0]), httponly=True, max_age=3600)
    return response


# --- Главная ---

@app.get("/home")
def get_home(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    if not user:
        return RedirectResponse("/login")

    with sqlite3.connect(DB_TASKS) as conn:
        tasks = conn.execute(
            "SELECT id, title FROM tasks ORDER BY id"
        ).fetchall()
        records = [{"id": t[0], "title": t[1]} for t in tasks]

    return templates.TemplateResponse(
        "home.html",
        {"request": request, "user": {"id": user[0], "username": user[1], "role": user[2]}, "records": records}
    )


# --- Профиль ---

@app.get("/profile")
def get_profile(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    if not user:
        return RedirectResponse("/login")

    with sqlite3.connect(DB_TASKS) as conn:
        result = conn.execute("""
            SELECT 
                s.task_id,
                t.title,
                s.status,
                s.passed_tests,
                s.total_tests
            FROM submissions s
            JOIN tasks t ON s.task_id = t.id
            WHERE s.user_id = ?
            ORDER BY s.id DESC
        """, (user_id,)).fetchall()

        tasks = [
            {
                "task_id": r[0],
                "title": r[1],
                "status": r[2],
                "passed_tests": r[3],
                "total_tests": r[4]
            }
            for r in result
        ]

        solved = sum(1 for t in tasks if t["status"] == "passed")
        attempts = len(tasks)

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": {"username": user[1]},
            "stats": {"solved_tasks": solved, "attempts": attempts},
            "tasks": tasks
        }
    )


# --- Ввод данных (админ) ---

@app.get("/data-entry")
def get_data_entry(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user[0] != "admin":
        return RedirectResponse("/home")

    return templates.TemplateResponse("data_entry.html", {"request": request})


@app.post("/data-entry")
def post_data_entry(
        request: Request,
        title: str = Form(...),
        description: str = Form(...),
        input: list = Form(...),
        expected_output: list = Form(...)
):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user[0] != "admin":
        return RedirectResponse("/home")

    # Валидация
    if not title or len(title) > 100:
        return templates.TemplateResponse(
            "data_entry.html",
            {"request": request, "error": "Название задачи: 1–100 символов."},
            status_code=400
        )
    if not description or len(description) > 1000:
        return templates.TemplateResponse(
            "data_entry.html",
            {"request": request, "error": "Описание: 1–1000 символов."},
            status_code=400
        )
    if len(input) == 0 or len(input) != len(expected_output):
        return templates.TemplateResponse(
            "data_entry.html",
            {"request": request,
             "error": "Добавьте хотя бы один тест. Количество входов и ожидаемых результатов должно совпадать."},
            status_code=400
        )

    with sqlite3.connect(DB_TASKS) as conn:
        try:
            # Добавляем задачу
            conn.execute(
                "INSERT INTO tasks (title, description) VALUES (?, ?)",
                (title.strip(), description.strip())
            )
            task_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # Добавляем тесты
            for inp, exp in zip(input, expected_output):
                if inp.strip() == "" or exp.strip() == "":
                    continue
                conn.execute(
                    "INSERT INTO tests (task_id, input_data, expected_output) VALUES (?, ?, ?)",
                    (task_id, inp.strip(), exp.strip())
                )
            conn.commit()

            return templates.TemplateResponse(
                "data_entry.html",
                {"request": request, "success": f"✅ Задача «{title}» добавлена с {len(input)} тестами."},
                status_code=200
            )
        except Exception as e:
            return templates.TemplateResponse(
                "data_entry.html",
                {"request": request, "error": f"Ошибка базы данных: {str(e)}"},
                status_code=500
            )


# --- Выход ---

@app.post("/logout")
def logout(request: Request):
    response = RedirectResponse(url="/home", status_code=302)
    response.delete_cookie("user_id")
    return response


# --- Задачи (заглушка) ---

@app.get("/tasks/{task_id}")
def get_task(request: Request, task_id: int):
    try:
        user_id = request.cookies.get("user_id")
        if not user_id:
            return RedirectResponse("/login")

        try:
            user_id = int(user_id)
        except ValueError:
            return RedirectResponse("/login")

        # Проверяем, админ ли: просто user_id == 1
        is_admin = (user_id == 1)

        # Подключаемся к БД задач
        with sqlite3.connect(DB_TASKS) as conn:
            task = conn.execute(
                "SELECT id, title, description FROM tasks WHERE id = ?",
                (task_id,)
            ).fetchone()

        with sqlite3.connect(DB_TASKS) as conn:
            tests = conn.execute(
                "SELECT input_data, expected_output FROM tests WHERE task_id = ? LIMIT 2",
                (task_id,)
            ).fetchall()

        if not task:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        return templates.TemplateResponse(
            "task.html",
            {
                "request": request,
                "task": {
                    "id": task[0],
                    "title": task[1],
                    "description": task[2]
                },
                "current_user": {
                    "id": user_id,
                    "is_admin": is_admin
                },
                "examples": ({"input": t[0], "output": t[1]} for t in tests)
            }
        )
    except Exception as e:
        print(f"❌ Ошибка в /tasks/{task_id}: {e}")  # Лог в консоль
        raise HTTPException(status_code=500, detail="Ошибка на сервере. Смотри лог.")


@app.post("/check-solution")
def check_solution(
        request: Request,
        task_id: int = Form(...),
        code: str = Form(...)
):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    # Проверяем, существует ли задача
    with sqlite3.connect(DB_TASKS) as conn:
        task = conn.execute("SELECT id, title FROM tasks WHERE id = ?", (task_id,)).fetchone()
        tests = conn.execute("SELECT input_data, expected_output FROM tests WHERE task_id = ?", (task_id,)).fetchall()

    if not task:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    if not tests:
        return templates.TemplateResponse(
            "task.html",
            {"request": request, "task": {"id": task[0], "title": task[1], "description": "Нет тестов."},
             "error": "Нет тестов для проверки."},
            status_code=400
        )

    # Создаём файл с кодом
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        temp_file = f.name

    passed = 0
    total = len(tests)
    results = []

    try:
        for inp, expected in tests:
            # Подготовка ввода
            input_data = inp.strip()
            expected = expected.strip()

            # Запуск кода с вводом
            proc = subprocess.run(
                ["python", temp_file],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8"
            )

            output = proc.stdout.strip()
            error = proc.stderr

            if error:
                results.append({
                    "input": input_data,
                    "expected": expected,
                    "output": f"Ошибка: {error}",
                    "passed": False
                })
                continue

            if output == expected:
                passed += 1
                results.append({
                    "input": input_data,
                    "expected": expected,
                    "output": output,
                    "passed": True
                })
            else:
                results.append({
                    "input": input_data,
                    "expected": expected,
                    "output": output,
                    "passed": False
                })

        # Определяем статус
        status = "passed" if passed == total else "failed"

        # Сохраняем попытку
        with sqlite3.connect(DB_TASKS) as conn:
            conn.execute("""
                INSERT INTO submissions (user_id, task_id, code, passed_tests, total_tests, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, task_id, code, passed, total, status))
            conn.commit()

        # Удаляем временный файл
        os.unlink(temp_file)

        # Возвращаем результат
        return templates.TemplateResponse(
            "task.html",
            {
                "request": request,
                "task": {"id": task[0], "title": task[1], "description": "Описание задачи"},
                "results": results,
                "code": code,
                "total": total,
                "passed": passed,
                "status": status
            }
        )

    except subprocess.TimeoutExpired:
        os.unlink(temp_file)
        return templates.TemplateResponse(
            "task.html",
            {"request": request, "task": {"id": task[0], "title": task[1]},
             "error": "Превышено время выполнения (5 сек)."},
            status_code=400
        )
    except Exception as e:
        if os.path.exists(temp_file):
            os.unlink(temp_file)
        return templates.TemplateResponse(
            "task.html",
            {"request": request, "task": {"id": task_id, "title": task[1]}, "error": f"Ошибка выполнения: {str(e)}"},
            status_code=500
        )


@app.get("/edit-task")
def get_edit_task(request: Request, task_id: int):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    try:
        user_id = int(user_id)
    except ValueError:
        return RedirectResponse("/login")

    # Проверяем, что пользователь — админ
    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user[0] != "admin":
        return RedirectResponse("/home")

    # Получаем задачу
    with sqlite3.connect(DB_TASKS) as conn:
        task = conn.execute(
            "SELECT id, title, description FROM tasks WHERE id = ?",
            (task_id,)
        ).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Задача не найдена")

        tests = conn.execute(
            "SELECT id, input_data, expected_output FROM tests WHERE task_id = ?",
            (task_id,)
        ).fetchall()

    return templates.TemplateResponse("edit-task.html", {
        "request": request,
        "task": {
            "id": task[0],
            "title": task[1],
            "description": task[2]
        },
        "tests": [
            {"id": t[0], "input": t[1], "expected_output": t[2]}
            for t in tests
        ]
    })


@app.post("/update-task")
def post_update_task(
        request: Request,
        task_id: int = Form(...),
        title: str = Form(...),
        description: str = Form(...),
        test_id: list = Form(None),  # Может быть None, если тестов не было
        input_data: list = Form(...),
        expected_output: list = Form(...)
):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    try:
        user_id = int(user_id)
    except ValueError:
        return RedirectResponse("/login")

    # Проверка: админ ли?
    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user[0] != "admin":
        return RedirectResponse("/home")

    # Валидация
    if not title or len(title) > 100:
        return templates.TemplateResponse("edit-task.html", {
            "request": request,
            "error": "Название задачи: 1–100 символов."
        }, status_code=400)

    if not description or len(description) > 1000:
        return templates.TemplateResponse("edit-task.html", {
            "request": request,
            "error": "Описание: 1–1000 символов."
        }, status_code=400)

    if len(input_data) == 0 or len(input_data) != len(expected_output):
        return templates.TemplateResponse("edit-task.html", {
            "request": request,
            "error": "Добавьте хотя бы один тест. Количество входов и ожидаемых результатов должно совпадать."
        }, status_code=400)

    try:
        with sqlite3.connect(DB_TASKS) as conn:
            # Обновляем задачу
            conn.execute(
                "UPDATE tasks SET title = ?, description = ? WHERE id = ?",
                (title.strip(), description.strip(), task_id)
            )

            # Удаляем старые тесты
            conn.execute("DELETE FROM tests WHERE task_id = ?", (task_id,))

            # Добавляем новые тесты
            for inp, exp in zip(input_data, expected_output):
                if inp.strip() == "" or exp.strip() == "":
                    continue
                conn.execute(
                    "INSERT INTO tests (task_id, input_data, expected_output) VALUES (?, ?, ?)",
                    (task_id, inp.strip(), exp.strip())
                )
            conn.commit()

        return RedirectResponse(f"/tasks/{task_id}", status_code=302)

    except Exception as e:
        print(f"❌ Ошибка при обновлении задачи: {e}")
        return templates.TemplateResponse("edit-task.html", {
            "request": request,
            "error": f"Ошибка базы данных: {str(e)}"
        }, status_code=500)


@app.post("/delete-task")
def delete_task(request: Request, task_id: int = Form(...)):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    try:
        user_id = int(user_id)
    except ValueError:
        return RedirectResponse("/login")

    # Проверяем, что пользователь — админ
    with sqlite3.connect(DB_USERS) as conn:
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user[0] != "admin":
        return RedirectResponse("/home")

    try:
        with sqlite3.connect(DB_TASKS) as conn:
    # Удаляем сначала тесты (из-за внешнего ключа)
            conn.execute("DELETE FROM tests WHERE task_id = ?", (task_id,))
    # Потом саму задачу
            conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()

    except Exception as e:
        print(f"❌ Ошибка при удалении задачи {task_id}: {e}")
        return RedirectResponse("/home", status_code=302)

    # Перенаправляем на главную
    return RedirectResponse("/home", status_code=302)
