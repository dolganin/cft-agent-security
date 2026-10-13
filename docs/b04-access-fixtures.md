# B04. Операторские роли, объекты и проверяемая личность

Роман, 14 октября 2026. Основа `main b05b3e7`, ветка `access-control-fixtures`.
Это подготовка и контроль fixture для будущих B05/B06, без verdict об уязвимости.

## Что подготовлено

`targets/juice-access-fixture.yaml` содержит типизированный `AccessFixtureProfile`:
две роли, пять явных object specs, полную матрицу десяти actor/object permissions,
фиксированный adapter и reset adapter. Обе роли — обычные `customer`, не admin.
Read/update permissions являются операторским ожидаемым правилом owner-only,
а не доказательством, что любой endpoint приложения уже правильно его реализует.

| Registry ID | Владелец | Фиксированные данные |
| --- | --- | --- |
| `basket-a` | `role-a` | Product 1, quantity 1 |
| `basket-b` | `role-b` | Product 1, quantity 2 |
| `address-a` | `role-a` | Отдельный синтетический private marker |
| `address-b` | `role-b` | Другой синтетический private marker |
| `negative-control-b` | `role-b` | Отдельный защищённый адрес для deny control |

Регистрация, обычный login и создание собственных объектов выполняются через
фиксированные существующие APIs внутри disposable Docker lab. Код цели,
проверки доступа, исходный checkout и исторические A01–A08/B01 profiles не меняются.
Никакой инъекции уязвимостей или setup через модель нет.

## Как доказываются identity, ownership и availability

`executor/access_fixture_worker.py` запрашивает серверный
`whoami?fields=id,email,role`, сопоставляет результат с отдельно зарегистрированным
ID/email и ожидаемой ролью `customer`. Client-side JWT decode не является доказательством.
HTTP 200 с пустым `user` не считается аутентификацией.

Каждое owner-read окружено двумя независимыми identity запросами того же actor.
Чтение проверяет реальный object ID, серверный `UserId`, private marker/quantity
и логический baseline digest. Для отрицательного контроля A читает отдельный
B-owned address: требуется точный application denial. B читает этот объект
до и после отказа A; удалённый или недоступный объект не имитирует проверку прав.
Отдельно проверяется anonymous identity, которая не должна иметь user ID.

Public `AccessFixtureContext` содержит зарегистрированные и полученные server IDs,
SHA-256 сравниваемых identity facts, owner IDs, object digests, permissions и
redacted HTTP observations с номерами exchanges. Schema проверяет согласованность
фактов, identity bracketing, отдельный negative control и его owner availability.
Набора boolean `ready=true` без этих наблюдений недостаточно.

Любая потеря/подмена identity, смена server role, owner mismatch, изменённый baseline,
ошибка controls, redirect, truncation, non-JSON, timeout или technical failure
даёт `inconclusive`. Identity/ownership flags такой попытки сбрасываются. B04 не
возвращает finding verdict `confirmed/rejected`: `ready` означает готовую fixture.

## Credentials, scope и reset

Пароли случайны и создаются внутри worker. Emails отделены по generation.
Session tokens живут только в приватном `/state` tmpfs (directory 0700, file 0600)
non-root Docker worker. Они не передаются через argv, host environment, model input,
public Context, artifacts или logs. Host broker хранит только opaque IDs и public facts.
Модель не может передать credentials, URL, request body, объект вне registry или
операцию подготовки: adapter не зарегистрирован как агентная capability.

`AccessFixtureLab` принадлежит операторскому orchestration и не хранится в AgentState.
Модель/следующий компонент могут получать только сериализуемый public Context.
Fixture ID, generation, source snapshot и profile digest связывают каждый контроль.
Source inventory из восьми файлов проверяется до/после операции, а target checkout
проверяется против pinned Git tree. Это операторская source/image привязка, не
независимая аттестация сборки image.

Reset уничтожает оба контейнера, anonymous volumes этих контейнеров и private network,
проверяет отсутствие ресурсов по собственному generation label и создаёт новый стенд.
Нет общего DB volume, host data mount, published port, Docker socket или Docker prune.
Старый/закрытый handle отклоняется до исполнения. Неизвестная cleanup блокирует reset.
Операции одного broker сериализованы; разные labs имеют разные names/networks/generations.

Signing key исходного Juice Shop не переписывается: глобальная криптографическая
ревокация JWT между чужими replicas не заявляется. Изоляция обеспечивается уничтожением
стенда/secret store и запретом старого broker handle. Внешние tokens не принимаются;
каждый следующий probe должен заново доказать актуальную server identity.

## Границы и бюджеты

| Ограничение | Значение |
| --- | --- |
| Target | Juice Shop v20.2.0, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`, pinned image |
| Worker | Pinned Python image; стандартная библиотека, без model/API calls |
| Startup | 90 s; readiness probe attempts записаны отдельно |
| Worker operation wall time | 120 s, Linux alarm; host exec timeout 130 s с уничтожением lab |
| Per-request socket timeout | До 3 s и оставшегося времени операции |
| Prepare HTTP budget | 64; фактически 39 |
| Full control HTTP budget | 32; фактически 25 |
| Request / response limit | 4 KiB / 64 KiB |
| Target resources | 2 CPU, 768 MiB, 128 PID |
| Worker resources | 1 CPU, 128 MiB, 32 PID; read-only root, caps dropped |
| Private session store | 1 MiB tmpfs; отсутствует на host |
| Docker log bound | 10 MiB × 2 на контейнер |

B05 обязан учитывать identity/controls в своём расписании HTTP exchanges. Вызов
полного batch из 25 запросов нельзя объявлять бесплатным или незаметно помещать
в меньший R01 family budget. Расписание и при необходимости явно reviewed version
такого budget относятся к реализации B05. B04 не включает foreign basket probe,
изменение чужого объекта или новую security capability.

## Запуск и передача B05

Нужны project dependencies, Docker и уже установленные pinned target/worker images.
CLI не скачивает образы автоматически. Других инструментов на host не требуется.
Профиль `runtime.type=operator_access_fixture` предназначен для operator broker;
его подготовка не запускается через agent tools или `POST /runs`.

```powershell
python -m app.access_fixture_acceptance --output artifacts/b04/new-acceptance
```

По умолчанию источник — `artifacts/benchmark-target/juice-shop`, clean LF checkout
закреплённого commit. Можно явно указать operator `--repository`. Output обязан
быть новым и находиться вне target; старые попытки/ошибки не перезаписываются.
CLI запускает две независимые generations, проверяет controls, lost-session и
changed-identity, повторяемость baseline, запрет старого/закрытого handle и cleanup.

Для operator integration:

```python
with AccessFixtureLab(repository, fresh_output) as lab:
    context = lab.prepare()
    # Перед probe требуется свежий control, а не доверие старому status="ready".
    checked = lab.controls(context)
    if checked.status != "ready":
        # Остановить проверку как inconclusive.
        ...
    # B05: только зарегистрированная capability через Validator и Executor.
    # Никаких model credentials, прямого Docker exec или произвольных HTTP writes.
```

Результаты и raw observations опубликованы в
[acceptance-summary.json](evidence/b04/acceptance-summary.json) и
[полном архиве](evidence/b04/access-fixture-acceptance.zip). Lifecycle связывает
source/profile digests, generation, readiness attempts, public control facts и cleanup.
Архив содержит seals и фактические test logs; secret state в него не входит.

Проверки: 42 B04 tests passed; полная серия **986 passed, 21 skipped**;
Ruff и `python -m app.main` прошли. Skips — существующие Windows symlink/POSIX
ограничения и opt-in SberLab/Autodealer/Stage1/отсутствующий pinned Stage2 checkout;
точный список находится в pytest log архива. Для Ruff 0.16 сохранён узкий import-order
ignore только у hash-frozen legacy A06 file; его текст и SHA-256 не менялись.
