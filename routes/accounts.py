"""Sign-in, sign-up, accounts, two-factor sign-in, sessions, the live feed's tickets and user management."""
import asyncio
import secrets
import time
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from accounts import AccountError, Locked, TwoFactorRequired
from fastapi import APIRouter
from api_core import (
    TICKET_SECONDS,
    admin_token,
    auth_required,
    bearer,
    hub,
    principal_for
)

router = APIRouter()


@router.get("/api/auth")
async def auth_status(request: Request):
    """What the sign-in page needs to know, answerable without signing in."""

    who = await asyncio.to_thread(principal_for, bearer(request))

    return {
        "required": await asyncio.to_thread(auth_required),
        "ok": who is not None,
        "user": who.name if who else None,
        "role": who.role if who else None,
        "methods": {
            "password": await asyncio.to_thread(hub.accounts.any_users),
            "token": bool(admin_token())
        },
        "signup": await asyncio.to_thread(hub.accounts.signup_state, bool(admin_token()))
    }


class Login(BaseModel):

    username: str
    password: str
    code: str | None = None


@router.post("/api/login")
async def login(credentials: Login, request: Request):

    client = request.client.host if request.client else "?"

    wait = hub.login_rate.blocked(client)

    if wait:
        return JSONResponse(
            {"detail": f"too many sign-in requests from this address; try again in {max(1, -(-wait // 60))} minute(s)"},
            status_code=429, headers={"Retry-After": str(wait)}
        )

    hub.login_rate.fail(client)

    try:
        token, user = await asyncio.to_thread(
            hub.accounts.login, credentials.username, credentials.password,
            client, credentials.code
        )
    except TwoFactorRequired:

        # only said after the password was right: it does not confirm that an account exists
        return JSONResponse(
            {"detail": "enter the code from your authenticator app", "two_factor": True}, status_code=401
        )
    except Locked as error:

        await asyncio.to_thread(
            hub.store.add_audit, "-", "login locked",
            f"{credentials.username} from {client}"
        )

        return JSONResponse(
            {"detail": str(error)}, status_code=429,
            headers={"Retry-After": str(error.retry_after)}
        )
    except AccountError as error:

        await asyncio.to_thread(
            hub.store.add_audit, "-", "login failed",
            f"{credentials.username} from {client}"
        )

        raise HTTPException(401, str(error))

    await asyncio.to_thread(hub.store.add_audit, user["username"], "login", client)

    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "expires_at": user["expires_at"]
    }


class AccountChange(BaseModel):

    current_password: str
    new_username: str | None = None
    new_password: str | None = None
    code: str | None = None


@router.get("/api/account")
async def my_account(request: Request):
    """The signed-in person's own details."""

    who = request.state.who

    if who.via != "session":
        return {"username": who.name, "role": who.role, "editable": False, "via": who.via}

    user = await asyncio.to_thread(hub.accounts.get, who.name)

    return {
        "username": user["username"], "role": user["role"], "editable": True, "via": who.via,
        "created_at": user["created_at"], "last_login": user["last_login"],
        "two_factor": bool(user["totp_enabled"])
    }


@router.patch("/api/account")
async def change_my_account(change: AccountChange, request: Request):
    """Change your own username and/or password. Needs the current password."""

    who = request.state.who

    if who.via != "session":
        raise HTTPException(
            400, "you are not signed in with a named account (open mode or the admin token)"
        )

    client = request.client.host if request.client else "?"

    # never record the passwords; say what changed
    request.state.audit = ", ".join(
        part for part in (
            f"username {who.name} -> {change.new_username}" if change.new_username else "",
            "password" if change.new_password else ""
        ) if part
    )

    try:
        token, user = await asyncio.to_thread(
            hub.accounts.change_own, who.name, change.current_password,
            change.new_username, change.new_password, client, change.code
        )
    except TwoFactorRequired:
        # a plain 400, not a 401: the person is signed in, they only need to type the code
        return JSONResponse(
            {"detail": "enter the code from your authenticator app to confirm", "two_factor": True},
            status_code=400
        )
    except Locked as error:
        return JSONResponse(
            {"detail": str(error)}, status_code=429, headers={"Retry-After": str(error.retry_after)}
        )
    except AccountError as error:
        raise HTTPException(400, str(error))

    return {"token": token, "username": user["username"], "role": user["role"]}


def named_account(request):
    """The signed-in person, who must have a named account (not open mode or the admin token)."""

    who = request.state.who

    if who.via != "session":
        raise HTTPException(
            400, "you are not signed in with a named account (open mode or the admin token)"
        )

    return who


class PasswordConfirm(BaseModel):

    current_password: str


class CodeConfirm(BaseModel):

    code: str


class DisableTwoFactor(BaseModel):

    current_password: str
    code: str


@router.get("/api/account/two-factor")
async def two_factor_status(request: Request):

    who = named_account(request)

    return await asyncio.to_thread(account_call, hub.accounts.two_factor_status, who.name)


@router.post("/api/account/two-factor/start")
async def two_factor_start(confirm: PasswordConfirm, request: Request):
    """Begin setting it up. The password is asked again, so a stolen session cannot lock the owner out."""

    who = named_account(request)

    client = request.client.host if request.client else "?"

    request.state.audit = "setup started"

    def start():

        # proves the password (with the usual lockout) and ends the proof session at once
        token, _ = hub.accounts.login(who.name, confirm.current_password, client)
        hub.accounts.logout(token)

        return hub.accounts.begin_two_factor(who.name)

    try:
        secret, uri = await asyncio.to_thread(start)
    except Locked as error:
        return JSONResponse(
            {"detail": str(error)}, status_code=429, headers={"Retry-After": str(error.retry_after)}
        )
    except TwoFactorRequired:
        raise HTTPException(400, "two-factor sign-in is already on")
    except AccountError as error:
        raise HTTPException(400, "the current password is wrong" if "password" in str(error) else str(error))

    return {"secret": secret, "uri": uri}


@router.post("/api/account/two-factor/confirm")
async def two_factor_confirm(confirm: CodeConfirm, request: Request):
    """Turn it on with a code from the new secret. The recovery codes are returned this one time."""

    who = named_account(request)

    request.state.audit = "turned on"

    codes = await asyncio.to_thread(account_call, hub.accounts.confirm_two_factor, who.name, confirm.code)

    return {"recovery_codes": codes}


@router.post("/api/account/two-factor/disable")
async def two_factor_disable(confirm: DisableTwoFactor, request: Request):
    """Turn it off: needs the password and a current code (or a recovery code)."""

    who = named_account(request)

    client = request.client.host if request.client else "?"

    request.state.audit = "turned off"

    def disable():

        token, _ = hub.accounts.login(who.name, confirm.current_password, client, confirm.code)
        hub.accounts.logout(token)

        hub.accounts.disable_two_factor(who.name)

    try:
        await asyncio.to_thread(disable)
    except TwoFactorRequired:
        raise HTTPException(400, "enter a code from your authenticator app")
    except Locked as error:
        return JSONResponse(
            {"detail": str(error)}, status_code=429, headers={"Retry-After": str(error.retry_after)}
        )
    except AccountError as error:
        raise HTTPException(400, str(error))

    return {"enabled": False, "recovery_left": 0}


@router.get("/api/account/sessions")
async def my_sessions(request: Request):

    who = named_account(request)

    return await asyncio.to_thread(hub.accounts.sessions, who.name, bearer(request))


@router.post("/api/account/sessions/sign-out-others")
async def sign_out_other_devices(request: Request):

    who = named_account(request)

    ended = await asyncio.to_thread(hub.accounts.sign_out_others, who.name, bearer(request))

    request.state.audit = f"{ended} other session(s) ended"

    return {"ended": ended}


@router.post("/api/ws-ticket")
async def ws_ticket(request: Request):
    """A ticket for opening the live feed once. The websocket cannot send a header, and a session
    token in the address would end up in logs and history; a ticket dies after one use or 30 seconds."""

    now = time.time()

    for old in [t for t, (_, expires) in hub.tickets.items() if expires < now]:
        del hub.tickets[old]

    ticket = secrets.token_urlsafe(24)

    hub.tickets[ticket] = (request.state.who, now + TICKET_SECONDS)

    return {"ticket": ticket, "valid_seconds": TICKET_SECONDS}


class Signup(BaseModel):

    username: str
    password: str


@router.post("/api/signup")
async def signup(person: Signup, request: Request):
    """Create an account yourself: the first one is the administrator, later ones need approval."""

    client = request.client.host if request.client else "?"

    try:
        name, role, pending = await asyncio.to_thread(
            hub.accounts.signup, person.username, person.password, client, bool(admin_token())
        )
    except Locked as error:
        return JSONResponse(
            {"detail": f"too many sign-ups from this address; try again in {max(1, error.retry_after // 60)} min"},
            status_code=429, headers={"Retry-After": str(error.retry_after)}
        )
    except AccountError as error:
        raise HTTPException(400, str(error))

    await asyncio.to_thread(
        hub.store.add_audit, name, "signup", f"{role}{' (pending approval)' if pending else ''} from {client}"
    )

    if pending:
        return {"username": name, "role": role, "pending": True}

    token, user = await asyncio.to_thread(hub.accounts.login, name, person.password, client)

    return {"username": name, "role": role, "pending": False, "token": token}


class SignupPolicy(BaseModel):

    mode: str


@router.get("/api/signup-policy")
async def get_signup_policy():

    return {"mode": await asyncio.to_thread(hub.accounts.signup_mode)}


@router.put("/api/signup-policy")
async def put_signup_policy(policy: SignupPolicy, request: Request):

    request.state.audit = policy.mode

    await asyncio.to_thread(account_call, hub.accounts.set_signup_mode, policy.mode)

    return {"mode": policy.mode}


@router.post("/api/logout")
async def logout(request: Request):

    await asyncio.to_thread(hub.accounts.logout, bearer(request))

    return {"ok": True}


class NewUser(BaseModel):

    username: str
    password: str
    role: str = "viewer"


class UserChange(BaseModel):

    role: str | None = None
    password: str | None = None
    disabled: bool | None = None
    reset_two_factor: bool | None = None


def account_call(function, *args):
    """Run an account change; mistakes become 400s."""

    try:
        return function(*args)
    except AccountError as error:
        raise HTTPException(400, str(error))


@router.get("/api/users")
async def list_users():

    return await asyncio.to_thread(hub.accounts.users)


@router.post("/api/users")
async def create_user(user: NewUser, request: Request):

    request.state.audit = f"{user.username} ({user.role})"

    name = await asyncio.to_thread(
        account_call, hub.accounts.create, user.username, user.password, user.role
    )

    return {"username": name, "role": user.role}


@router.patch("/api/users/{username}")
async def change_user(username: str, change: UserChange, request: Request):

    me = request.state.who

    request.state.audit = username + (
        f" role={change.role}" if change.role else ""
    ) + (" password reset" if change.password else "") + (
        " two-factor reset" if change.reset_two_factor else ""
    ) + (
        f" disabled={change.disabled}" if change.disabled is not None else ""
    )

    if change.disabled and username.lower() == me.name:
        raise HTTPException(409, "you cannot disable your own account")

    def apply():

        if change.role is not None:
            hub.accounts.set_role(username, change.role)

        if change.password is not None:
            hub.accounts.set_password(username, change.password)

        if change.disabled is not None:
            hub.accounts.set_disabled(username, change.disabled)

        if change.reset_two_factor:
            hub.accounts.disable_two_factor(username)

    await asyncio.to_thread(account_call, apply)

    return {"ok": True}


@router.delete("/api/users/{username}")
async def delete_user(username: str, request: Request):

    request.state.audit = username

    if username.lower() == request.state.who.name:
        raise HTTPException(409, "you cannot delete your own account")

    await asyncio.to_thread(account_call, hub.accounts.delete, username)

    return {"ok": True}
