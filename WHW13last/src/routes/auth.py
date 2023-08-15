from typing import List

from fastapi import APIRouter, HTTPException, Depends, status, Security, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.db import get_db
from src.schemas import AccountSchema, AccountResponseSchema, TokenModel
from src.repository import acc as repository_accs
from src.services.auth import auth_service
from src.services.email import send_email

router = APIRouter(prefix='/auth', tags=["auth"])
security = HTTPBearer()


@router.post("/signup", response_model=AccountResponseSchema, status_code=status.HTTP_201_CREATED)
async def signup(body: AccountSchema, background_tasks: BackgroundTasks, request: Request, db: AsyncSession = Depends(get_db)):
    exist_acc = await repository_accs.get_acc_by_email(body.email, db)
    if exist_acc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    body.password = auth_service.get_password_hash(body.password)
    new_acc = await repository_accs.create_acc(body, db)
    background_tasks.add_task(send_email, new_acc.email, new_acc.username, str(request.base_url))
    return new_acc


@router.post("/login", response_model=TokenModel)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    acc = await repository_accs.get_acc_by_email(body.username, db)
    if acc is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not acc.confirmed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not confirmed")
    if not auth_service.verify_password(body.password, acc.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    # Generate JWT
    access_token = await auth_service.create_access_token(data={"sub": acc.email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": acc.email})
    await repository_accs.update_token(acc, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get('/refresh_token', response_model=TokenModel)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security),
                        db: AsyncSession = Depends(get_db)):
    token = credentials.credentials
    email = await auth_service.decode_refresh_token(token)
    user = await repository_accs.get_acc_by_email(email, db)
    if user.refresh_token != token:
        await repository_accs.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await auth_service.create_access_token(data={"sub": email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": email})
    await repository_accs.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get('/{username}')
async def refresh_token(username: str, db: AsyncSession = Depends(get_db)):
    print("------------------------------")
    print(f"{username} відкрив наш email")
    print("------------------------------")
    return RedirectResponse("http://localhost:8000/static/check.png")


@router.get('/confirmed_email/{token}')
async def confirmed_email(token: str, db: AsyncSession = Depends(get_db)):
    email = await auth_service.get_email_from_token(token)
    user = await repository_accs.get_acc_by_email(email, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    await repository_accs.confirmed_email(email, db)
    return {"message": "Email confirmed"}