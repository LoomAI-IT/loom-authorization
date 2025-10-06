import jwt
from fastapi import Request
from fastapi.responses import JSONResponse

from internal import interface, common, model
from .model import *

from pkg.trace_wrapper import traced_method


class AuthorizationController(interface.IAuthorizationController):
    def __init__(
            self,
            tel: interface.ITelemetry,
            authorization_service: interface.IAuthorizationService,
            domain: str
    ):
        self.tracer = tel.tracer()
        self.logger = tel.logger()
        self.authorization_service = authorization_service
        self.domain = domain

    @traced_method()
    async def authorization(self, body: AuthorizationBody):
        account_id = body.account_id
        two_fa_status = body.two_fa_status
        role = body.role
        self.logger.info("Начало операции авторизации")
        jwt_token: model.JWTToken = await self.authorization_service.create_tokens(
            account_id,
            two_fa_status,
            role
        )

        self.logger.info("Завершение операции авторизации")
        return JSONResponse(
            status_code=200,
            content=AuthorizationResponse(
                access_token=jwt_token.access_token,
                refresh_token=jwt_token.refresh_token
            ).model_dump(),
        )

    @traced_method()
    async def authorization_tg(self, body: AuthorizationBody):
        account_id = body.account_id
        two_fa_status = body.two_fa_status
        role = body.role
        self.logger.info("Начало операции авторизации Telegram")
        jwt_token: model.JWTToken = await self.authorization_service.create_tokens_tg(
            account_id,
            two_fa_status,
            role
        )

        self.logger.info("Завершение операции авторизации Telegram")
        return JSONResponse(
            status_code=200,
            content=AuthorizationResponse(
                access_token=jwt_token.access_token,
                refresh_token=jwt_token.refresh_token
            ).model_dump(),
        )

    @traced_method()
    async def check_authorization(self, request: Request):
        try:
            self.logger.info("Начало операции проверки авторизации")
            access_token = request.cookies.get("Access-Token")
            token_payload = await self.authorization_service.check_token(
                access_token,
            )

            self.logger.info("Завершение операции проверки авторизации")
            return JSONResponse(
                status_code=200,
                content=CheckAuthorizationResponse(
                    account_id=token_payload.account_id,
                    two_fa_status=token_payload.two_fa_status,
                    role=token_payload.role,
                    message="Access-Token verified",
                    status_code=200
                ).model_dump(),
            )
        except jwt.ExpiredSignatureError as err:
            self.logger.warning("Токен истек")

            return JSONResponse(
                status_code=200,
                content=CheckAuthorizationResponse(
                    account_id=-1,
                    two_fa_status=False,
                    role="",
                    message="token expired",
                    status_code=403
                ).model_dump(),
            )
        except jwt.InvalidTokenError as err:
            self.logger.warning("Токен не валиден")

            return JSONResponse(
                status_code=200,
                content=CheckAuthorizationResponse(
                    account_id=-1,
                    two_fa_status=False,
                    role="",
                    message="token invalid",
                    status_code=403
                ).model_dump(),
            )

    @traced_method()
    async def refresh_token(self, request: Request):
        try:
            self.logger.info("Начало операции обновления токена")
            refresh_token = request.cookies.get("Refresh-Token")
            jwt_token = await self.authorization_service.refresh_token(
                refresh_token,
            )

            response = JSONResponse(status_code=200, content={"message": "ok"})
            response.set_cookie(
                key="Access-Token",
                value=jwt_token.access_token,
                httponly=True,
                secure=True,
                samesite="lax"
            )
            response.set_cookie(
                key="Refresh-Token",
                value=jwt_token.refresh_token,
                httponly=True,
                secure=True,
                samesite="lax"
            )

            self.logger.info("Завершение операции обновления токена")
            return response
        except common.ErrAccountNotFound as err:
            self.logger.warning("Не найден аккаунт")

            return JSONResponse(
                status_code=400,
                content={"message": "account not found"}
            )
        except jwt.ExpiredSignatureError as err:
            self.logger.warning("Токен истек")

            return JSONResponse(
                status_code=403,
                content={"message": "token expired"}
            )
        except jwt.InvalidTokenError as err:
            self.logger.warning("Токен не валиден")

            return JSONResponse(
                status_code=403,
                content={"message": "token invalid"}
            )

    @traced_method()
    async def refresh_token_tg(self, request: Request):
        try:
            self.logger.info("Начало операции обновления токена Telegram")
            refresh_token = request.cookies.get("Refresh-Token")
            jwt_token = await self.authorization_service.refresh_token_tg(
                refresh_token,
            )

            response = JSONResponse(status_code=200, content={"message": "ok"})
            response.set_cookie(
                key="Access-Token",
                value=jwt_token.access_token,
                httponly=True,
                secure=True,
                samesite="lax"
            )
            response.set_cookie(
                key="Refresh-Token",
                value=jwt_token.refresh_token,
                httponly=True,
                secure=True,
                samesite="lax"
            )

            self.logger.info("Завершение операции обновления токена Telegram")
            return response
        except common.ErrAccountNotFound as err:
            self.logger.warning("Не найден аккаунт")

            return JSONResponse(
                status_code=400,
                content={"message": "account not found"}
            )
        except jwt.ExpiredSignatureError as err:
            self.logger.warning("Токен истек")

            return JSONResponse(
                status_code=403,
                content={"message": "token expired"}
            )
        except jwt.InvalidTokenError as err:
            self.logger.warning("Токен не валиден")

            return JSONResponse(
                status_code=403,
                content={"message": "token invalid"}
            )
