from .sql_query import *
from internal import model, interface

from pkg.trace_wrapper import traced_method


class AccountRepo(interface.IAuthorizationRepo):
    def __init__(self, tel: interface.ITelemetry, db: interface.IDB):
        self.db = db
        self.tracer = tel.tracer()

    @traced_method()
    async def create_account(self, account_id: int) -> None:
        args = {
            'account_id': account_id,
        }
        await self.db.insert(create_account, args)

    @traced_method()
    async def account_by_id(self, account_id: int) -> list[model.Account]:
        args = {'account_id': account_id}
        rows = await self.db.select(account_by_id, args)
        accounts = model.Account.serialize(rows) if rows else []

        return accounts

    @traced_method()
    async def account_by_refresh_token(self, refresh_token: str) -> list[model.Account]:
        args = {'refresh_token': refresh_token}
        rows = await self.db.select(account_by_refresh_token, args)
        accounts = model.Account.serialize(rows) if rows else []

        return accounts

    @traced_method()
    async def update_refresh_token(self, account_id: int, refresh_token: str) -> None:
        args = {
            'account_id': account_id,
            'refresh_token': refresh_token,
        }
        await self.db.update(update_refresh_token, args)
