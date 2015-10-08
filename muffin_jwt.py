from datetime import datetime, timedelta
import asyncio
import logging
import os

import jwt

from muffin.plugins import BasePlugin


__version__ = "0.0.0"
__project__ = "muffin-jwt"
__license__ = "MIT"


logger = logging.getLogger(__name__)


async def jwt_middleware_factory(app, handler):
    async def jwt_middleware(request):
        if 'Json-Web-Token' in request.headers:
            request.jwt = app.ps.jwt.decode(request.headers['Json-Web-Token'])
            if 'user' in request.jwt:
                logger.info("authenticated as user=%s", request.jwt['user'])
                await app.ps.jwt.load_user(request, request.jwt['user'])
        return await handler(request)
    return jwt_middleware


def default_user_loader(user):
    return user


class Plugin(BasePlugin):
    name = 'jwt'

    defaults = {
        'issuer': 'Muffin App',
        'secret': None,
        'exp_seconds': 604800,
    }

    _user_loader = default_user_loader

    def setup(self, app):
        super().setup(app)
        if self.cfg.secret is None:
            logger.warning("jwt_secret is None - using random")
            self.cfg.secret = os.urandom(32)

        @app.manage.command
        def decode(token):
            print(self.decode(token))

    def start(self, app):
        """Register jwt middleware."""
        app.middlewares.insert(0, jwt_middleware_factory)

    def user_loader(self, user_loader):
        self._user_loader = user_loader

    async def load_user(self, request, user):
        if self._user_loader is not None:
            user = self._user_loader(user)
            if asyncio.iscoroutine(user):
                request.user = await user
            else:
                request.user = user

    def encode(self, **kwargs):
        if 'iss' not in kwargs:
            kwargs['iss'] = self.cfg.issuer
        return jwt.encode(dict(
            exp=datetime.utcnow() + timedelta(
                seconds=self.cfg.exp_seconds),
            **kwargs
        ), self.cfg.secret)

    def decode(self, token, **kwargs):
        if 'issuer' not in kwargs:
            kwargs['issuer'] = self.cfg.issuer
        return jwt.decode(token, self.cfg.secret, **kwargs)
