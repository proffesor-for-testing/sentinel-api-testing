import sys
import os
from logging.config import fileConfig
from dotenv import load_dotenv

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config/local.env')))


from sqlalchemy import engine_from_config
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
from sqlalchemy.schema import MetaData
from sentinel_backend.data_service.models import Base as DataServiceBase
from sentinel_backend.spec_service.models import Base as SpecServiceBase
from sentinel_backend.config.settings import get_database_settings

# Combine metadata from all services
target_metadata = MetaData()
for base in [DataServiceBase, SpecServiceBase]:
    for table in base.metadata.tables.values():
        table.to_metadata(target_metadata)

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    settings = get_database_settings()
    url = settings.url
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # see: https://alembic.sqlalchemy.org/en/latest/autogenerate.html#preventing-autogenerate-from-detecting-unchanged-tables
    def process_revision_directives(context, revision, directives):
        if config.cmd_opts.autogenerate and all(
            map(lambda x: x.upgrade_ops.is_empty(), directives)
        ):
            directives[:] = []

    db_settings = get_database_settings()
    connectable = engine_from_config(
        {"sqlalchemy.url": db_settings.url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    import asyncio
    
    async def run_async_migrations():
        db_settings = get_database_settings()
        connectable = create_async_engine(db_settings.url, poolclass=pool.NullPool)

        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)

    asyncio.run(run_async_migrations())


def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
