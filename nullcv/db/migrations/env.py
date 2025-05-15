# migrations/env.py
from nullcv.db.ledger import Base as LedgerBase
from nullcv.db import Tables  # ensure import side-effects register mappers
target_metadata = LedgerBase.metadata
