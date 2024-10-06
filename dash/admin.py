from django.contrib import admin
from .models import OTPCode, UserDatabase
from .models import GeneralBtcDatabase, GeneralEthDatabase,  GeneralLtcDatabase, GeneralUsdtDatabase, GeneralSolDatabase
from .models import BtcDeposit, EthDeposit, UsdtDeposit, LtcDeposit, SolDeposit
from. models import BtcPayout, EthPayout, UsdtPayout, LtcPayout, SolPayout, ExtendUser, UsdcPayout, LusdPayout, BankPayout
from .models import Contact, Trades, NewTrader
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin


# Register your models here.


admin.site.register(UserDatabase)

admin.site.register(ExtendUser)

admin.site.register(OTPCode)

admin.site.register(GeneralBtcDatabase)

admin.site.register(GeneralEthDatabase)

admin.site.register(GeneralUsdtDatabase)

admin.site.register(GeneralLtcDatabase)

admin.site.register(GeneralSolDatabase)

admin.site.register(BtcDeposit)

admin.site.register(EthDeposit)

admin.site.register(UsdtDeposit)

admin.site.register(LtcDeposit)

admin.site.register(SolDeposit)

admin.site.register(BtcPayout)

admin.site.register(EthPayout)

admin.site.register(UsdtPayout)

admin.site.register(LtcPayout)

admin.site.register(SolPayout)

admin.site.register(UsdcPayout)

admin.site.register(LusdPayout)

admin.site.register(BankPayout)

admin.site.register(Contact)

admin.site.register(Trades)

admin.site.register(NewTrader)
