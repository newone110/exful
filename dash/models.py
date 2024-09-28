from django.db import models
from django.contrib.auth.models import User
import uuid

# Create your models here.
def generate_deposit_id():
    return f"BD-{uuid.uuid4().hex[:6].upper()}"


class OTPCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6, unique=True)

class NewTrader(models.Model):
       id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
       profile_image = models.ImageField(upload_to='images/')
       trader_name = models.CharField(max_length=255, default='New Trader')
       profit_share = models.CharField(max_length=255, default='20')
       category  = models.CharField(max_length=255, default='Crypto')
       wins = models.IntegerField(null=True)
       losses = models.IntegerField(null=True)
       copiers = models.IntegerField(default=45)
       copy_max = models.IntegerField(null=True)
       minimum_deposit = models.DecimalField(max_digits=10, decimal_places=2)
       bio = models.TextField()

class BotPlan(models.Model):
      id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id,editable=False)
      user = models.ForeignKey(User, on_delete=models.CASCADE, default=None)
      status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ]) 
      created_at = models.DateTimeField(auto_now_add=True)

class UserDatabase(models.Model):
    id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    trade_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    bot_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    btc_address = models.CharField(max_length=45, null=True, default=None)
    eth_address = models.CharField(max_length=45, null=True, default=None)
    usdt_address =  models.CharField(max_length=45, null=True, default=None)
    ltc_address = models.CharField(max_length=45, null=True, default=None)
    sol_address = models.CharField(max_length=45, null=True, default=None)
    trader = models.ForeignKey(NewTrader, on_delete=models.SET_DEFAULT, null=True, default=None)
    bot_plans  = models.CharField(max_length=10, null=True, default=None, choices=[
        ('bronze', 'Bronze'),
        ('silver', 'Silver'),
        ('enterprise', 'Enterprise'),
    ])

      
class BotTrade(models.Model):
    user = models.ForeignKey(UserDatabase, on_delete=models.CASCADE, null=True, default=None)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    asset = models.CharField(max_length=50, default=None)
      

class Trades(models.Model):
       trader_key = models.ForeignKey(NewTrader, on_delete=models.SET_DEFAULT, null=True, default=None)
       direction = models.CharField(max_length=50, default='NEUTRAL')
       amount = models.DecimalField(max_digits=10, decimal_places=2)
       asset = models.CharField(max_length=50, default='BTC/USDT')
       leverage = models.IntegerField(null=True)
       change =  models.DecimalField(max_digits=10, decimal_places=1, null=True)
       status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
       

class GeneralBtcDatabase(models.Model):
    btc_address = models.CharField(max_length=42, null=True)

class GeneralEthDatabase(models.Model):
    eth_address = models.CharField(max_length=42, null=True)

class GeneralUsdtDatabase(models.Model):
    usdt_address = models.CharField(max_length=42, null=True)

class GeneralLtcDatabase(models.Model):
    ltc_address = models.CharField(max_length=42, null=True)

class GeneralSolDatabase(models.Model):
    sol_address = models.CharField(max_length=42, null=True)

class BtcDeposit(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='BTC')
        btc_deposit = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class BtcPayout(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='BTC')
        btc_payout = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])


class EthDeposit(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='ETH')
        eth_deposit = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class EthPayout(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='ETH')
        eth_payout = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class UsdtDeposit(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='USDT')
        usdt_deposit = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class UsdtPayout(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='USDT')
        usdt_payout = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class LtcDeposit(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='LTC')
        ltc_deposit = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class LtcPayout(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='LTC')
        ltc_payout = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class SolDeposit(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='SOL')
        sol_deposit = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])
        
class SolPayout(models.Model):
        id = models.CharField(max_length=36, primary_key=True, default=generate_deposit_id, editable=False)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        method_of_crypto = models.CharField(max_length=20, default='SOL')
        sol_payout = models.FloatField()
        status = models.CharField(max_length=10, default='pending', choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ])


