from django.shortcuts import get_object_or_404, redirect, render
from .models import User, OTPCode, UserDatabase
from .models import GeneralBtcDatabase, GeneralEthDatabase, GeneralLtcDatabase, GeneralUsdtDatabase, GeneralSolDatabase
from .models import BtcDeposit, EthDeposit, UsdtDeposit, LtcDeposit, SolDeposit
from .models import BtcPayout, EthPayout, UsdtPayout, LtcPayout, SolPayout, UsdcPayout, LusdPayout, BankPayout
from django.contrib.auth.models import User
from django.contrib import messages
from .models import Contact, ExtendUser
from .models import NewTrader, Trades
from .models import BotPlan, BotTrade
from .forms import NewTraderForm
from .forms import TraderForm
from .email import send_welcome_email, send_otp_email, send_funding_email, send_withdrawal_email
from django.contrib.auth import authenticate, login, logout
from exful.get_crypto import crypto_prices_view
from exful.news import get_news_data
from django.urls import reverse
from django.contrib.auth.decorators import login_required
import random
from decimal import Decimal

# Create your views here.

def get_crypto_news(request):
    access_key = "bcd90b01a2b2208e7deed259319a7de5"
    keywords = "cryptocurrency"
    language = "en"

    try:
        news_data = get_news_data(access_key, keywords, language)
    except Exception as e:
        news_data = []

    if news_data:
        first_news = news_data[0]
        second_news = news_data[1] if len(news_data) > 1 else None
    else:
        first_news = None
        second_news = None

    context = {
        'first_news': first_news,
        'second_news': second_news,
    }

    return context

def index(request):
    crypto_news_context = get_crypto_news(request)
    context = {
        **crypto_news_context,
    }
    if request.method == 'POST':
        email = request.POST.get('Email-2')
        phone = request.POST.get('Phone-Number-2')
        message = request.POST.get('Message-2')
        
        contact = Contact.objects.create(email=email, phone=phone, message=message)
        contact.save()

    return render(request, 'index.html', context)

def about(request):
    return render(request, 'about-us.html')

def signup(request):
    user = request.user
    if request.method == "POST":
        username = request.POST.get('username-3')
        email = request.POST.get('email-3')
        password = request.POST.get('password-3')
        firstname = request.POST.get('fname-3')
        lastname = request.POST.get('lname-3')
        country  = request.POST.get('country-3')
        currency = request.POST.get('currency-3')

        if User.objects.filter(username=username):
            messages.error(request, 'Username already exist')
            return redirect('/signup/')
        
        if User.objects.filter(email=email):
            messages.error(request, 'Email has been registered')
            return redirect('/signup/')  

        myuser = User.objects.create_user(username, email, password, first_name=password)
        myuser.save()
        extenduser =  ExtendUser.objects.create(user=myuser,  country=country, currency=currency, firstname= firstname, lastname = lastname, password = password)
        extenduser.save()
        user = User.objects.get(username=username)
        otp = str(random.randint(100000, 999999))
        otp_code_instance = OTPCode(user=user, otp_code=otp)
        otp_code_instance.save()
        request.session['otp_code'] = otp
        send_otp_email(user, otp)
        print(otp)
        request.session['user_id'] = user.id

        return redirect('/otp/')
    
    return render(request, 'signup.html')

def admin_required(view_func):
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_superuser:
            return redirect('/administrator/login/')  
        return view_func(request, *args, **kwargs)
    return wrapper

def otp_page(request):
    if request.method == "POST":
        otp_code = request.POST.get('OTP')
        if 'otp_code' in request.session and 'user_id' in request.session:
            if otp_code == request.session['otp_code']:
                user = User.objects.get(id=request.session['user_id'])
                user.is_active = True
                user.save()
                del request.session['otp_code']
                del request.session['user_id']
                messages.success(request, 'Account has been created successfully')
                send_welcome_email(user)
                return redirect('/signin/')
            else:
                messages.error(request, 'Invalid OTP')
                return redirect('/otp/')
        else:
            messages.error(request, 'Session has expired')
            return redirect('/signup/')
        
    return render(request, 'otp.html')

def signin(request) :

    if request.method == "POST" :
        username = request.POST.get('username-3')
        password = request.POST.get('password-3')
        
        user = authenticate(username=username ,password=password)

        if user is not None:
            login(request, user)
            return redirect(reverse('dashboard_url'))

        else:
            messages.error(request, "Invalid Credentials")
        
        
        
    return render(request, 'login.html')

def signout(request):
    logout(request)
    return redirect('/')

@login_required
def dashboard(request):
    user = request.user
    username = request.user.username
    user_database = UserDatabase.objects.filter(user=user).first()
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    currency = extenduser.currency
    crypto_prices = crypto_prices_view(currency)
    

    context = {
        'crypto_prices': crypto_prices,
        'username': username,
        'currency': currency_symbol
    }

    if user_database is not None:
        context['balance'] = user_database.balance

    return render(request, 'dashboard/home.html', context)

@login_required
def account_settings(request):
    data_input = ''
    users = request.user.username
    user = request.user
    # Check if the user has a UserDatabase instance
    extend = ExtendUser.objects.filter(user=user).first()
    user_database, created = UserDatabase.objects.get_or_create(user=user)

    if request.method == "POST":
        btc_address = request.POST.get('BTC-Address')
        eth_address = request.POST.get('ETH-Address')
        usdt_address = request.POST.get('USDT-Address')
        ltc_address = request.POST.get('LTC-Address')
        sol_address = request.POST.get('SOL-Address')
        usdc_address = request.POST.get('USDC-Address')
        lusd_address = request.POST.get('LUSD-Address')
        account_name = request.POST.get('Account-Name')
        account_number = request.POST.get('Account-Number')
        routing_number = request.POST.get('Routing-Number')
        bank_name = request.POST.get('Bank-Name')
        username = request.POST.get('Username')
        email = request.POST.get('Email')
        password = request.POST.get('Password')

        

        # Update the user's UserDatabase instance
        if btc_address:
            user_database.btc_address = btc_address
        if eth_address:
            user_database.eth_address = eth_address
        if usdt_address:
            user_database.usdt_address = usdt_address
        if ltc_address:
            user_database.ltc_address = ltc_address
        if sol_address:
            user_database.sol_address = sol_address
        if usdc_address:
            user_database.usdc_address = usdc_address
        if lusd_address:
            user_database.lusd_address = lusd_address
        if  account_name:
            user_database.account_name = account_name
        if account_number:
            user_database.account_number = account_number
        if routing_number:
            user_database.routing_number = routing_number
        if bank_name:
            user_database.bank_name = bank_name


        current_btc_address = user_database.btc_address
        current_eth_address = user_database.eth_address
        current_usdt_address = user_database.usdt_address
        current_ltc_address = user_database.ltc_address
        current_sol_address = user_database.sol_address
        current_usdc_address = user_database.usdc_address
        current_lusd_address = user_database.lusd_address
        current_account_name = user_database.account_name
        current_account_number = user_database.account_number
        current_routing_number = user_database.routing_number
        current_bank_name = user_database.bank_name

        # If a field is not filled in, use the current value from the database
        if not btc_address:
            user_database.btc_address = current_btc_address
        if not eth_address:
            user_database.eth_address = current_eth_address
        if not usdt_address:
            user_database.usdt_address = current_usdt_address
        if not ltc_address:
            user_database.ltc_address = current_ltc_address
        if not sol_address:
            user_database.sol_address = current_sol_address
        if not usdc_address:
            user_database.usdc_address = current_usdc_address
        if not lusd_address:
            user_database.lusd_address = current_lusd_address
        if not account_name:
            user_database.account_name = current_account_name
        if not account_number:
            user_database.account_number = current_account_number
        if not routing_number:
            user_database.routing_number = current_routing_number
        if not bank_name:
            user_database.bank_name = current_bank_name

        user_database.save()
        if created:
            messages.success(request, 'Account information created')
        else:
            messages.success(request, 'Account information Updated')

        # Update the user's username, email, and password
        if username:
            if User.objects.filter(username=username).exclude(id=user.id).exists():
                messages.error(request, 'Username already exists')
                return redirect('/accountsettings/')
            else:
                user.username = username
        if email:
            if User.objects.filter(email=email).exclude(id=user.id).exists():
                messages.error(request, 'Email already exists')
                return redirect('/accountsettings/')
            else:
                user.email = email

        # Update the user's password
        if password:
            user.set_password(password)

        user.save()

    user_database = UserDatabase.objects.filter(user=user).first()

    context = {
        'username': users,
        'btc_address': user_database.btc_address if user_database else '',
        'eth_address': user_database.eth_address if user_database else '',
        'usdt_address': user_database.usdt_address if user_database else '',
        'ltc_address': user_database.ltc_address if user_database else '',
        'sol_address': user_database.sol_address if user_database else '',
        'usdc_address': user_database.usdc_address if user_database else '',
        'lusd_address': user_database.lusd_address if user_database else '',
        'account_name': user_database.account_name if user_database else '',
        'account_number': user_database.account_number if user_database else '',
        'routing_number': user_database.routing_number if user_database else '',
        'bank_name': user_database.bank_name if user_database else '',
        'username' : user.username,
        'emails' : user.email,
        'extend': extend
    }

    
    return render(request, 'dashboard/account-settings.html', context)

@login_required
def wallet(request):
    username = request.user.username
    context = {
        'username': username,
    }
    return render(request, 'dashboard/wallet.html', context)


@login_required
def withdraw(request):
    users = request.user.username
    user = request.user
    user_database = UserDatabase.objects.filter(user=user).first()
    extenduser = ExtendUser.objects.get(user=user)
    currency = extenduser.currency
    if request.method == 'POST':
        btc_payout = request.POST.get('Btc-Payout-2')
        if btc_payout is not None and btc_payout != '':
            extenduser = ExtendUser.objects.get(user=user)
            currency = extenduser.currency
            crypto_prices = crypto_prices_view(currency)
            btc_price = next((price for price in crypto_prices if price["name"] == "Bitcoin"), None)
            btc_p =  float(btc_price['price'].replace(',', ''))
            btc_amount = float(btc_payout) * btc_p
            if user_database.balance is not None and btc_amount <= user_database.balance:
                btc_payout = float(btc_payout)
                btc_payo = BtcPayout.objects.filter(user=user).first()
                result = BtcPayout(
                    user=user,
                    btc_payout=btc_amount
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass

        eth_payout = request.POST.get('Eth-Payout-2')
        if eth_payout is not None and eth_payout != '':
            extenduser = ExtendUser.objects.get(user=user)
            currency = extenduser.currency
            crypto_prices = crypto_prices_view(currency)
            btc_price = next((price for price in crypto_prices if price["name"] == "Ethereum"), None)
            btc_p =  float(btc_price['price'].replace(',', ''))
            eth_amount = float(eth_payout) * btc_p
            if user_database is not None and eth_amount <= user_database.balance:
                eth_payout = float(eth_payout)
                eth_payo = EthPayout.objects.filter(user=user).first()
                result = EthPayout(
                    user=user,
                    eth_payout=eth_amount
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass

        usdt_payout = request.POST.get('Usdt-Payout-2')
        if usdt_payout is not None and usdt_payout != '':
            if user_database is not None and float(usdt_payout) <= user_database.balance:
                usdt_payout = float(usdt_payout)
                usdt_payo = UsdtPayout.objects.filter(user=user).first()
                result = UsdtPayout(
                    user=user,
                    usdt_payout=usdt_payout
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass

        ltc_payout = request.POST.get('Ltc-Payout-2')
        if ltc_payout is not None and ltc_payout != '':
            extenduser = ExtendUser.objects.get(user=user)
            currency = extenduser.currency
            crypto_prices = crypto_prices_view(currency)
            btc_price = next((price for price in crypto_prices if price["name"] == "Litecoin"), None)
            btc_p =  float(btc_price['price'].replace(',', ''))
            ltc_amount = float(ltc_payout) * btc_p
            if user_database is not None and ltc_amount <= user_database.balance:
                ltc_payout = float(ltc_payout)
                ltc_payo = LtcPayout.objects.filter(user=user).first()
                result = LtcPayout(
                    user=user,
                    ltc_payout=ltc_amount
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass

        sol_payout = request.POST.get('Sol-Payout-2')
        if sol_payout is not None and sol_payout != '':
            extenduser = ExtendUser.objects.get(user=user)
            currency = extenduser.currency
            crypto_prices = crypto_prices_view(currency)
            btc_price = next((price for price in crypto_prices if price["name"] == "Solana"), None)
            btc_p =  float(btc_price['price'].replace(',', ''))
            sol_amount = float(sol_payout) * btc_p
            if user_database is not None and sol_amount <= user_database.balance:
                sol_payout = float(sol_payout)
                sol_payo = SolPayout.objects.filter(user=user).first()
                result = SolPayout(
                    user=user,
                    sol_payout=sol_amount
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')

        else:
            messages.error(request, 'You do not have enough balance')
        usdc_payout = request.POST.get('Usdc-Payout-2')
        if usdc_payout is not None and usdc_payout != '':
            if user_database is not None and float(usdc_payout) <= user_database.balance:
                usdc_payout = float(usdc_payout)
                usdc_payo = UsdcPayout.objects.filter(user=user).first()
                result = UsdcPayout(
                    user=user,
                    usdc_payout=usdc_payout
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass
        lusd_payout = request.POST.get('Lusd-Payout-2')
        if lusd_payout is not None and lusd_payout != '':
            if user_database is not None and float(usdt_payout) <= user_database.balance:
                lusd_payout = float(lusd_payout)
                lusd_payo = LusdPayout.objects.filter(user=user).first()
                result = LusdPayout(
                    user=user,
                    lusd_payout=lusd_payout
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass
        bank_payout = request.POST.get('Bank-with-amt-2')
        if bank_payout is not None and bank_payout != '':
            if user_database is not None and float(bank_payout) <= user_database.balance:
                bank_payout = float(bank_payout)
                bank_payo = BankPayout.objects.filter(user=user).first()
                result = BankPayout(
                    user=user,
                    bank_payout=bank_payout
                )
                result.save()
                messages.success(request, 'You will receive your payment soon')
            else:
                messages.error(request, 'You do not have enough balance')
        else:
            pass

    context = {
        'username': users,
        'btc_address': user_database.btc_address if user_database else '',
        'eth_address': user_database.eth_address if user_database else '',
        'usdt_address': user_database.usdt_address if user_database else '',
        'ltc_address': user_database.ltc_address if user_database else '',
        'sol_address': user_database.sol_address if user_database else '',
        'usdc_address': user_database.usdc_address if user_database else '',
        'lusd_address': user_database.lusd_address if user_database else '',
        'account_name': user_database.account_name if user_database else '',
        'account_number': user_database.account_number if user_database else '',
        'routing_number': user_database.routing_number if user_database else '',
        'bank_name': user_database.bank_name if user_database else '',
        'username' : user.username,
        'emails' : user.email
    }
    return  render(request, 'dashboard/withdraw.html', context)

@login_required
def market(request):
    user = request.user
    users = request.user.username
    extenduser = ExtendUser.objects.get(user=user)
    currency = extenduser.currency
    currency_symbol = extenduser.get_currency_symbol()
    crypto_prices = crypto_prices_view(currency)
    access_key = "bcd90b01a2b2208e7deed259319a7de5"
    keywords = "cryptocurrency"
    language = "en"

    try:
        news_data = get_news_data(access_key, keywords, language)
    except Exception as e:
        news_data = []

    if news_data:
        first_news = news_data[0]
    else:
        first_news = None
    print(first_news)

    context = {
        'user': users,
        'first_news': first_news,
        "crypto_prices": crypto_prices,
        "currency": currency_symbol
    }

    return render(request, 'dashboard/market-overview.html', context)

@login_required
def crypto(request) :
    user = request.user
    
    extenduser = ExtendUser.objects.get(user=user)
    currency = extenduser.currency 
    currency_symbol = extenduser.get_currency_symbol()
    crypto_prices = crypto_prices_view(currency)
    context = {
        "crypto_prices": crypto_prices,
        "currency": currency_symbol
    }    
    return render(request, 'dashboard/crypto.html', context)

@login_required
def news(request):
    user = request.user.username
    
    access_key = "bcd90b01a2b2208e7deed259319a7de5"
    keywords = "cryptocurrency"
    language = "en"

    news_data = get_news_data(access_key, keywords, language)
    request.session['news_data'] = news_data
    first_news = news_data[0] if news_data else None
    context = {
        'news_data': news_data, 
        'first_news': first_news,
        'username': user
        }
    return render(request, 'dashboard/news.html', context )



def news_detail(request, news_id):
    news_data = request.session.get('news_data')
    if news_data:
        news_article = next((article for article in news_data if article['news_id'] == news_id), None)
        if news_article:
            return render(request, 'dashboard/blog.html', {'news_article': news_article})
    return render(request, '404.html', status=404)

@admin_required
def administrator_settings(request):
    if request.method == "POST":
        if 'email-form-1' in request.POST:
            btc_address = request.POST.get('BTC-Address')

            # Get or create the instance of GeneralBtcDatabase
            btc_database, created = GeneralBtcDatabase.objects.get_or_create(
                defaults={
                    'btc_address': btc_address,
                }
            )
            if not created:
                # Update the instance
                btc_database.btc_address = btc_address
                btc_database.save()

        elif 'email-form-2' in request.POST:
            eth_address = request.POST.get('ETH-Address')

            # Get or create the instance of GeneralEthDatabase
            eth_database, created = GeneralEthDatabase.objects.get_or_create(
                defaults={
                    'eth_address': eth_address,
                }
            )
            if not created:
                # Update the instance
                eth_database.eth_address = eth_address
                eth_database.save()

        elif 'email-form-3' in request.POST:
            usdt_address = request.POST.get('USDT-Address')

            # Get or create the instance of GeneralUsdtDatabase
            usdt_database, created = GeneralUsdtDatabase.objects.get_or_create(
                defaults={
                    'usdt_address': usdt_address,
                }
            )
            if not created:
                usdt_database.usdt_address = usdt_address
                usdt_database.save()

        elif 'email-form-4' in request.POST:
            ltc_address = request.POST.get('LTC-Address')

            # Get or create the instance of GeneralLtcDatabase
            ltc_database, created = GeneralLtcDatabase.objects.get_or_create(
                defaults={
                    'ltc_address': ltc_address,
                }
            )
            if not created:
                ltc_database.ltc_address = ltc_address
                ltc_database.save()

        elif 'email-form-5' in request.POST:
            sol_address = request.POST.get('SOL-Address')

            # Get or create the instance of GeneralLtcDatabase
            sol_database, created = GeneralSolDatabase.objects.get_or_create(
                defaults={
                    'sol_address': sol_address,
                }
            )
            if not created:
                sol_database.sol_address = sol_address
                sol_database.save()

    btc_database = GeneralBtcDatabase.objects.first()
    eth_database = GeneralEthDatabase.objects.first()
    usdt_database = GeneralUsdtDatabase.objects.first()
    ltc_database = GeneralLtcDatabase.objects.first()
    sol_database = GeneralSolDatabase.objects.first()
    

    if btc_database or eth_database or usdt_database or ltc_database or sol_database:
        context = {
            'btc_address': btc_database.btc_address if btc_database else '',
            'eth_address': eth_database.eth_address if eth_database else '',
            'usdt_address': usdt_database.usdt_address if usdt_database else '',
            'ltc_address': ltc_database.ltc_address if ltc_database else '',
            'sol_address': sol_database.sol_address if sol_database else '',
        }
    else:
        context = {'data_input': 'No user data found'}

    return render(request,'admin-dashmilliy/settings.html', context)

@login_required
def fund(request):
    user = request.user
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    user_database = UserDatabase.objects.filter(user=user).first()

    if request.method == 'POST':
        btc_deposit = request.POST.get('Btc-Amount-2')
    

        if btc_deposit is not None:
            btc_deposit = float(btc_deposit)
        
            btc_depo = BtcDeposit.objects.filter(user=user).first()
            result = BtcDeposit(
                user=user,
                btc_deposit=btc_deposit
            )
            result.save()
            messages.success(request, 'Account will be credited as soon as it is confirmed')
        
        eth_deposit = request.POST.get('Eth-Amount-2')
        

        if eth_deposit is not None:
            eth_deposit = float(eth_deposit)
        
            eth_depo = EthDeposit.objects.filter(user=user).first()
            result = EthDeposit(
                user=user,
                eth_deposit=eth_deposit
            )
            result.save()
            messages.success(request, 'Account will be credited as soon as it is confirmed')

        usdt_deposit = request.POST.get('Usdt-Amount-2')
        if usdt_deposit is not None:
            usdt_deposit = float(usdt_deposit)
        
            usdt_depo = UsdtDeposit.objects.filter(user=user).first()
            result = UsdtDeposit(
                user=user,
                usdt_deposit=usdt_deposit
            )
            result.save()
            messages.success(request, 'Account will be credited as soon as it is confirmed')

        ltc_deposit = request.POST.get('Ltc-Amount-2')
        if ltc_deposit is not None:
            ltc_deposit = float(ltc_deposit)
        
            ltc_depo = LtcDeposit.objects.filter(user=user).first()
            result = LtcDeposit(
                user=user,
                ltc_deposit=ltc_deposit
            )
            result.save()
            messages.success(request, 'Account will be credited as soon as it is confirmed')

        sol_deposit = request.POST.get('Sol-Amount-2')
        if sol_deposit is not None:
            sol_deposit = float(sol_deposit)
        
            sol_depo = SolDeposit.objects.filter(user=user).first()
            result = SolDeposit(
                user=user,
                sol_deposit=sol_deposit
            )
            result.save()
            messages.success(request, 'Account will be credited as soon as it is confirmed')

    btc_database = GeneralBtcDatabase.objects.first()
    eth_database = GeneralEthDatabase.objects.first()
    usdt_database = GeneralUsdtDatabase.objects.first()
    ltc_database = GeneralLtcDatabase.objects.first()
    sol_database = GeneralSolDatabase.objects.first()

    if btc_database or eth_database or usdt_database or ltc_database or sol_database:
        context = {
            'btc_address': btc_database.btc_address if btc_database else '',
            'eth_address': eth_database.eth_address if eth_database else '',
            'usdt_address': usdt_database.usdt_address if usdt_database else '',
            'ltc_address': ltc_database.ltc_address if ltc_database else '',
            'sol_address': sol_database.sol_address if sol_database else '',
            'currency': currency_symbol
        }
    else:
        context = {'data_input': 'No user data found'}

    return render(request, 'dashboard/fund.html', context)

@admin_required
def administrator_deposit(request):
    username = request.user.username
    btc_database = GeneralBtcDatabase.objects.first()
    eth_database = GeneralEthDatabase.objects.first()
    usdt_database = GeneralUsdtDatabase.objects.first()
    ltc_database = GeneralLtcDatabase.objects.first()
    sol_database = GeneralSolDatabase.objects.first()
    btc_deposits =  BtcDeposit.objects.filter(status='pending')
    users_deposits = {}
    for user in User.objects.all():
        users_deposits[user] = BtcDeposit.objects.filter(user=user, status='pending')
    
    eth_deposits = EthDeposit.objects.filter(status='pending')
    users_eth_deposits = {}
    for user in User.objects.all():
        users_eth_deposits[user] = EthDeposit.objects.filter(user=user, status='pending')

    usdt_deposits = UsdtDeposit.objects.filter(status='pending')
    users_usdt_deposits = {}
    for user in User.objects.all():
        users_usdt_deposits[user] = UsdtDeposit.objects.filter(user=user, status='pending')

    ltc_deposits = LtcDeposit.objects.filter(status='pending')
    users_ltc_deposits = {}
    for user in User.objects.all():
        users_ltc_deposits[user] = LtcDeposit.objects.filter(user=user, status='pending')

    sol_deposits = SolDeposit.objects.filter(status='pending')
    users_sol_deposits = {}
    for user in User.objects.all():
        users_sol_deposits[user] = SolDeposit.objects.filter(user=user, status='pending')
        
    if request.method == 'POST':
        deposit_id = request.POST.get('deposit_id')
        deposit_type = request.POST.get('deposit_type')
        action = request.POST.get('action')

        if action == 'confirm':
            if deposit_type == 'btc':
                extenduser = ExtendUser.objects.get(user=user)
                currency = extenduser.currency
                currency_symbol = extenduser.get_currency_symbol()
                crypto_prices = crypto_prices_view(currency)
                btc_price = next((price for price in crypto_prices if price["name"] == "Bitcoin"), None)
                if btc_price:
                    deposit = BtcDeposit.objects.get(id=deposit_id)
                    btc_p =  float(btc_price['price'].replace(',', ''))
                    result = deposit.btc_deposit *btc_p
                    deposit.status = 'approved'
                    deposit.save()
                    user_database = UserDatabase.objects.get(user=deposit.user)
                    user_database.balance = (user_database.balance) + Decimal(result)
                    crypto = 'BTC'
                    send_funding_email(user, result, crypto)
                    user_database.save()
            elif deposit_type == 'eth':
                deposit = EthDeposit.objects.get(id=deposit_id)
                deposit.status = 'approved'
                deposit.save()
                extenduser = ExtendUser.objects.get(user=user)
                currency = extenduser.currency
                currency_symbol = extenduser.get_currency_symbol()
                crypto_prices = crypto_prices_view(currency)
                btc_price = next((price for price in crypto_prices if price["name"] == "Ethereum"), None)
                if btc_price:
                    deposit = EthDeposit.objects.get(id=deposit_id)
                    btc_p =  float(btc_price['price'].replace(',', ''))
                    result = deposit.eth_deposit *btc_p
                    user_database = UserDatabase.objects.get(user=deposit.user)
                    user_database.balance = (user_database.balance) + Decimal(result)
                    crypto = 'ETH'
                    send_funding_email(user, result, crypto)
                    user_database.save()
            elif deposit_type == 'usdt':
                deposit = UsdtDeposit.objects.get(id=deposit_id)
                deposit.status = 'approved'
                deposit.save()
                user_database = UserDatabase.objects.get(user=deposit.user)
                user_database.balance = str(int(user_database.balance) + int(deposit.usdt_deposit))
                crypto = 'USDT'
                send_funding_email(user, deposit.usdt_deposit, crypto)
                user_database.save()
            elif deposit_type == 'ltc':
                deposit = LtcDeposit.objects.get(id=deposit_id)
                deposit.status = 'approved'
                deposit.save()
                extenduser = ExtendUser.objects.get(user=user)
                currency = extenduser.currency
                currency_symbol = extenduser.get_currency_symbol()
                crypto_prices = crypto_prices_view(currency)
                btc_price = next((price for price in crypto_prices if price["name"] == "Litecoin"), None)
                if btc_price:
                    deposit = LtcDeposit.objects.get(id=deposit_id)
                    btc_p =  float(btc_price['price'].replace(',', ''))
                    result = deposit.ltc_deposit *btc_p
                    user_database = UserDatabase.objects.get(user=deposit.user)
                    user_database.balance = (user_database.balance) + Decimal(result)
                    crypto = 'LTC'
                    send_funding_email(user, result, crypto)
                    user_database.save()

            elif deposit_type == 'sol':
                deposit = SolDeposit.objects.get(id=deposit_id)
                deposit.status = 'approved'
                deposit.save()
                extenduser = ExtendUser.objects.get(user=user)
                currency = extenduser.currency
                crypto_prices = crypto_prices_view(currency)
                btc_price = next((price for price in crypto_prices if price["name"] == "Solana"), None)
                if btc_price:
                    deposit = SolDeposit.objects.get(id=deposit_id)
                    btc_p =  float(btc_price['price'].replace(',', ''))
                    result = deposit.sol_deposit *btc_p
                    user_database = UserDatabase.objects.get(user=deposit.user)
                    user_database.balance = (user_database.balance) + Decimal(result)
                    crypto = 'SOL'
                    send_funding_email(user, result, crypto)
                    user_database.save()
            
        elif action == 'reject':

            if deposit_type == 'btc':
                deposit = BtcDeposit.objects.get(id=deposit_id)
                deposit.status = 'rejected'
                deposit.save()
            elif deposit_type == 'eth':
                deposit = EthDeposit.objects.get(id=deposit_id)
                deposit.status = 'rejected'
                deposit.save()
            elif deposit_type == 'usdt':
                deposit = UsdtDeposit.objects.get(id=deposit_id)
                deposit.status = 'rejected'
                deposit.save()
            elif deposit_type == 'ltc':
                deposit = LtcDeposit.objects.get(id=deposit_id)
                deposit.status = 'rejected'
                deposit.save()
            elif deposit_type == 'sol':
                deposit = SolDeposit.objects.get(id=deposit_id)
                deposit.status = 'rejected'
                deposit.save()

        return redirect('/administrator/deposit/')
    
    context = {}  # Define the context dictionary here

    if btc_database or eth_database or usdt_database or ltc_database or sol_database:
        context.update({
        #'account_name': user_database.account_name,
        'btc_deposits': btc_deposits,
        'eth_deposits': eth_deposits,
        'usdt_deposits': usdt_deposits,
        'ltc_deposits': ltc_deposits,
        'sol_deposits': sol_deposits,
        'btc_database': btc_database.btc_address,
        "eth_database": eth_database.eth_address,
        "usdt_database": usdt_database.usdt_address,
        "ltc_database": ltc_database.ltc_address,
        "sol_database": sol_database.sol_address,
        'users_deposits': users_deposits.items(),
        'users_eth_deposits': users_eth_deposits.items(),
        'users_usdt_deposits': users_usdt_deposits.items(),
        'users_ltc_deposits': users_ltc_deposits.items(),
        'users_sol_deposits': users_sol_deposits.items(),
        "username": username,
    })
    else:
        context.update({'data_input': 'No user data found'})

    return render(request, 'admin-dashmilliy/deposit-rqs.html', context)

@admin_required
def administrator_payout(request):

    context = {
    'payouts': [],
    'btc_payouts': [],
    'eth_payouts': [],
    'usdt_payouts': [],
    'ltc_payouts': [],
    'sol_payouts': [],
    'usdc_payouts': [],
    'lusd_payouts': [],
    'bank_payouts': []
}

    btc_payouts = BtcPayout.objects.filter(status='pending')
    eth_payouts = EthPayout.objects.filter(status='pending')
    usdt_payouts = UsdtPayout.objects.filter(status='pending')
    ltc_payouts = LtcPayout.objects.filter(status='pending')
    sol_payouts = SolPayout.objects.filter(status='pending')
    usdc_payouts = UsdcPayout.objects.filter(status='pending')
    lusd_payouts = LusdPayout.objects.filter(status='pending')
    bank_payouts = BankPayout.objects.filter(status='pending')


    for payout in btc_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'btc_payout': payout.btc_payout,
            'username': user.username,
            'btc_address':user_database.btc_address,
            'id': payout.id
        }
        context['btc_payouts'].append(payout_data)

    for payout in eth_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'eth_payout': payout.eth_payout,
            'username': user.username,
            'eth_address':user_database.eth_address,
            'id': payout.id 
        }
        context['eth_payouts'].append(payout_data)

    for payout in usdt_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'usdt_payout': payout.usdt_payout,
            'username': user.username,
            'usdt_address':user_database.usdt_address,
            'id': payout.id 
        }
        context['usdt_payouts'].append(payout_data)

    for payout in ltc_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'ltc_payout': payout.ltc_payout,
            'username': user.username,
            'ltc_address':user_database.ltc_address,
            'id': payout.id 
        }
        context['ltc_payouts'].append(payout_data)

    for payout in sol_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'sol_payout': payout.sol_payout,
            'username': user.username,
            'sol_address':user_database.sol_address,
            'id': payout.id 
        }
        context['sol_payouts'].append(payout_data)

    for payout in usdc_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'usdc_payout': payout.usdc_payout,
            'username': user.username,
            'usdc_address':user_database.usdc_address,
            'id': payout.id 
        }
        context['usdc_payouts'].append(payout_data)

    for payout in lusd_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'lusd_payout': payout.lusd_payout,
            'username': user.username,
            'lusd_address':user_database.lusd_address,
            'id': payout.id 
        }
        context['lusd_payouts'].append(payout_data)

    for payout in bank_payouts:
        user = payout.user
        user_database = UserDatabase.objects.get(user=user)
        payout_data = {
            'bank_payout': payout.bank_payout,
            'username': user.username,
            'bank_name':user_database.bank_name,
            'account_name': user_database.account_name,
            'account_number': user_database.account_number,
            'routing_number': user_database.routing_number,
            'id': payout.id 
        }
        context['bank_payouts'].append(payout_data)

    if request.method == 'POST':
        payout_id = request.POST.get('payout_id')
        deposit_type = request.POST.get('deposit_type')
        action = request.POST.get('action')

        payout_models = {
            'btc': BtcPayout,
            'eth': EthPayout,
            'usdt': UsdtPayout,
            'ltc': LtcPayout,
            'sol': SolPayout,
            'usdc': UsdcPayout,
            'lusd': LusdPayout,
            'bank': BankPayout,
        }

        if action == 'confirm':
            deposit = payout_models[deposit_type].objects.get(id=payout_id)
            deposit.status = 'approved'
            deposit.save()
            user_database = UserDatabase.objects.get(user=deposit.user)
            user_database.balance = str(int(user_database.balance) - int(getattr(deposit, f'{deposit_type}_payout')))
            crypto = deposit_type.upper()
            send_withdrawal_email(deposit.user, getattr(deposit, f'{deposit_type}_payout'), crypto)
            user_database.save()

        elif action == 'reject':
            deposit = payout_models[deposit_type].objects.get(id=payout_id)
            deposit.status = 'rejected'
            deposit.save()

        return redirect('/administrator/withdraw/')

    return render(request, 'admin-dashmilliy/payouts-rqs.html', context)

@admin_required
def administrator_traders(request):
    traders = NewTrader.objects.all()
    new_trader_count = NewTrader.objects.all().count()
    if request.method == 'POST':
        form = NewTraderForm(request.POST, request.FILES)
        if form.is_valid():
            trader = form.save(commit=False)
            trader.save()
            return redirect('/administrator/traders/') 
    else:
        form = NewTraderForm()
    return render(request,'admin-dashmilliy/traders.html',{'form': form, 'traders': traders, 'new_trader_count': new_trader_count})

@admin_required
def traders_manager(request, trader_id):
    trader = NewTrader.objects.get(id=trader_id)
    if request.method == 'POST':
        form = NewTraderForm(request.POST, request.FILES, instance=trader)
        if form.is_valid():
            form.save()
            url = reverse('traders_manager', args=[trader_id])
            return redirect(url) 
    else:
        form = NewTraderForm(instance=trader)
    return render(request, 'admin-dashmilliy/trader-manager.html', {'trader': trader})

def delete_trader(request, trader_id):
    trader = NewTrader.objects.get(id=trader_id)
    trader.delete()
    return redirect('/administrator/traders/')

@admin_required
def trades(request):
    traders = NewTrader.objects.all()
    context = {
        'traders': traders
    }
    if request.method == "POST":
        trader_id = request.POST.get('trader_id')
        direction = request.POST.get('Trade-2')
        amount = request.POST.get('Crypto-Amount-3')
        change = request.POST.get('Crypto-Amount-4')
        asset = request.POST.get('Asset')
        leverage = request.POST.get('Leverage-Size')
        trader = NewTrader.objects.get(id=trader_id)

        trade = Trades(
            trader_key=trader,
            direction=direction,
            change=change,
            amount=Decimal(amount),  # Convert to Decimal for DecimalField
            asset=asset,
            leverage=int(leverage) if leverage else None  # Convert to int for IntegerField
        )
        trade.save()
        return redirect('/administrator/trades/')


    return render(request, 'admin-dashmilliy/copy-trade.html', context)

@admin_required
def complete_trade(request):
    trades = Trades.objects.filter(status='pending')
    context = {
        'trades': trades,
    }
    if request.method == 'POST':
        trade_id = request.POST.get('trade_id')
        action = request.POST.get('action')
        if action == 'Complete':
            trade = Trades.objects.get(id=trade_id)
            trade.status = 'approved'
            trade.save()
            
            # Calculate the percentage change
            percentage_change = float(trade.change)
            
            # Get the user database objects for the trader
            user_databases = UserDatabase.objects.filter(trader=trade.trader_key)
            
            # Loop over the user database objects and update their balances
            for user_database in user_databases:
                # If the percentage change is negative, subtract it from the user's balance
                if percentage_change < 0:
                    user_database.trade_balance -= Decimal(str(abs(percentage_change / 100) * float(trade.amount)))
                # If the percentage change is positive, add it to the user's balance
                else:
                    user_database.trade_balance += Decimal(str((percentage_change / 100) * float(trade.amount)))
                
                user_database.save()
    
    return render(request, 'admin-dashmilliy/complete_trade.html', context)

@admin_required
def administrator_dashboard(request):
    traders = NewTrader.objects.all()
    btc_deposit_count = BtcDeposit.objects.filter(status='pending').count()
    eth_deposit_count = EthDeposit.objects.filter(status='pending').count()
    usdt_deposit_count = UsdtDeposit.objects.filter(status='pending').count()
    ltc_deposit_count = LtcDeposit.objects.filter(status='pending').count()
    sol_deposit_count = SolDeposit.objects.filter(status='pending').count()

    total_deposit_count = btc_deposit_count + eth_deposit_count + usdt_deposit_count + ltc_deposit_count + sol_deposit_count

    btc_payouts_count = BtcPayout.objects.filter(status='pending').count()
    eth_payouts_count = EthPayout.objects.filter(status='pending').count()
    usdt_payouts_count = UsdtPayout.objects.filter(status='pending').count()
    ltc_payouts_count = LtcPayout.objects.filter(status='pending').count()
    sol_payouts_count = SolPayout.objects.filter(status='pending').count()

    total_payouts_count = btc_payouts_count + eth_payouts_count + usdt_payouts_count + ltc_payouts_count + sol_payouts_count
    user_count = User.objects.count()
    total_trades = Trades.objects.count()

    context = {
        'total_payout' : total_payouts_count,
        'total_deposit': total_deposit_count,
        'total_trade' : total_trades,
        'user_count': user_count,
        'traders': traders
    }
    return render(request, 'admin-dashmilliy/dashboard-overview.html', context)

@login_required
def trade(request):
    user = request.user
    username = user.username
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    try:
        user_database = UserDatabase.objects.get(user=user)
    except UserDatabase.DoesNotExist:
        user_database = None

    if user_database:
        trader = user_database.trader
        user_trades = Trades.objects.filter(trader_key=trader)
    else:
        user_trades = None

    traders = NewTrader.objects.all()
    for trader in traders:
        trader.profile_url = reverse('trader_profile', args=[trader.id])

    context = {
        'traders': traders,
        'username': username,
        'currency': currency_symbol,
        'user_trades': user_trades,
    }

    if user_database is not None:
        context['trade_balance'] = user_database.trade_balance

    if user_database is not None:
        if user_database.trader is not None:
            context['trade_trader'] = user_database.trader
    else:
        pass

    return render(request, 'dashboard/trade.html', context)

@login_required
def trader_profile(request, trader_id):
    user = request.user
    user_database = UserDatabase.objects.filter(user=user).first()
    if request.method == 'POST': 
        trader = get_object_or_404(NewTrader, id=trader_id)
        if user_database.trade_balance > trader.minimum_deposit:
            user_database.trader = trader
            user_database.save()
            print(user_database.trader)
            messages.success(request, 'Copy Trade requested')
            return redirect(reverse('trader_profile', args=[trader_id]))
        else:
            messages.error(request, 'Insufficient balance to copy this trader')
            return redirect(reverse('trader_profile', args=[trader_id]))
        
    trader = get_object_or_404(NewTrader, id=trader_id)
    
    context = {
        'trader': trader,
        'bio': trader.bio,
        'profile_image': trader.profile_image,
        # add any other fields you want to display on the trader's profile page
    }

    if user_database.trader is not None:
        context['traded'] = 'active'

    return render(request, 'dashboard/trader-profile.html', context)

@login_required
def bot_plan(request):
    username = request.user.username
    user = request.user
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    context = {
        'username': username,
        'currency': currency_symbol
    }
    return render(request, 'dashboard/bot-plans.html', context)

@login_required
def bot_payment(request):
    user = request.user
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    if request.method == "POST":
        amount = Decimal(request.POST.get('Tronscan-2'))
        plan = request.POST.get('Plans')
        
        bot = UserDatabase.objects.get(user=user)
        bots = BotPlan.objects.filter(user=user).first()
        if bots:
            if bots.status != 'pending':

                # Check if user has enough balance for the plan
                if plan == 'Bronze Package':
                    if amount > 50 and amount < 500:
                        if bot.balance <= 50:
                            messages.error(request, 'Account is insufficient for Bronze Package.')
                            return redirect('/bot_payment/')
                        else:
                            bot.bot_balance += amount
                            bot.balance -= amount
                            bot.bot_plans = 'bronze'
                            bot.save()
                            # Create a new BotPlan object and save it to the database
                            bot_plan = BotPlan(user=user, status='pending')
                            bot_plan.save()
                            messages.success(request, 'Bot has been activated.')
                            return redirect('/bot_payment/')
                    else:
                        messages.error(request, "The amount you've entered is not eligible for this package.")
                        return redirect('/bot_payment/')

                elif plan == 'Silver Package':
                    if amount > 600 and amount < 2000:
                        if bot.balance <= 600 :
                            messages.error(request, 'Account is insufficient for Silver Package.')
                            return redirect('/bot_payment/')
                        else:
                            bot.bot_balance += amount
                            bot.balance -= amount
                            bot.bot_plans = 'silver'
                            bot.save()
                            # Create a new BotPlan object and save it to the database
                            bot_plan = BotPlan(user=user, status='pending')
                            bot_plan.save()
                            messages.success(request, 'Bot has been activated.')
                            return redirect('/bot_payment/')
                    else:
                        messages.error(request, "The amount you've entered is not eligible for this package.")
                        return redirect('/bot_payment/')
                    
                elif plan == 'Enterprise Package':
                    if amount > 2100 and amount < 10500:
                        if bot.balance <= 2100 :
                            messages.error(request, 'Account is insufficient for Enterprise Package.')
                            return redirect('/bot_payment/')
                        else: 
                            bot.bot_balance += amount
                            bot.balance -= amount
                            bot.bot_plans = 'enterprise'
                            bot.save()
                            # Create a new BotPlan object and save it to the database
                            bot_plan = BotPlan(user=user, status='pending')
                            bot_plan.save()
                            messages.success(request, 'Bot has been activated.')
                            return redirect('/bot_payment/')
                    else:
                        messages.error(request, "The amount you've entered is not eligible for this package.")
                        return redirect('/bot_payment/')
                else:
                    messages.error(request, "You are already engaged in a package")
                    return redirect('/bot_payment/')
        else:
            messages.error(request, "Set up your account settings")
            return redirect('/bot_payment/')
        # Check if user has enough balance to cover the amount
        if bot.balance < amount:
            messages.error(request, 'Account is insufficient to cover the amount.')
            return redirect('/bot_payment/')

        
    return render(request, 'dashboard/payment-step-1.html')

@login_required
def transfer(request):
    user = request.user
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    if request.method == "POST":
        amount = Decimal(request.POST.get('Transfer-Amount'))
        move_from = request.POST.get('Move-funds-1')
        move_to = request.POST.get('Move-funds-2')
        
        transfer = UserDatabase.objects.get(user=user)
        
        if move_from == 'Balance':
            if transfer.balance < amount:
                messages.error(request, 'Insufficient balance')
                return render(request, 'dashboard/balance-transfer.html')
            if move_to == 'Bot Balance':
                transfer.balance -= amount
                transfer.bot_balance += amount
                messages.success(request, 'Transfer Successful')
            elif move_to == 'Trading Balance':
                transfer.balance -= amount
                transfer.trade_balance += amount
                messages.success(request, 'Transfer Successful')
            elif move_to == 'Balance':
                messages.error(request, 'Cannot transfer to the same account')
                return render(request, 'dashboard/balance-transfer.html')
        elif move_from == 'Bot Balance':
            if transfer.bot_balance < amount:
                messages.error(request, 'Insufficient bot balance')
                return render(request, 'dashboard/balance-transfer.html')
            if move_to == 'Balance':
                transfer.bot_balance -= amount
                transfer.balance += amount
                messages.success(request, 'Transfer Successful')
            elif move_to == 'Trading Balance':
                transfer.bot_balance -= amount
                transfer.trade_balance += amount
                messages.success(request, 'Transfer Successful')
            elif move_to == 'Bot Balance':
                messages.error(request, 'Cannot transfer to the same account')
                return render(request, 'dashboard/balance-transfer.html')
        elif move_from == 'Trading Balance':
            if transfer.trade_balance < amount:
                messages.error(request, 'Insufficient trading balance')
                return render(request, 'dashboard/balance-transfer.html')
            if move_to == 'Balance':
                transfer.trade_balance -= amount
                transfer.balance += amount
                messages.success(request, 'Transfer Successful')
            elif move_to == 'Bot Balance':
                transfer.trade_balance -= amount
                transfer.bot_balance += amount
                messages.success(request, 'Transfer Successful')
            elif move_to == 'Trading Balance':
                messages.error(request, 'Cannot transfer to the same account')
                return render(request, 'dashboard/balance-transfer.html')
        
        transfer.save()
    
    return render(request, 'dashboard/balance-transfer.html')

@login_required
def bot_trades(request):

    if request.method == "POST":
        amount = request.POST.get('Crypto-Amount-3')
        asset = request.POST.get('Asset')
        package = request.POST.get('bot_id')
        
        users = UserDatabase.objects.filter(bot_plans=package)
        for user in users:
            user.bot_balance += Decimal(amount)
            user.save()
            
            # Create a new BotTrade object to record the transaction
            bot_trade = BotTrade(user=user, amount=Decimal(amount), asset=asset)
            bot_trade.save()

        return redirect('/administrator/bot-trade/')


    return render(request, 'admin-dashmilliy/bot-trade.html')

@login_required
def complete_bot(request):
    user = request.user
    
    bots = BotPlan.objects.filter(status='pending')
    context = {
        'bots': bots,
    }
    if request.method == 'POST':
        bot_id = request.POST.get('bot_id')
        action = request.POST.get('action')
        if action == 'Complete':
            bot = BotPlan.objects.get(id=bot_id)
            user = bot.user
            user_obj = UserDatabase.objects.get(user=user)
            user_obj.bot_plans = None
            user_obj.save()
            bot.status = 'approved'
            bot.save()
            
    return render(request, 'admin-dashmilliy/complete_bot.html', context)

@login_required
def current_plans(request):
    user = request.user
    extenduser = ExtendUser.objects.get(user=request.user)
    currency_symbol = extenduser.get_currency_symbol()
    context = {}
    
    user_obj = UserDatabase.objects.filter(user=user).first()
    if user_obj is not None:
        bot_trades = BotTrade.objects.filter(user=user_obj)
        
        context['bot_trades'] = bot_trades
        context['currency'] = currency_symbol
        
    if user_obj is not None:
        if user_obj.bot_balance:
            context['bot_balance'] = user_obj.bot_balance
            context['currency'] = currency_symbol
        else:
            context['bot_balance'] = 0.00
            context['currency'] = currency_symbol

        if user_obj.bot_plans:
            user_obj.bot_plans = user_obj.bot_plans.upper() 
            context['bot_plan'] = user_obj.bot_plans
        else:
            context['bot_plan'] = 'No Plan Yet'
    else:
        pass

    return render(request, 'dashboard/current-plans.html', context)

def administrator_signin(request):
    if request.method == "POST":
        username = request.POST.get('admin-email-2')
        password = request.POST.get('password-7')
        
        user = authenticate(username=username, password=password)
        if user is not None and user.is_superuser:
            login(request, user)
            return redirect('/administrator/dashboard/')
        else:
            messages.error(request, "Invalid Credentials or Access Denied. Only admin users can access this page.")

    return render(request, 'admin-dashmilliy/sign-in.html')

def forgot_pass(request):
    if request.method == "POST":
        email = request.POST.get('OTP-email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "This email is not associated with any account.")
            return redirect('/forgot-pass/')
        
        otp = str(random.randint(100000, 999999))
        otp_code_instance = OTPCode(user=user, otp_code=otp)
        otp_code_instance.save()
        request.session['otp_code'] = otp
        print(otp)
        request.session['user_id'] = user.id
        return redirect('/otp/')
    
    return render(request, 'forgot-pass.html')

def transaction_history(request):
    user = request.user
    extenduser = ExtendUser .objects.get(user=request.user)
    currency = extenduser.get_currency_symbol()
    currency_converter = extenduser.currency
    crypto_prices = crypto_prices_view(currency_converter)
    transactions = []

    crypto_mapping = {
        'Bitcoin': 'BTC',
        'Ethereum': 'ETH',
        'Solana': 'SOL',
        'Liquidity USD': 'LUSD',
        'USD Coin': 'USDC',
        'Tether': 'USDT',
        'Litecoin': 'LTC',
    }

    models = [
        {'model': BtcDeposit, 'method': 'BTC', 'field': 'btc_deposit', 'type': 'deposit'},
        {'model': BtcPayout, 'method': 'BTC', 'field': 'btc_payout', 'type': 'payout'},
        {'model': EthDeposit, 'method': 'ETH', 'field': 'eth_deposit', 'type': 'deposit'},
        {'model': EthPayout, 'method': 'ETH', 'field': 'eth_payout', 'type': 'payout'},
        {'model': UsdtDeposit, 'method': 'USDT', 'field': 'usdt_deposit', 'type': 'deposit'},
        {'model': UsdtPayout, 'method': 'USDT', 'field': 'usdt_payout', 'type': 'payout'},
        {'model': LtcDeposit, 'method': 'LTC', 'field': 'ltc_deposit', 'type': 'deposit'},
        {'model': LtcPayout, 'method': 'LTC', 'field': 'ltc_payout', 'type': 'payout'},
        {'model': SolDeposit, 'method': 'SOL', 'field': 'sol_deposit', 'type': 'deposit'},
        {'model': SolPayout, 'method': 'SOL', 'field': 'sol_payout', 'type': 'payout'},
        {'model': UsdcPayout, 'method': 'USDC', 'field': 'usdc_payout', 'type': 'payout'},
        {'model': LusdPayout, 'method': 'LUSD', 'field': 'lusd_payout', 'type': 'payout'},
        {'model': BankPayout, 'method': 'Bank', 'field': 'bank_payout', 'type': 'payout'},
    ]

    for model in models:
        for transaction in model['model'].objects.filter(user=user):
            amount = getattr(transaction, model['field'])
            converted_amount = amount
            if model['type'] == 'deposit':
                for price in crypto_prices:
                    if price["name"] in crypto_mapping and crypto_mapping[price["name"]] == model['method']:
                        converted_amount = amount * float(price["price"].replace(',', ''))
                        print(amount)
                        break
            transactions.append({
                'amount': round(converted_amount, 2),
                'status': transaction.status,
                'type': model['type'],
                'method': model['method'],
            })

    # Sort the transactions based on the status
    transactions.sort(key=lambda x: ['approved', 'rejected', 'pending'].index(x['status']))

    context = {
        'transactions': transactions,
        'currency': currency,
    }

    return render(request, 'dashboard/transaction-history.html', context)