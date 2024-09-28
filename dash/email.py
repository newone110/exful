import yagmail
from django.template.loader import get_template
from django.conf import settings


 
 

def send_welcome_email(user):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'Welcome to Exful!'
    #template = get_template('welcome.html')
    #context = {'user': user}
    #html_content = template.render(context)
    body = f'Thanks for signing up, {user.username}!'
    yag.send(user.email, subject, body)


def send_otp_email(user, otp):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'OTP for Exful Account'
    #template = get_template('otp-message.html')
    #context = {'user': user, 'otp': otp}
    #html_content = template.render(context)
    body = f'This is your OTP, {otp}!'
    yag.send(user.email, subject, body )

def send_funding_email(user, amount, crypto):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'Funding Successful!'
    #template = get_template('funding.html')
    #context = {'user': user, 'amount': amount, 'crypto': crypto}
    #html_content = template.render(context)
    body = f"Your fund of ${amount}  worth of {crypto} have been confirmed and deposited from your FinanceBee account {user.username}"
    yag.send(user.email, subject, body)
    

def send_withdrawal_email(user, amount, crypto):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'Withdrawal Successful!'
    #template = get_template('withdrawal.html')
    #context = {'user': user, 'amount': amount, 'crypto': crypto}
    #html_content = template.render(context)
    body = f"Your fund of ${amount}  worth of {crypto} have been confirmed and withdrawn from your FinanceBee account {user.username}"
    yag.send(user.email, subject, body)