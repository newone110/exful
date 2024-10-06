import yagmail
from django.template.loader import get_template
from django.conf import settings
from django.template import Context
from premailer import transform

def send_welcome_email(user):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'Welcome to Exful!'
    template = get_template('welcome.html')
    context = {'user': user}
    html_content = template.render(context)
    inline_html = transform(html_content)
    yag.send(user.email, subject, inline_html)


def send_otp_email(user, otp):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'OTP for Exful account!'
    template = get_template('withdrawal.html')
    context = {'user': user, 'otp': otp}
    html_content = template.render(context)
    inline_html = transform(html_content)
    yag.send(user.email, subject, inline_html)

def send_funding_email(user, amount, crypto):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'Funding Successful for Exful account!'
    template = get_template('withdrawal.html')
    context = {'user': user, 'amount': amount, 'crypto': crypto}
    html_content = template.render(context)
    inline_html = transform(html_content)
    yag.send(user.email, subject, inline_html)
    

def send_withdrawal_email(user, amount, crypto):
    yag = yagmail.SMTP('wpetss01@gmail.com', 'ahadmfycskhubweu', host='smtp.gmail.com', port=465)
    subject = 'Withdrawal Successful for Exful account!'
    template = get_template('withdrawal.html')
    context = {'user': user, 'amount': amount, 'crypto': crypto}
    html_content = template.render(context)
    inline_html = transform(html_content)
    yag.send(user.email, subject, inline_html)