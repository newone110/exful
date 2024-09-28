from django import forms
from .models import NewTrader

class NewTraderForm(forms.ModelForm):
    class Meta:
        model = NewTrader
        fields = ('profile_image', 'trader_name', 'profit_share', 'category', 'wins', 'losses', 'copy_max', 'minimum_deposit', 'bio')


class TraderForm(forms.Form):
    trader_id = forms.CharField(widget=forms.HiddenInput())