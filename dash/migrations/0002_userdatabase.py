# Generated by Django 5.0.6 on 2024-09-23 00:04

import dash.models
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dash', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserDatabase',
            fields=[
                ('id', models.CharField(default=dash.models.generate_deposit_id, editable=False, max_length=36, primary_key=True, serialize=False)),
                ('balance', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('trade_balance', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('bot_balance', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('btc_address', models.CharField(max_length=42, null=True)),
                ('eth_address', models.CharField(max_length=42, null=True)),
                ('usdt_address', models.CharField(max_length=42, null=True)),
                ('ltc_address', models.CharField(max_length=42, null=True)),
                ('sol_address', models.CharField(max_length=42, null=True)),
                ('user', models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
