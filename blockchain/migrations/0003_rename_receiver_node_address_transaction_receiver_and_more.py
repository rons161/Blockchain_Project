# Generated by Django 4.2 on 2023-04-30 15:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blockchain', '0002_remove_transaction_receiver_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='transaction',
            old_name='receiver_node_address',
            new_name='receiver',
        ),
        migrations.RenameField(
            model_name='transaction',
            old_name='sender_node_address',
            new_name='sender',
        ),
    ]