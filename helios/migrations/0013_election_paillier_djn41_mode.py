# Generated manually: the DJN §4.1 setting becomes a three-way mode.
#
# paillier_use_djn41 (a boolean) is replaced by paillier_djn41_mode ('off',
# 'short' or 'long'). Existing elections keep what they meant: True could only
# ever select the short-exponent variant, so it maps to 'short', and False maps
# to 'off'.

from django.db import migrations, models


def boolean_to_mode(apps, schema_editor):
  # Historical models do not carry ElectionManager, which is not
  # use_in_migrations, so this plain default manager includes soft-deleted
  # elections too: every row is mapped.
  Election = apps.get_model('helios', 'Election')
  Election.objects.filter(paillier_use_djn41=True).update(
    paillier_djn41_mode='short')
  Election.objects.filter(paillier_use_djn41=False).update(
    paillier_djn41_mode='off')


def mode_to_boolean(apps, schema_editor):
  # 'long' has no boolean of its own; it maps to True, the DJN side, as
  # 'short' does.
  Election = apps.get_model('helios', 'Election')
  Election.objects.filter(paillier_djn41_mode='off').update(
    paillier_use_djn41=False)
  Election.objects.exclude(paillier_djn41_mode='off').update(
    paillier_use_djn41=True)


class Migration(migrations.Migration):

  dependencies = [
    ('helios', '0012_election_paillier_use_crt_proofs_and_more'),
  ]

  operations = [
    migrations.AddField(
      model_name='election',
      name='paillier_djn41_mode',
      field=models.CharField(choices=[('off', 'Off (standard Paillier)'), ('short', 'DJN §4.1, short exponent'), ('long', 'DJN §4.1, long exponent')], default='off', max_length=10),
    ),
    migrations.RunPython(boolean_to_mode, mode_to_boolean),
    migrations.RemoveField(
      model_name='election',
      name='paillier_use_djn41',
    ),
  ]
