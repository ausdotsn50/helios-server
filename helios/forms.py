"""
Forms for Helios
"""

from django import forms
from django.conf import settings

from .fields import DateTimeLocalField
from .models import Election


class ElectionForm(forms.Form):
  short_name = forms.SlugField(max_length=40, help_text='no spaces, will be part of the URL for your election, e.g. my-club-2010')
  name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'size':60}), help_text='the pretty name for your election, e.g. My Club 2010 Election')
  description = forms.CharField(max_length=4000, widget=forms.Textarea(attrs={'cols': 70, 'wrap': 'soft'}), required=False)
  election_type = forms.ChoiceField(label="type", choices = Election.ELECTION_TYPES)
  use_voter_aliases = forms.BooleanField(required=False, initial=False, help_text='If selected, voter identities will be replaced with aliases, e.g. "V12", in the ballot tracking center')
  #use_advanced_audit_features = forms.BooleanField(required=False, initial=True, help_text='disable this only if you want a simple election with reduced security but a simpler user interface')
  randomize_answer_order = forms.BooleanField(required=False, initial=False, help_text='enable this if you want the answers to questions to appear in random order for each voter')
  private_p = forms.BooleanField(required=False, initial=False, label="Private?", help_text='A private election is only visible to registered voters.')
  help_email = forms.CharField(required=False, initial="", label="Help Email Address", help_text='An email address voters should contact if they need help.')

  # Which cryptosystem to run this election under. Defaults to elgamal and is
  # not required, so an existing caller that omits the field -- including the
  # measurement harness before it was taught about schemes -- gets exactly the
  # behaviour it had before.
  crypto_scheme = forms.ChoiceField(
    required=False, initial='elgamal', label="Cryptosystem",
    choices=Election.CRYPTO_SCHEMES,
    help_text='Paillier is experimental and supports exactly one trustee.')

  # Optimization ablations (masterplan §6.3). Per-election so the workload can
  # vary them cell by cell without restarting anything, and so a stored
  # election records what it actually ran under.
  paillier_use_djn41 = forms.BooleanField(
    required=False, initial=False, label="Paillier: DJN §4.1 encryption",
    help_text='Short-exponent encryption. Faster ciphertexts, but assumes more '
              'than decisional composite residuosity.')

  paillier_use_crt_proofs = forms.BooleanField(
    required=False, initial=True, label="Paillier: CRT decryption proofs",
    help_text='Chinese Remainder Theorem acceleration of the decryption proof. '
              'No additional assumption; on by default.')

  def clean_crypto_scheme(self):
    # An empty submission means "unchanged", not "invalid".
    return self.cleaned_data.get('crypto_scheme') or 'elgamal'

  # --- ablation flags: parsed from the RAW post, not via CheckboxInput -----
  #
  # forms.BooleanField uses CheckboxInput, whose value_from_datadict maps only
  # the literal strings "true"/"false" and otherwise falls through to
  # bool(value). Since bool("0") is True, posting "0" to turn a flag OFF turns
  # it ON -- silently, and with the form reporting valid.
  #
  # That is exactly how a §4.1 ablation cell inherited the previous cell's
  # setting: the run stamped djn41=False on its records while the election was
  # created with djn41=True. The acceptance cross-check caught it, which is the
  # argument for having built that check.
  #
  # These read self.data directly so that "0", "false", "" and absence all mean
  # what a caller would expect, independent of widget behaviour.

  FALSEY = ('', '0', 'false', 'False', 'off', 'no')

  def _raw_flag(self, name, default):
    if name not in self.data:
      return default
    return self.data.get(name) not in self.FALSEY

  def clean_paillier_use_djn41(self):
    """Off unless explicitly requested — it widens the security assumption."""
    return self._raw_flag('paillier_use_djn41', False)

  def clean_paillier_use_crt_proofs(self):
    """
    On unless explicitly disabled.

    Defaults TRUE when absent, unlike a normal BooleanField: an unchecked
    checkbox submits nothing, and a caller that never heard of this field must
    not thereby disable an optimization that costs no extra assumption.
    """
    return self._raw_flag('paillier_use_crt_proofs', True)

  if settings.ALLOW_ELECTION_INFO_URL:
    election_info_url = forms.CharField(required=False, initial="", label="Election Info Download URL", help_text="the URL of a PDF document that contains extra election information, e.g. candidate bios and statements")
  
  # times
  voting_starts_at = DateTimeLocalField(help_text = 'UTC date and time when voting begins',
                                   required=False)
  voting_ends_at = DateTimeLocalField(help_text = 'UTC date and time when voting ends',
                                   required=False)

class ElectionTimeExtensionForm(forms.Form):
  voting_extended_until = DateTimeLocalField(help_text = 'UTC date and time voting extended to',
                                   required=False)
  
class EmailVotersForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=4000, widget=forms.Textarea)
  send_to = forms.ChoiceField(label="Send To", initial="all", choices= [('all', 'all voters'), ('voted', 'voters who have cast a ballot'), ('not-voted', 'voters who have not yet cast a ballot')])

class TallyNotificationEmailForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea, required=False)
  send_to = forms.ChoiceField(label="Send To", choices= [('all', 'all voters'), ('voted', 'only voters who cast a ballot'), ('none', 'no one -- are you sure about this?')])

class VoterPasswordForm(forms.Form):
  voter_id = forms.CharField(max_length=50, label="Voter ID")
  password = forms.CharField(widget=forms.PasswordInput(), max_length=100)

class VoterPasswordResendForm(forms.Form):
  voter_id = forms.CharField(max_length=50, label="Voter ID", help_text="Enter the voter ID you were assigned for this election")

