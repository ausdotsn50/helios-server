"""
Timing parity across the four measured arms: ElGamal, and Paillier with
djn41_mode 'off', 'short' and 'long'.

Each arm runs Helios's own server-side flow -- trustee key generation at
election creation, cast verification, tally, trustee decryption, combine --
with helios.measure switched ON and pointed at a temporary file, then checks
what was recorded.

The flow goes through the cast path (tasks.cast_vote_verify_and_store), so
verification_time_ns and verification_only_ns ARE part of every arm's expected
set, once per ballot. The Celery tasks run eagerly under the test runner
(settings.CELERY_TASK_ALWAYS_EAGER), so each task body runs in full, in
process, exactly as the worker would run it -- including the tally task's own
chaining of the trustee's decryption.
"""

import datetime
import json
import os
import tempfile
import uuid as uuid_mod
from unittest import mock

from django.test import TestCase

from helios import measure

QUESTIONS = [{
  'answers': ['A', 'B', 'C'], 'answer_urls': [None] * 3,
  'max': 2, 'min': 0, 'question': 'pick up to 2',
  'short_name': 'q1', 'tally_type': 'homomorphic',
  'result_type': 'absolute', 'choice_type': 'approval'}]

BALLOTS = [[0], [0, 1], [2], [0, 2], [1]]
EXPECTED_RESULT = [[3, 2, 2]]
N_CELLS = 3

# Master's metric set for an election driven through the cast path.
ELGAMAL_METRICS = {
  'keygen_time_ns', 'prove_sk_time_ns',
  'verification_time_ns', 'verification_only_ns',
  'aggregation_time_ns', 'aggregation_only_ns',
  'decryption_factor_time_ns', 'decryption_factor_only_ns',
  'decryption_factors_bytes', 'decryption_proofs_bytes',
  'dlog_precompute_time_ns', 'dlog_lookup_time_ns',
}

# Paillier, in every mode: no trustee proof of knowledge and no discrete-log
# stage, so those three metrics are ABSENT rather than zero, and
# decryption_time_ns times the same per-cell loop dlog_lookup_time_ns does.
PAILLIER_METRICS = (ELGAMAL_METRICS
                    - {'prove_sk_time_ns', 'dlog_precompute_time_ns',
                       'dlog_lookup_time_ns'}
                    | {'decryption_time_ns'})

PER_BALLOT = {'verification_time_ns', 'verification_only_ns'}

# The keys every record carries (helios.measure.record).
ROW_KEYS = {'election_uuid', 'metric', 'value', 'unit', 'pid', 'wall'}

# Each metric's extra keys, as master writes them. ElGamal's names, extras and
# span boundaries must stay exactly as on master, so that its numbers remain
# comparable with runs already taken there; pinning the extras here makes a
# drift fail loudly. Spans add instrumentation_ns; plain records do not.
EXTRAS = {
  'keygen_time_ns': {'context', 'instrumentation_ns'},
  'prove_sk_time_ns': {'context', 'instrumentation_ns'},
  'verification_time_ns': {'cast_vote_id', 'instrumentation_ns'},
  'verification_only_ns': {'cast_vote_id', 'instrumentation_ns'},
  'aggregation_time_ns': {'verify_p', 'includes', 'n_votes',
                          'instrumentation_ns'},
  'aggregation_only_ns': {'n_votes'},
  'decryption_factor_time_ns': {'instrumentation_ns'},
  'decryption_factor_only_ns': {'n_cells'},
  'decryption_factors_bytes': {'n_cells'},
  'decryption_proofs_bytes': {'n_cells'},
  'dlog_precompute_time_ns': {'num_tallied', 'instrumentation_ns'},
  'dlog_lookup_time_ns': {'n_cells', 'instrumentation_ns'},
  'decryption_time_ns': {'n_cells', 'includes', 'instrumentation_ns'},
}

ARMS = (('elgamal', None), ('paillier', 'off'), ('paillier', 'short'),
        ('paillier', 'long'))


class MeasureParityTests(TestCase):

  fixtures = ['users.json']

  def setUp(self):
    from helios_auth.models import User
    self.user = User.objects.get(user_id='ben@adida.net', user_type='google')

  # --- the flow ---------------------------------------------------------------

  def _run(self, scheme, mode):
    """Create, freeze, cast BALLOTS, tally, decrypt, combine. Returns the
    election, reloaded from the database."""
    from helios import tasks, views
    from helios.models import CastVote, Election, Voter
    from helios.workflows.homomorphic import EncryptedVote

    e = Election.objects.create(
      admin=self.user, uuid=str(uuid_mod.uuid4()),
      short_name='parity-%s' % uuid_mod.uuid4().hex[:12],
      name='parity', description='', election_type='election',
      crypto_scheme=scheme, cast_url='http://localhost/cast')
    if scheme == 'paillier':
      e.paillier_djn41_mode = mode

    # Small Paillier keys, as ElectionIntegrationTests uses them: 256-bit safe
    # primes in the DJN modes, and 512-bit strong primes -- getStrongPrime's
    # floor -- for 'off'. ElGamal's group is fixed, so its keys are already
    # cheap.
    key_size = 256 if mode in ('short', 'long') else 512
    with mock.patch.object(views.PAILLIER_PARAMS, 'key_size', key_size):
      e.generate_trustee(views.crypto_params_for(e))

    e.questions = QUESTIONS
    e.openreg = True
    e.save()
    e.freeze()

    for i, answer in enumerate(BALLOTS):
      voter = Voter.objects.create(
        election=e, uuid=str(uuid_mod.uuid4()), voter_login_id='v%d' % i,
        voter_name='Voter %d' % i, voter_email='v%d@example.com' % i)
      vote = EncryptedVote.fromElectionAndAnswers(e, [answer])
      cast_vote = CastVote(voter=voter, vote=vote, vote_hash=vote.hash,
                           cast_at=datetime.datetime.utcnow())
      cast_vote.save()
      tasks.cast_vote_verify_and_store.apply(args=[cast_vote.id], throw=True)

    # The tally task chains the trustee's decryption (tally_helios_decrypt,
    # which records the payload sizes) itself, as it does in production, so
    # it is not invoked a second time here.
    tasks.election_compute_tally.apply(args=[e.id], throw=True)

    e = Election.objects.get(id=e.id)
    e.combine_decryptions()
    return e

  def _run_measured(self, scheme, mode):
    """The flow with measurement ON. Returns (election, lines written)."""
    with tempfile.TemporaryDirectory() as tmp:
      path = os.path.join(tmp, 'measure.jsonl')
      with mock.patch.object(measure, '_ENABLED', True), \
           mock.patch.object(measure, '_PATH', path):
        e = self._run(scheme, mode)
      with open(path) as f:
        lines = [line for line in f.read().splitlines() if line.strip()]
    return e, lines

  # --- the checks -------------------------------------------------------------

  def _check_arm(self, scheme, mode):
    e, lines = self._run_measured(scheme, mode)

    # Record format: every line parses as JSON and carries this election.
    records = []
    for line in lines:
      row = json.loads(line)
      self.assertEqual(row.get('election_uuid'), e.uuid, row)
      records.append(row)

    # Exact metric set -- no dlog or prove_sk record for Paillier, not even a
    # zero -- and each exactly once, except once per ballot at cast time.
    expected = ELGAMAL_METRICS if scheme == 'elgamal' else PAILLIER_METRICS
    metrics = [r['metric'] for r in records]
    self.assertEqual(set(metrics), expected)
    for metric in expected:
      want = len(BALLOTS) if metric in PER_BALLOT else 1
      self.assertEqual(metrics.count(metric), want, metric)

    by = {r['metric']: r for r in records}

    # Each metric's extras, pinned to master's.
    for r in records:
      self.assertEqual(set(r) - ROW_KEYS, EXTRAS[r['metric']], r['metric'])
    self.assertEqual(by['decryption_factor_only_ns']['n_cells'], N_CELLS)
    if scheme == 'elgamal':
      self.assertEqual(by['dlog_precompute_time_ns']['num_tallied'],
                       len(BALLOTS))
      self.assertEqual(by['dlog_lookup_time_ns']['n_cells'], N_CELLS)
    else:
      self.assertEqual(by['decryption_time_ns']['n_cells'], N_CELLS)
      self.assertEqual(
        by['decryption_time_ns']['includes'],
        'per-cell combine of decryption factors + identity decode')

    # Master's monkeypatch reaches this scheme's decryption_factor: the
    # factors alone took time, and no more than factors plus proofs.
    only = by['decryption_factor_only_ns']['value']
    total = by['decryption_factor_time_ns']['value']
    self.assertTrue(0 < only <= total, (only, total))

    # Payload sizes are the stored sizes: the length of what the Trustee
    # fields actually serialize.
    trustee = e.get_helios_trustee()
    for metric, field_name in (('decryption_proofs_bytes', 'decryption_proofs'),
                               ('decryption_factors_bytes',
                                'decryption_factors')):
      field = trustee._meta.get_field(field_name)
      stored = field.get_prep_value(getattr(trustee, field_name))
      self.assertEqual(by[metric]['value'], len(stored), metric)
      self.assertEqual(by[metric]['unit'], 'bytes', metric)

    # ...in the scheme's own proof shape: a Pi_root commitment is a scalar, a
    # Chaum-Pedersen commitment is {A, B}.
    stored_proofs = json.loads(trustee._meta.get_field('decryption_proofs')
                               .get_prep_value(trustee.decryption_proofs))
    commitment = stored_proofs[0][0]['commitment']
    if scheme == 'paillier':
      self.assertIsInstance(commitment, str)
    else:
      self.assertEqual(set(commitment), {'A', 'B'})

    # The key is in the arm it claims.
    if scheme == 'paillier':
      self.assertEqual(e.public_key.djn41_mode, mode)

    # And the answer is right.
    self.assertEqual(e.result, EXPECTED_RESULT)

  def test_elgamal(self):
    self._check_arm('elgamal', None)

  def test_paillier_off(self):
    self._check_arm('paillier', 'off')

  def test_paillier_short(self):
    self._check_arm('paillier', 'short')

  def test_paillier_long(self):
    self._check_arm('paillier', 'long')

  def test_measurement_off_writes_nothing_and_changes_nothing(self):
    """
    With measurement off -- the production default -- nothing is written, not
    even to a path that is set, and every arm still decrypts to the same
    result.
    """
    for scheme, mode in ARMS:
      with self.subTest(scheme=scheme, mode=mode):
        with tempfile.TemporaryDirectory() as tmp:
          path = os.path.join(tmp, 'measure.jsonl')
          with mock.patch.object(measure, '_ENABLED', False), \
               mock.patch.object(measure, '_PATH', path):
            e = self._run(scheme, mode)
          self.assertFalse(os.path.exists(path), 'a record was written')
        self.assertEqual(e.result, EXPECTED_RESULT)
