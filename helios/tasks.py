"""
Celery queued tasks for Helios

2010-08-01
ben@adida.net
"""
import copy
from celery import shared_task
from celery.utils.log import get_logger
from django.conf import settings
from django.urls import reverse
from urllib.parse import urlparse

from . import measure
from . import signals
from . import utils
from .models import CastVote, Election, Voter, VoterFile, EmailOptOut
from .view_utils import render_template_raw


@shared_task
def cast_vote_verify_and_store(cast_vote_id, status_update_message=None, **kwargs):
    cast_vote = CastVote.objects.get(id=cast_vote_id)
    # Proof verification, in the process that actually performs it: the
    # Celery worker, at cast time. One record per ballot.
    #
    # NOT cast_vote.vote.election: CastVote.vote is an EncryptedVote LDObject,
    # which carries election_uuid but gets .election only from init_election(),
    # never called on this path. Reading it raises, and because the expression
    # is evaluated in the argument list it escapes span's own guard and fails
    # the cast. Use the same path the code below already uses.
    with measure.span(cast_vote.voter.election.uuid, 'verification_time_ns',
                      cast_vote_id=cast_vote_id):
        result = cast_vote.verify_and_store()

    voter = cast_vote.voter
    election = voter.election
    user = voter.get_user()

    if result:
        # send the signal
        signals.vote_cast.send(sender=election, election=election, user=user, voter=voter, cast_vote=cast_vote)

        if status_update_message and user.can_update_status():
            user.update_status(status_update_message)
    else:
        logger = get_logger(cast_vote_verify_and_store.__name__)
        logger.error("Failed to verify and store %d" % cast_vote_id)


@shared_task
def voters_email(election_id, subject_template, body_template, extra_vars={},
                 voter_constraints_include=None, voter_constraints_exclude=None):
    """
    voter_constraints_include are conditions on including voters
    voter_constraints_exclude are conditions on excluding voters
    """
    election = Election.objects.get(id=election_id)

    # select the right list of voters
    voters = election.voter_set.all()
    if voter_constraints_include:
        voters = voters.filter(**voter_constraints_include)
    if voter_constraints_exclude:
        voters = voters.exclude(**voter_constraints_exclude)

    for voter in voters:
        single_voter_email.delay(voter.uuid, subject_template, body_template, extra_vars)


@shared_task
def voters_notify(election_id, notification_template, extra_vars={}):
    election = Election.objects.get(id=election_id)
    for voter in election.voter_set.all():
        single_voter_notify.delay(voter.uuid, notification_template, extra_vars)


@shared_task
def single_voter_email(voter_uuid, subject_template, body_template, extra_vars={}):
    voter = Voter.objects.get(uuid=voter_uuid)
    
    # Check if voter email is opted out
    voter_email = voter.voter_email or (voter.user and voter.user.user_id)
    if voter_email and EmailOptOut.is_opted_out(voter_email):
        logger = get_logger(single_voter_email.__name__)
        logger.info(f"Skipping email to opted-out voter {voter.uuid}")
        return

    the_vars = copy.copy(extra_vars)
    the_vars.update({'election': voter.election})
    the_vars.update({'voter': voter})
    
    # Add unsubscribe link to email context
    if voter_email:
        unsubscribe_code = utils.generate_email_confirmation_code(voter_email, 'optout')
        unsubscribe_path = reverse('optout_confirm', kwargs={'email': voter_email, 'code': unsubscribe_code})
        unsubscribe_url = f"{settings.URL_HOST}{unsubscribe_path}"
        
        the_vars.update({
            'unsubscribe_url': unsubscribe_url,
            'unsubscribe_code': unsubscribe_code
        })

    subject = render_template_raw(None, subject_template, the_vars)
    body = render_template_raw(None, body_template, the_vars)

    voter.send_message(subject, body)


@shared_task
def single_voter_notify(voter_uuid, notification_template, extra_vars={}):
    voter = Voter.objects.get(uuid=voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter': voter})

    notification = render_template_raw(None, notification_template, the_vars)

    voter.send_notification(notification)


@shared_task
def election_compute_tally(election_id):
    election = Election.objects.get(id=election_id)
    election.compute_tally()          # contains aggregation_time_ns

    election_notify_admin.delay(election_id=election_id,
                                subject="encrypted tally computed",
                                body="""
The encrypted tally for election %s has been computed.

--
Helios
""" % election.name)

    if election.has_helios_trustee():
        tally_helios_decrypt.delay(election_id=election.id)


@shared_task
def tally_helios_decrypt(election_id):
    election = Election.objects.get(id=election_id)
    election.helios_trustee_decrypt()  # contains decryption_factor_time_ns

    # Payload sizes, after the crypto so it is not in any span. Serialized the
    # way Helios stores them (LDObjectField.get_prep_value), so the size
    # matches what is on disk.
    if measure.enabled():
        from helios import datatypes
        _trustee = election.get_helios_trustee()
        # The type hints come from the Trustee fields themselves, because
        # LDObjectField.get_prep_value serializes with exactly those: the
        # measured size is then the stored size by construction, for any
        # scheme. A copied literal would only match by coincidence -- the
        # proofs hint 'legacy/EGZKProof' is scheme-ambiguous, and Paillier
        # proofs serialize as paillier/ZKProof only because datatypes honours
        # the object's own datatype for such hints.
        _f_type = _trustee._meta.get_field('decryption_factors').type_hint
        _p_type = _trustee._meta.get_field('decryption_proofs').type_hint
        _n_cells = sum(len(q) for q in election.encrypted_tally.tally)
        measure.record(
            election.uuid, 'decryption_factors_bytes',
            len(datatypes.LDObject.instantiate(
                _trustee.decryption_factors, datatype=_f_type).serialize()),
            unit='bytes', n_cells=_n_cells)
        measure.record(
            election.uuid, 'decryption_proofs_bytes',
            len(datatypes.LDObject.instantiate(
                _trustee.decryption_proofs, datatype=_p_type).serialize()),
            unit='bytes', n_cells=_n_cells)
    election_notify_admin.delay(election_id=election_id,
                                subject='Helios Decrypt',
                                body="""
Helios has decrypted its portion of the tally
for election %s.

--
Helios
""" % election.name)


@shared_task
def voter_file_process(voter_file_id):
    voter_file = VoterFile.objects.get(id=voter_file_id)
    voter_file.process()
    election_notify_admin.delay(election_id=voter_file.election.id,
                                subject='voter file processed',
                                body="""
Your voter file upload for election %s
has been processed.

%s voters have been created.

--
Helios
""" % (voter_file.election.name, voter_file.num_voters))


@shared_task
def notify_admin_opted_out_voters(election_id, opted_out_voters):
    election = Election.objects.get(id=election_id)
    
    if not opted_out_voters:
        return
    
    subject = f"Opted-out voters not added to election {election.name}"
    
    body = f"""
The following {len(opted_out_voters)} voters could not be added to election "{election.name}" 
because they have opted out of receiving Helios emails:

"""
    
    for voter in opted_out_voters:
        body += f"- {voter['name']} ({voter['email']}) [ID: {voter['voter_id']}, Type: {voter['voter_type']}]\n"
    
    optin_path = reverse('optin_form')
    optin_url = f"{settings.URL_HOST}{optin_path}"
    
    body += f"""

These voters will need to opt back in before they can be added to elections.
They can opt back in at: {optin_url}

--
Helios
"""
    
    election.admin.send_message(subject, body)


@shared_task
def election_notify_admin(election_id, subject, body):
    election = Election.objects.get(id=election_id)
    election.admin.send_message(subject, body)
