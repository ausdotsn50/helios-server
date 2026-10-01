"""
The Helios datatypes are RDF datatypes that map to JSON-LD

A datatype object wraps another object and performs serialization / de-serialization
to and from that object. For example, a Helios election is treated as follows:

  helios_election = get_current_election() # returns a helios.models.Election object
  
  # dispatch to the right contructor via factory pattern
  # LDObject knows about base classes like Election, Voter, CastVote, Trustee
  # and it looks for the datatype field within the wrapped object to determine
  # which LDObject subclass to dispatch to.
  ld_object = LDObject.instantiate(helios_election)

  # get some JSON-LD
  ld_object.serialize()

And when data comes in:

  # the type is the base type, Election, CastVote, Trustee, ...
  # if this is raw JSON, then this invokes the legacy LDObject parser
  # if this is JSON-LD, then it finds the right LDObject based on the declared type
  # in the JSON-LD.
  # the optional type variable is necessary for legacy objects (otherwise, what is the type?)
  # but is not necessary for full JSON-LD objects.
  LDObject.deserialize(json_string, type=...)
"""
import importlib

from helios import utils
from helios.crypto import utils as cryptoutils

##
## utility function
##
def recursiveToDict(obj):
    if obj is None:
        return None

    if isinstance(obj, list):
        return [recursiveToDict(el) for el in obj]
    else:
        return obj.toDict()

##
## scheme dispatch
##
## Nine persisted LDObjectField type hints name an ElGamal-specific datatype at
## class-definition time (models.py:69, 71, 143, 956, 1142, 1290, 1297, 1301,
## 1308). Once a second cryptosystem exists those hints are ambiguous: a Paillier
## public key stored in Election.public_key would be handed to the ElGamal
## deserializer. The reach is wider than the keys -- encrypted_tally and every
## CastVote.vote resolve down to legacy/EGCiphertext, so ballots and tallies are
## affected too.
##
## Helios anticipated this. The FIXME sits on the exact line that must change:
## "the LD type is either in d or in type_hint / FIXME: get this from the
## dictionary itself".
##
## The dispatch below is deliberately NARROW. It applies only when the type hint
## is one of the six legacy datatypes that name an ElGamal representation, and
## only when the serialized dict's own field set identifies a different scheme.
## Everything else passes through untouched.
##

SCHEME_AMBIGUOUS_DATATYPES = frozenset({
    'legacy/EGPublicKey',
    'legacy/EGSecretKey',
    'legacy/EGCiphertext',
    'legacy/EGZKProof',
    'legacy/EGZKDisjunctiveProof',
    'legacy/DLogProof',
})


def _resolve_by_shape(d, ld_type):
    """
    Resolve an ambiguous legacy datatype against the shape of the data itself.

    Returns the datatype to use. Falls back to `ld_type` unchanged whenever the
    shape is not recognisably non-ElGamal, so an unknown shape keeps today's
    behaviour (and today's error message) rather than acquiring a new one.

    The discriminators are disjoint by construction, not by convention:
    ElGamal's public key carries 'y' and Paillier's does not; ElGamal's
    ciphertext is {alpha, beta} and Paillier's is {c}; ElGamal's proof
    commitment is a two-element dict {A, B} and Paillier's is a scalar, because
    Chaum-Pedersen commits to two values where Pi_root commits to one.
    """
    if ld_type not in SCHEME_AMBIGUOUS_DATATYPES:
        return ld_type

    if ld_type == 'legacy/EGZKDisjunctiveProof':
        # Serialized as a bare array. Dispatch on the first transcript.
        if isinstance(d, list) and d:
            inner = _resolve_by_shape(d[0], 'legacy/EGZKProof')
            if inner != 'legacy/EGZKProof':
                return 'paillier/ZKDisjunctiveProof'
        return ld_type

    if not isinstance(d, dict):
        return ld_type

    if ld_type == 'legacy/EGPublicKey':
        # A standard Paillier key is {n, g}, and a DJN §4.1 key adds
        # {h, hn, djn41_mode}. Neither carries 'y', so both route here.
        if 'y' not in d and 'n' in d:
            return 'paillier/PublicKey'

    elif ld_type == 'legacy/EGSecretKey':
        if 'x' not in d and {'p', 'q'} <= set(d):
            return 'paillier/SecretKey'

    elif ld_type == 'legacy/EGCiphertext':
        if 'alpha' not in d and 'c' in d:
            return 'paillier/Ciphertext'

    elif ld_type == 'legacy/EGZKProof':
        # A Pi_root commitment is a single value; a Chaum-Pedersen commitment is
        # {'A': ..., 'B': ...}.
        if 'commitment' in d and not isinstance(d['commitment'], dict):
            return 'paillier/ZKProof'

    # legacy/DLogProof is not dispatched: the Paillier arm generates no trustee
    # proof of knowledge of the secret key (build spec §4.4), so pok is stored
    # as null and never reaches a shape decision.

    return ld_type


def get_class(datatype):
    # already done?
    if not isinstance(datatype, str):
        return datatype

    # parse datatype string "v31/Election" --> from v31 import Election
    parsed_datatype = datatype.split("/")
    
    # get the module
    dynamic_module = importlib.import_module("helios.datatypes." + (".".join(parsed_datatype[:-1])))
    
    if not dynamic_module:
        raise Exception("no module for %s" % datatype)

    # go down the attributes to get to the class
    try:
        dynamic_ptr = dynamic_module
        for attr in parsed_datatype[-1:]:
            dynamic_ptr = getattr(dynamic_ptr, attr)
        dynamic_cls = dynamic_ptr
    except AttributeError:
        raise Exception ("no module for %s" % datatype)    

    dynamic_cls.datatype = datatype
        
    return dynamic_cls
        

class LDObjectContainer(object):
    """
    a simple container for an LD Object.
    """
    
    @property
    def ld_object(self):
        if not hasattr(self, '_ld_object'):
            self._ld_object = LDObject.instantiate(self)

        return self._ld_object

    def toJSONDict(self, complete=False):
        return self.ld_object.toJSONDict(complete=complete)

    def toJSON(self):
        return self.ld_object.serialize()

    @property
    def hash(self):
        return self.ld_object.hash

class LDObject(object):
    """
    A linked-data object wraps another object and serializes it according to a particular
    data format. For example, a legacy election LDObject instance will wrap an Election object
    and serialize its fields according to the specs for that version.

    To accomodate old JSON types, we allow  classes to do basically whatever they want,
    or to let this base class serialize pure JSON thingies, without the JSON-LD.
    """

    # whether or not to add JSON-LD things
    USE_JSON_LD = True

    # fields to serialize
    FIELDS = []

    # structured fields are other LD objects, not simple types
    STRUCTURED_FIELDS = {}

    # the underlying object type, which contains algorithms, to instantiate by default
    WRAPPED_OBJ_CLASS = None

    def __init__(self, wrapped_obj):
        self.wrapped_obj = wrapped_obj
        self.structured_fields = {}

    @classmethod
    def instantiate(cls, obj, datatype=None):
        """
        The FIXME this replaced asked: "should datatype override the object's
        internal datatype? probably not". The answer turns out to be "only
        sometimes", and the boundary matters.

        A blanket flip -- object's own datatype always wins -- is what the
        Paillier design documents prescribe, on the stated grounds that the
        wrapped crypto classes carry no `datatype` attribute. That is true of
        helios.crypto.elgamal.* and helios.crypto.algs.*, and false of two
        classes that reach this method:

          homomorphic.EncryptedVote.datatype -> 'legacy/EncryptedVote'
          homomorphic.Tally.datatype         -> 'legacy/Tally'
          models.CastVote.datatype           -> 'legacy/CastVote' (when saved)

        Under a blanket flip, legacy.EncryptedVote.includeRandomness() -- which
        asks for 'legacy/EncryptedVoteWithRandomness' -- would be overridden
        back to 'legacy/EncryptedVote' and silently drop the randomness a voter
        needs to audit their own ballot. legacy.CastVote.short would likewise
        serialize a full CastVote. Both are silent: the field lists are the same
        length and only the nested structured types differ.

        So the object's datatype wins only where the caller's hint is one of the
        six ElGamal-specific legacy datatypes, i.e. exactly where the hint is
        ambiguous under a second cryptosystem. Every other hint is honoured.
        """
        if isinstance(obj, LDObject):
            return obj

        obj_datatype = getattr(obj, 'datatype', None)

        if obj_datatype and (not datatype or datatype in SCHEME_AMBIGUOUS_DATATYPES):
            datatype = obj_datatype

        if not datatype:
            raise Exception("no datatype found")

        # nulls
        if obj is None:
            return None

        # the class
        dynamic_cls = get_class(datatype)

        # instantiate it and load data
        return_obj = dynamic_cls(obj)
        return_obj.loadData()

        return return_obj

    def _getattr_wrapped(self, attr):
        return getattr(self.wrapped_obj, attr)

    def _setattr_wrapped(self, attr, val):
        setattr(self.wrapped_obj, attr, val)

    def loadData(self):
        """
        load data using from the wrapped object
        """
        # go through the subfields and instantiate them too
        for subfield_name, subfield_type in self.STRUCTURED_FIELDS.items():
            self.structured_fields[subfield_name] = self.instantiate(self._getattr_wrapped(subfield_name), datatype = subfield_type)
        
    def loadDataFromDict(self, d):
        """
        load data from a dictionary
        """

        # the structured fields
        structured_fields = list(self.STRUCTURED_FIELDS.keys())

        # go through the fields and set them properly
        # on the newly instantiated object
        for f in self.FIELDS:
            if f in structured_fields:
                # a structured ld field, recur
                sub_ld_object = self.fromDict(d[f], type_hint = self.STRUCTURED_FIELDS[f])
                self.structured_fields[f] = sub_ld_object

                # set the field on the wrapped object too
                if sub_ld_object is not None:
                    self._setattr_wrapped(f, sub_ld_object.wrapped_obj)
                else:
                    self._setattr_wrapped(f, None)
            else:
                # a simple type
                new_val = self.process_value_in(f, d[f])
                self._setattr_wrapped(f, new_val)
        
    def serialize(self):
        d = self.toDict(complete = True)
        return utils.to_json(d)
    
    def toDict(self, alternate_fields=None, complete=False):
        val = {}

        fields = self.FIELDS

        if not self.structured_fields:
            if self.wrapped_obj.alias is not None:
                fields = self.ALIASED_VOTER_FIELDS

        for f in (alternate_fields or fields):
            # is it a structured subfield?
            if f in self.structured_fields:
                val[f] = recursiveToDict(self.structured_fields[f])
            else:
                val[f] = self.process_value_out(f, self._getattr_wrapped(f))

        if self.USE_JSON_LD:
            if complete:
                val['#'] = {'#vocab': 'http://heliosvoting.org/ns#'}

            if hasattr(self, 'datatype'):
                val['a'] = self.datatype

        return val

    toJSONDict = toDict

    @classmethod
    def fromDict(cls, d, type_hint=None):
        # null objects
        if d is None:
            return None

        # the LD type is either in d or in type_hint.
        # The FIXME that stood here -- "get this from the dictionary itself" --
        # is what _resolve_by_shape now does, for the six ambiguous legacy
        # datatypes only. Every other hint passes straight through.
        ld_type = _resolve_by_shape(d, type_hint)

        # get the LD class so we know what wrapped object to instantiate
        ld_cls = get_class(ld_type)

        wrapped_obj_cls = ld_cls.WRAPPED_OBJ_CLASS
        
        if not wrapped_obj_cls:
            raise Exception("cannot instantiate wrapped object for %s" % ld_type)

        wrapped_obj = wrapped_obj_cls()

        # then instantiate the LD object and load the data
        ld_obj = ld_cls(wrapped_obj)
        ld_obj.loadDataFromDict(d)

        return ld_obj

    fromJSONDict = fromDict

    @property
    def hash(self):
        s = self.serialize()
        return cryptoutils.hash_b64(s)
    
    def process_value_in(self, field_name, field_value):
        """
        process some fields on the way into the object
        """
        if field_value is None:
            return None
      
        val = self._process_value_in(field_name, field_value)
        if val is not None:
            return val
        else:
            return field_value
    
    def _process_value_in(self, field_name, field_value):
        return field_value

    def process_value_out(self, field_name, field_value):
        """
        process some fields on the way out of the object
        """
        if field_value is None:
            return None
      
        val = self._process_value_out(field_name, field_value)
        if val is not None:
            return val
        else:
            return field_value
  
    def _process_value_out(self, field_name, field_value):
        if isinstance(field_value, bytes):
            return field_value.decode('utf-8')
        return None

    def __eq__(self, other):
        if not hasattr(self, 'uuid'):
            return super(LDObject, self) == other
    
        return other is not None and self.uuid == other.uuid
  

class BaseArrayOfObjects(LDObject):
    """
    If one type has, as a subtype, an array of things, then this is the structured field used
    """
    ELEMENT_TYPE = None
    WRAPPED_OBJ_CLASS = list

    def __init__(self, wrapped_obj):
        super(BaseArrayOfObjects, self).__init__(wrapped_obj)
    
    def toDict(self, complete=False):
        return [item.toDict(complete=complete) for item in self.items]

    def loadData(self):
        "go through each item and LD instantiate it, as if it were a structured field"
        self.items = [self.instantiate(element, datatype= self.ELEMENT_TYPE) for element in self.wrapped_obj]

    def loadDataFromDict(self, d):
        "assumes that d is a list"
        # TODO: should we be using ELEMENT_TYPE_CLASS here instead of LDObject?
        self.items = [LDObject.fromDict(element, type_hint = self.ELEMENT_TYPE) for element in d]
        self.wrapped_obj = [item.wrapped_obj for item in self.items]
        

def arrayOf(element_type):
    """
    a wrapper for the construtor of the array
    returns the constructor
    """
    class ArrayOfTypedObjects(BaseArrayOfObjects):
        ELEMENT_TYPE = element_type

    return ArrayOfTypedObjects

class DictObject(object):
    "when the wrapped object is actually dictionary"
    def _getattr_wrapped(self, attr):
        return self.wrapped_obj[attr]

    def _setattr_wrapped(self, attr, val):
        self.wrapped_obj[attr] = val

class ListObject(object):
    def loadDataFromDict(self, d):
        self.wrapped_obj = d

    def toDict(self, complete=False):
        return self.wrapped_obj

