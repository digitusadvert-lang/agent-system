import copy
import random
from types import SimpleNamespace


class _MRow:
    """Attribute-access wrapper for a masked/decoy customer row.
    Falls back to None for any attribute not explicitly set,
    so Jinja2 templates never raise AttributeError.
    """
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __getattr__(self, name):
        return None


# ── Decoy customer pool (realistic Malaysian fake data) ──────────────────────
# Used when panic mode is active. All records are entirely fictional.

_DECOY_POOL = [
    {
        'id': 9000001, 'name': 'Ahmad Bin Ismail',
        'contact_number': '0123847291', 'ic_number': '850312-14-5672',
        'address': 'No. 12, Jalan Wawasan 3/4, Puchong, 47100 Selangor',
        'email': 'ahmad.ismail85@gmail.com', 'data_source': 'IMPORT-2024',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
    {
        'id': 9000002, 'name': 'Tan Wei Liang',
        'contact_number': '0167234891', 'ic_number': '790624-08-2341',
        'address': 'Unit 5-2, Residensi Sri Ukay, Ampang, 68000 Kuala Lumpur',
        'email': 'tanweilian79@hotmail.com', 'data_source': 'IMPORT-2023',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
    {
        'id': 9000003, 'name': 'Rajesh A/L Subramaniam',
        'contact_number': '0112837465', 'ic_number': '921105-12-8834',
        'address': '34, Lorong Kenanga 7, Bandar Baru Bangi, 43650 Selangor',
        'email': 'rajesh.s92@yahoo.com', 'data_source': 'IMPORT-2024',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
    {
        'id': 9000004, 'name': 'Nurul Ain Binti Hassan',
        'contact_number': '0194523017', 'ic_number': '880915-04-1293',
        'address': 'No. 8, Jalan Mawar, Subang Jaya, 47500 Selangor',
        'email': 'nurulain88@gmail.com', 'data_source': 'IMPORT-2023',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
    {
        'id': 9000005, 'name': 'Lim Chee Keong',
        'contact_number': '0138927341', 'ic_number': '960203-10-7821',
        'address': 'Blok C-12-3, Vista Perdana, Kepong, 52100 Kuala Lumpur',
        'email': 'limck96@gmail.com', 'data_source': 'IMPORT-2024',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
    {
        'id': 9000006, 'name': 'Siti Norzahra Binti Razali',
        'contact_number': '0111928374', 'ic_number': '870720-06-3312',
        'address': 'No. 3, Jalan Kenari 5, Bandar Puchong Jaya, 47100 Selangor',
        'email': 'sitinorzahra87@gmail.com', 'data_source': 'IMPORT-2023',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
    {
        'id': 9000007, 'name': 'Chong Kok Wai',
        'contact_number': '0162738192', 'ic_number': '830416-07-5543',
        'address': '18-2, Jalan Kepong Baru, Kepong, 52100 Kuala Lumpur',
        'email': 'ckwai83@yahoo.com', 'data_source': 'IMPORT-2024',
        'additional_data': None, 'upload_id': None,
        'created_at': None, 'updated_at': None, 'upload': None,
    },
]


def generate_decoy_results(search_type, search_term):
    """Return 2–4 convincing fake customer records.

    The first record is seeded with the search term so the attacker
    sees a plausible 'hit' and doesn't suspect the swap.
    """
    pool = [copy.deepcopy(r) for r in _DECOY_POOL]
    random.shuffle(pool)
    count = random.randint(2, 4)
    results = pool[:count]

    # Seed first record to echo search term (makes decoy more believable)
    if results and search_term:
        first = results[0]
        st = search_type or ''
        if st == 'name':
            parts = search_term.title().split()
            first['name'] = ' '.join(parts) if len(parts) > 1 else parts[0] + ' Bin Abdullah'
        elif st in ('phone', 'contact'):
            first['contact_number'] = search_term.replace('-', '').replace(' ', '')
        elif st == 'ic':
            first['ic_number'] = search_term

    return (
        [_MRow(**r) for r in results],
        {'ok': True, 'message': f'Found {count} result(s)', 'limit': count, 'minimum': 3},
    )


# ────────────────────────────────────────────────────────────────────────────────


class DataProtection:
    """Server-side data masking + panic mode for agent-facing customer views.

    Data masking: enabled/disabled via SystemSettings 'data_protection_enabled'.
    Panic mode:   enabled/disabled via SystemSettings 'panic_mode_enabled'.
                  When active, ALL customer queries return decoy data — the real
                  DB is never touched. Admin users are also served decoy data in
                  panic mode (the threat is physical coercion, not role bypass).
    """

    _MASK_KEY  = 'data_protection_enabled'
    _PANIC_KEY = 'panic_mode_enabled'

    def __init__(self, app, SystemSettings):
        self.app = app
        self._S = SystemSettings
        self._field_masks = {
            'name':           self.mask_name,
            'Name':           self.mask_name,
            'contact_number': self.mask_phone,
            'Contact Number': self.mask_phone,
            'phone':          self.mask_phone,
            'phone_number':   self.mask_phone,
            'email':          self.mask_email,
            'Email':          self.mask_email,
            'ic_number':      self.mask_ic,
            'IC Number':      self.mask_ic,
            'address':        self.mask_address,
            'Address':        self.mask_address,
        }

    # ── data masking toggle ──────────────────────────────────────────────────────

    def enable(self):
        self._S.set(self._MASK_KEY, '1')

    def disable(self):
        self._S.set(self._MASK_KEY, '0')

    def status(self):
        return self._S.get(self._MASK_KEY, '0') == '1'

    def can_see_full_data(self, user):
        """Admin always True; agent True only when masking is OFF."""
        if user.role == 'admin':
            return True
        return not self.status()

    # ── panic mode ───────────────────────────────────────────────────────────────

    def is_panic(self):
        """Return True if panic mode is active."""
        return self._S.get(self._PANIC_KEY, '0') == '1'

    def activate_panic(self):
        self._S.set(self._PANIC_KEY, '1')

    def deactivate_panic(self):
        self._S.set(self._PANIC_KEY, '0')

    def panic_results(self, search_type, search_term):
        """Return decoy search results when panic mode is active."""
        return generate_decoy_results(search_type, search_term)

    # ── masking helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def mask_phone(v):
        """012-3456789  ->  XXXXXX789"""
        if not v:
            return v
        s = str(v)
        return 'XXXXXX' + s[-3:] if len(s) >= 3 else 'XXX'

    @staticmethod
    def mask_email(v):
        """john@example.com  ->  j***@example.com"""
        if not v:
            return v
        s = str(v)
        at = s.find('@')
        if at < 0:
            return '***'
        local, domain = s[:at], s[at:]
        return (local[0] + '***' if local else '***') + domain

    @staticmethod
    def mask_name(v):
        """John Smith  ->  J*** S****"""
        if not v:
            return v
        parts = str(v).split()
        return ' '.join(
            p[0] + '*' * (len(p) - 1) if len(p) > 1 else p
            for p in parts
        )

    @staticmethod
    def mask_ic(v):
        """123456-78-9012  ->  XXXXXX-XX-9012"""
        if not v:
            return v
        digits = str(v).replace('-', '')
        visible = digits[-4:] if len(digits) >= 4 else digits
        return f'XXXXXX-XX-{visible}'

    @staticmethod
    def mask_address(v):
        """123 Jalan Ampang  ->  [Address hidden — 17 chars]"""
        if not v:
            return v
        return f'[Address hidden — {len(str(v))} chars]'

    # ── row / list masking ───────────────────────────────────────────────────────

    def mask_row(self, row_dict, user):
        if self.can_see_full_data(user):
            return row_dict
        result = dict(row_dict)
        for field, fn in self._field_masks.items():
            if field in result and result[field]:
                result[field] = fn(result[field])
        return result

    def mask_customer_list(self, customers, user):
        """Mask a list of CustomerData ORM objects or dicts for display."""
        if self.can_see_full_data(user):
            return customers
        masked = []
        for c in customers:
            if isinstance(c, dict):
                masked.append(self.mask_row(c, user))
            else:
                row = {
                    'id':              getattr(c, 'id', None),
                    'name':            getattr(c, 'name', None),
                    'contact_number':  getattr(c, 'contact_number', None),
                    'ic_number':       getattr(c, 'ic_number', None),
                    'address':         getattr(c, 'address', None),
                    'email':           getattr(c, 'email', None),
                    'additional_data': getattr(c, 'additional_data', None),
                    'data_source':     getattr(c, 'data_source', None),
                    'upload_id':       getattr(c, 'upload_id', None),
                    'created_at':      getattr(c, 'created_at', None),
                    'updated_at':      getattr(c, 'updated_at', None),
                    'upload':          getattr(c, 'upload', None),
                }
                masked.append(_MRow(**self.mask_row(row, user)))
        return masked
