#!/usr/bin/python3
from app import db, app
from app.models import *
import unittest


class test_db(unittest.TestCase):
    def setUp(self):
        pass

    def test_Leader(self):
        # Create new leader
        leader = Leader(u'leader', u'pw123456', u'Leader')
        # Test Password
        self.assertTrue(leader.testPassword('pw123456'))
        # Test Change Password
        leader.setPassword('pw654321')
        self.assertTrue(leader.testPassword('pw654321'))

    def test_Group(self):
        leader = Leader(u'leader', u'pw123456', u'Leader')
        group1 = Group(leader, 'Group1')
        for i in range(5):
            signer = Signer(group1, 'group1-' + str(i), "Signer-" + str(i))
        signers = Signer.query.all()
        for signer in signers:
            self.assertTrue(signer.group_signed == group1)

    def test_Activity(self):
        leader = Leader(u'leader', u'pw123456', u'Leader')
        group1 = Group(leader, 'Group1')
        for i in range(5):
            signer = Signer(group1, 'group1-' + str(i), "Signer-" + str(i))
        signers = Signer.query.all()
        activity = Activity(group1, 'Activity-1', datetime.now(), datetime.now() + timedelta(hours=1), True, True, True,
                            True)
        self.assertTrue(activity.group == group1)

    def tearDown(self):
        leaders = Leader.query.all()
        for leader in leaders:
            db.session.delete(leader)
        signers = Signer.query.all()
        for signer in signers:
            db.session.delete(signer)
        groups = Group.query.all()
        for group in groups:
            db.session.delete(group)
        activities = Activity.query.all()
        for activity in activities:
            db.session.delete(activity)
        signs = Sign.query.all()
        for sign in signs:
            db.session.delete(sign)
        db.session.commit()


if __name__ == '__main__':
    unittest.main()
