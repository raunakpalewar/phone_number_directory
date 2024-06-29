from django.core.management.base import BaseCommand
from faker import Faker
from myapp.models import UserRegistration, Contact, SpamReport

class Command(BaseCommand):
    help = 'Populates the database with sample data'

    def handle(self, *args, **kwargs):
        fake = Faker()

        for _ in range(50):
            name = fake.name()
            phone_number = fake.phone_number()
            email = fake.email()

            UserRegistration.objects.create(
                name=name,
                phone_number=phone_number,
                email=email,
                is_active=True,  
                is_admin=False,
                is_verified=False,
                is_registered=False,
            )

        for _ in range(100):
            owner = UserRegistration.objects.order_by('?').first()
            name = fake.name()
            phone_number = fake.phone_number()

            Contact.objects.create(
                owner=owner,
                name=name,
                phone_number=phone_number,
            )

        for _ in range(20):
            reporter = UserRegistration.objects.order_by('?').first()
            phone_number = fake.phone_number()

            SpamReport.objects.create(
                reporter=reporter,
                phone_number=phone_number,
            )

        self.stdout.write(self.style.SUCCESS('Sample data populated successfully'))
