pip install django sympy pandas matplotlib

python manage.py makemigrations
python manage.py migrate

python manage.py shell <<EOF
from django.contrib.auth.models import User
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', '', 'Cjkysirj')
    print("Пользователь создан.")
else:
    print("Пользователь уже существует.")
EOF

python manage.py runserver 0.0.0.0:8000