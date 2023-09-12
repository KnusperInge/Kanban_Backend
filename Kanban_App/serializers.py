from rest_framework import serializers
from Kanban_App.models import ToDo, Subtask
from django.contrib.auth.models import User, Group
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ['id', 'name',]


class UserSeriallizer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name',
                  'last_name', 'email', 'groups']


class AuthorSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True,)

    class Meta:
        model = User
        fields = ['id', 'username', 'groups']


class SubtaskSerializer(serializers.ModelSerializer):
    task = serializers.RelatedField(source="ToDo", read_only=True)

    class Meta:
        model = Subtask
        fields = ['id', 'message', 'status', 'task']


class TodosSerializer(serializers.ModelSerializer):
    users = UserSeriallizer(many=True, read_only=True)
    author = AuthorSerializer(read_only=True)
    subtasks = SubtaskSerializer(read_only=True, many=True)

    class Meta:
        ordering = ['-id']
        model = ToDo
        fields = ['id', 'title', 'description', 'status', 'subtasks',
                  'created_at', 'author', 'users', ]

        extra_kwargs = {'users': {'required': True}}
        depth = 1


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, validators=[
                                   UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'password2',
                  'email', 'first_name', 'last_name']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn´t match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email']

        )

        user.set_password(validated_data['password'])
        user.save()
        return user


class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, )
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                {"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):

        instance.set_password(validated_data['password'])
        instance.save()

        return instance
