from django.shortcuts import render
from rest_framework import viewsets, generics
# from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from Kanban_App.models import ToDo, Subtask
from django.contrib.auth.models import User, Group
from Kanban_App.serializers import TodosSerializer, UserSeriallizer, ChangePasswordSerializer, RegisterSerializer, SubtaskSerializer

# ANCHOR - Change Password


class ChangePasswordView(generics.UpdateAPIView):

    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = ChangePasswordSerializer

# ANCHOR - Register new Users


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


# ANCHOR - Get users and Change Usersdata

class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):

        group = Group.objects.filter(user__id=request.user.pk).first()

        if group.name == 'leader':
            queryset = User.objects.all()
            serializer = UserSeriallizer(queryset, many=True)
        else:
            queryset = User.objects.filter(pk=request.user.pk)
            serializer = UserSeriallizer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):

        data = request.data
        queryset = User.objects.filter(pk=kwargs['pk']).first()

        if not queryset:

            return Response("Not Found", status=status.HTTP_404_NOT_FOUND)
        else:
            queryset.groups.clear()

            for group in data['groups']:
                group_obj = Group.objects.get(pk=group['id'])
                queryset.groups.add(group_obj)
                serializer = UserSeriallizer(queryset, data, partial=True)

                if serializer.is_valid():
                    serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ANCHOR - Userlogin, create Token
class login_View(ObtainAuthToken):
    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username,

        })


class Taskview_Set(viewsets.ModelViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


# ANCHOR - get Tasks

    def list(self, request):
        if ToDo.objects.filter(author=request.user.pk):
            all = ToDo.objects.filter(author=request.user.pk)
            serializer = TodosSerializer(all, many=True)
        else:
            queryset = ToDo.objects.filter(users__id=request.user.pk)

            serializer = TodosSerializer(queryset, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

# ANCHOR - Create Task

    def create(self, request):
        data = request.data
        author = User.objects.get(pk=request.user.pk)
        new_task = ToDo.objects.create(title=data['title'],
                                       description=data['description'],
                                       author=author)

        new_task.save()

        for user in data['users']:
            user_obj = User.objects.get(pk=user)
            new_task.users.add(user_obj)

        for subtask in data['subtasks']:
            sub_obj = Subtask.objects.create(
                message=subtask['message'],
                task_id=new_task.id
            )
            new_task.subtasks.add(sub_obj)

        serializer = TodosSerializer(new_task)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

# ANCHOR - Patch Task

    def update(self, request, *args, **kwargs):
        data = request.data
        queryset = ToDo.objects.get(id=kwargs['pk'])

        if not queryset:
            return Response("Not Found", status=status.HTTP_404_NOT_FOUND)

        else:
            queryset.users.clear()
            for user in data['users']:
                user_obj = User.objects.get(pk=user['id'])

                queryset.users.add(user_obj)

            for st in data['subtasks']:

                if Subtask.objects.filter(id=st['id']).exists():
                    instance = Subtask.objects.get(id=st['id'])
                    instance .status = st['status']
                    instance .save()

                else:
                    st_obj = Subtask.objects.create(
                        message=st['message'], task_id=queryset.id)
                    queryset.subtasks.add(st_obj)

            serializer = TodosSerializer(queryset, data, partial=True)

            if serializer.is_valid(raise_exception=True):
                serializer.save(author=User.objects.get(
                    pk=data['author']['id']))

                return Response(serializer.data, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ANCHOR - Delete Task

    def destroy(self, request, *args, **kwargs):

        if not ToDo.objects.filter(id=kwargs['pk']).exists():
            return Response("Not Found", status=status.HTTP_404_NOT_FOUND)

        else:
            queryset = ToDo.objects.get(id=kwargs['pk'])
            data = Subtask.objects.filter(subtasks__id=kwargs['pk'])

            for st in data:
                st_obj = Subtask.objects.get(id=st.id)
                st_obj.delete()

            queryset.delete()

            return Response("successfully deleted", status=status.HTTP_200_OK)
