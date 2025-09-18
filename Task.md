Мы создаем аддон для Novatek в Home assistant
Тут документация: https://htmlpreview.github.io/?https://github.com/vedga/novatek/blob/main/API/WebApi_EM-125_126_129_.html
Авторизация для апи выполняется следующим образом: 
1 .Получение информации об устройстве: /api/login?device_info
2. Далее декодируем "user_info" и берем первые 6 символов - DeviceInfo
3. Далее получаем соль: /api/login?salt
4. Далее генерируем пароль для аутентификации: sha1 (DeviceInfo+password+Соль)
5. Далее выполняем авторизацию с полученным на предыдущем этапе паролем для аутентификации: /api/login?login
6. Полученый пароль подставляем в api/login?login="Пароль"