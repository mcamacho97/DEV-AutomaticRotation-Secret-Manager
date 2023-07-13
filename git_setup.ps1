# Solicitar URL de repositorio
$url = Read-Host "Ingrese el URL del repositorio"

# Solicitar mensaje de commit
$commitMessage = Read-Host "Ingrese el mensaje del commit"

# Inicializar repositorio Git
git init

# Cambiar el nombre de la rama de master a main
git branch -m master main

# Agregar todos los archivos al repositorio Git
git add .

# Hacer commit con el mensaje proporcionado
git commit -m $commitMessage

# Agregar el origen remoto
git remote add origin $url

# Realizar una fusión (merge) permitiendo historias no relacionadas
git pull origin main --allow-unrelated-histories

# Empujar los cambios al repositorio remoto
git push -u origin main
