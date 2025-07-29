# Suspicious PowerShell Script - DEMONSTRATION ONLY
# Ce fichier contient des patterns PowerShell malveillants pour tester Lynx

# Patterns détectés :
# - Invoke-Expression
# - IEX
# - eval(
# - exec(
# - system(

# Code malveillant simulé
Write-Host "Démarrage du script PowerShell suspect"

# Invoke-Expression dangereux
$payload = "Invoke-Expression (Get-Content 'malicious.ps1')"
Invoke-Expression $payload

# Évaluation de code
eval("Write-Host 'malicious code executed'")

# Exécution de commande
exec("Get-Process | Stop-Process")

# Appel système
system("malicious system command")

Write-Host "Script PowerShell suspect terminé" 