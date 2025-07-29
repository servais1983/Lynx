// Fichier JavaScript de démonstration pour Lynx
// Ce fichier contient le pattern "string2" pour tester la détection

console.log("Démarrage du script de démonstration");

// Pattern recherché : string2
const suspiciousPattern = "string2";

// Fonction de test
function testPattern() {
    console.log("Pattern détecté :", suspiciousPattern);
    return "string2 trouvé dans le code";
}

// Code suspect pour la démonstration
const maliciousCode = `
    // Simulation de code malveillant
    eval("string2");
    document.write("string2");
    window.location = "string2";
`;

// Test de détection
if (maliciousCode.includes("string2")) {
    console.log("Pattern suspect détecté !");
}

module.exports = {
    pattern: suspiciousPattern,
    description: "Fichier de test pour la détection de patterns"
}; 