<#
.SYNOPSIS
Verifie si un mot de passe à déja fuité dans une base de donnée du site: https://haveibeenpwned.com/
 
.DESCRIPTION
Verifie si un mot de passe à déja fuité dans une base de donnée du site: https://haveibeenpwned.com/

Invite à saisir un mot de passe, ensuite ce mot de passe est hashé en sha1 pour qu'il soit comparé à la base de mot de passe de haveibeenpwned.
Seul les 5 premiers caractères du hash sont envoyé au site, le reste du hash est renvoyé par la requete HTTP du site, ainsi le mot de passe et son hash restent sur l'ordinateur source et on est sur qu'il n'est pas compromis car envoyé quelque part.

.EXAMPLE
Appelé le script avec la commande: 
./Get-CheckPasswordLeak.ps1 
puis saisir le mot de passe à tester.
 
.NOTES

.LINK

#>

do{
$password = Read-Host -Prompt "Saisir un mot de passe" -AsSecureString 
} while ($password.Length -eq 0)

# converti le mot de passe en hash sha1
$passwordBytes = [System.Text.Encoding]::ASCII.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))
$hash = [BitConverter]::ToString([System.Security.Cryptography.SHA1]::Create().ComputeHash($passwordBytes)).ToLower() -replace '-'

# crée le lien qui servira à tester le mot de passe, puis envoi une requête
# Documentation: https://haveibeenpwned.com/API/v3#APIVersion
$link =  "https://api.pwnedpasswords.com/range/" + $hash.subString(0,5)
$testPassword = Invoke-WebRequest -Uri $link 

# Si la connexion au site a reussie, on regarde parmis le contenu que nous a renvoyé le site si le hash est présent ou non
if ($testPassword.StatusCode -eq 200){
    $isLeaked = $false
    $content = $testPassword.Content.Split([Environment]::NewLine)
    foreach ($element in $content){
        $element = $element.Split(":")
        if ($element[0] -like $hash.subString(5)){
            Write-Host "$hash correspond à $($element[0])"
            Write-Host "Le mot de passe a fuité dans: $($element[1]) leak" -ForegroundColor red
            $isLeaked = $true
            break
        }
    }

    if ($isLeaked -eq $false) {
        Write-Host "Le mot de passe n'a pas leak" -ForegroundColor green
    }

} else {
    # Si on ne peux pas se connecter au site, il y a une erreur
    Write-Host "Erreur lors de la requête de test du mot de passe, vérifier votre connexion"
}

<# liens utiles:
https://github.com/yrougy/CheckPasswordLeak/blob/master/check_pass.bash
https://github.com/yrougy/CheckPasswordLeak/blob/master/check_pass.php
https://www.powershellgallery.com/packages/Get-PwnedPassword/1.3/Content/Get-PwnedPassword.ps1
https://haveibeenpwned.com/API/v3#APIVersion
#>

<#PSScriptInfo
 
.VERSION 1.0
 
.AUTHOR Loonaire https://www.github.com/loonaire
 
.DESCRIPTION 
       
.COMPANYNAME 
 
.COPYRIGHT
 
.TAGS Password,Leak
 
.LICENSEURI
 
.PROJECTURI
 
.ICONURI
 
.EXTERNALMODULEDEPENDENCIES
 
.REQUIREDSCRIPTS
 
.EXTERNALSCRIPTDEPENDENCIES
 
.RELEASENOTES
 
#>
