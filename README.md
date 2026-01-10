# Analyseur de Sécurité des Mots de Passe Gmail | À des fins éducatives uniquement

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Security](https://img.shields.io/badge/Security-Audit-red)
![License](https://img.shields.io/badge/License-Educational%20Only-lightgrey)

---

## ⚠️ AVIS LÉGAL – À LIRE AVANT UTILISATION

**Ce dépôt est fourni uniquement à des fins d’APPRENTISSAGE, DE RECHERCHE et d’AUDITS DE SÉCURITÉ AUTORISÉS.**

**Cet outil utilise l’API PASS REVELATOR pour illustrer des concepts d’analyse de mots de passe.  
Pour plus d’informations sur la protection des comptes email et l’audit des mots de passe :**  
👉 https://www.passwordrevelator.net/fr/passbreaker

![PassBreaker Logo](./PASSBREAKER.png)

- 🚫 **Utilisation interdite** : Toute tentative d’accès à des comptes Gmail sans autorisation explicite est illégale.
- ✅ **Autorisation requise** : Effectuez les tests uniquement sur des comptes que vous possédez ou pour lesquels vous avez une autorisation écrite.
- 🔐 **Focus éducation à la sécurité** : L’objectif est de mettre en évidence les mots de passe faibles et de promouvoir de bonnes pratiques d’authentification.
- ⚖️ **Responsabilité utilisateur** : L’utilisateur est entièrement responsable du respect des lois.

**En utilisant ce logiciel, vous reconnaissez que l’accès non autorisé à des systèmes informatiques est passible de sanctions dans de nombreux pays.**

---

## 🎯 Présentation du projet

L’**Analyseur de Sécurité des Mots de Passe Gmail** est un outil pratique de formation en cybersécurité conçu pour démontrer comment le piratage de mots de passe peut être exploité.  
Il s’adresse aux étudiants, chercheurs et professionnels de la sécurité souhaitant comprendre les simulations d’attaques sur les mots de passe.

### 🎓 Objectifs pédagogiques

- Présenter des techniques courantes d’attaque de mots de passe dans un environnement contrôlé.
- Évaluer la robustesse des mots de passe sur des comptes Gmail autorisés.
- Sensibiliser aux vulnérabilités liées aux identifiants.
- Soutenir l’enseignement en cybersécurité et la formation au hacking éthique.
- Hacker les protections OAuth2.

---

## ✨ Fonctionnalités principales

### 🔑 Approches de test de mots de passe

- **Audit par listes de mots** : Teste les mots de passe avec des dictionnaires standard ou personnalisés.
- **Génération basée sur des modèles** : Crée des mots de passe selon des masques de caractères définis.
- **Variations par règles** : Modifie des termes de base avec des transformations fréquentes.
- **Techniques mixtes** : Combine plusieurs méthodes pour étendre la couverture.

### 🌐 Contrôles de confidentialité et anonymat

- **Rotation automatique des proxys** : Change de proxy pendant l’exécution.
- **Compatibilité Tor** : Permet le routage via le réseau Tor.
- **Régulation dynamique des requêtes** : Ajuste automatiquement les intervalles entre requêtes.
- **Simulation de navigateur** : Randomise les en-têtes User-Agent.

### 📊 Suivi et rapports

- Indicateurs d’avancement en temps réel.
- Statistiques de succès et performance.
- Suivi de la consommation des ressources.
- Journaux complets et rapports détaillés.

### 🔒 Gestion sécurisée des interactions

- Gestion des jetons CSRF.
- Flux d’authentification type Gmail.
- Gestion sécurisée des sessions.
- Détection automatique des CAPTCHA.

---

## 🚀 Instructions d’installation

### Prérequis

- Python 3.8 ou supérieur
- Gestionnaire de paquets pip
- Connexion Internet active

### Étape 1 : Récupérer le code source

git clone https://github.com/HoffmannAlex/Pirater-un-compte-GMail-Avec-IA.git  
cd gmail-password-tool

### Étape 2 : Installer les bibliothèques nécessaires

pip install -r requirements.txt

### Dépendances principales

aiohttp>=3.8.0  
requests>=2.28.0  
cryptography>=3.4.0  
stem>=1.8.0  
psutil>=5.9.0  
asyncio>=3.9.0  

### Étape 3 : Vérifier l’installation

python hack_gmail.py --help

---

## ⚡ Scénarios d’utilisation

### Audit de mots de passe standard

python hack_gmail.py --email your_account@gmail.com --password-list passwords.txt

### Audit anonyme via Tor

python hack_gmail.py --email your_account@gmail.com --password-list passwords.txt --use-tor

### Mode multi-threads haute performance

python hack_gmail.py --email your_account@gmail.com --password-list passwords.txt --threads 4 --use-tor --min-delay 2 --max-delay 5

### Exécution via proxy

python hack_gmail.py --email your_account@gmail.com --password-list passwords.txt --proxy-list proxies.txt --threads 3

---

## 🔥 Techniques de test disponibles

### 1. Audit par dictionnaire

python hack_gmail.py --email target@gmail.com --password-list common_passwords.txt  
python hack_gmail.py --email target@gmail.com --password-list custom_list.txt  

### 2. Création de mots de passe basée sur des masques

?l?l?l?d?d?d  # Exemple : abc123  
?u?l?l?l?d?d  # Exemple : Abcd12  
?l?l?l?l?s?d  # Exemple : abcd!1  

### 3. Mode règles / combinaisons

python hack_gmail.py --email target@gmail.com --strategy combination --base-words "password,gmail,user"

### 4. Démonstration brute force complète (strictement éducatif)

python hack_gmail.py --email target@gmail.com --strategy brute --min-length 4 --max-length 8
