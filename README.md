# pastis-dse

Dynamic Symbolic Execution engine of PASTIS


## Prérequis fonctionnels

- doit être une librairie pour être appelé par *(pastis-agent.py)* avec une class ``Agent`` déjà instancié
- *(pour du test)* doit pouvoir être lancé en ligne de commande avec un ``FileAgent``

## Dépendances

Le projet utilise:
    - tritondse
    - libpastis

## TODO

- Faire la trame de setup.py qui permettra de l'installer sur le Pi

- Faire la class PastisDSE qui contiendra l'essentiel du code
    - le constructeur prend l'agent en paramètre et enregistre ses propres callbacks dessus
    
- Implémenter la callback ``start_callback`` et donc faire:
    - traiter tous le contenu du message (programme, config, options, rapport SAST etc.)
    - traiter en particulier CheckMode (qui va changer les callback qu'on enregistre sur le cbm)
    - lancer le SymbolicExplorator avec les bonnes options de config
 
- Implémenter la callback ``stop_callback`` qui interrompt l'exécution
    
- Implémenter le mode cli qui "craft" un start_message et appel la même fonction (+tester)

- Implémenter la callback ``seed_callback`` pour le réception de seed et implémenter l'envoie

- Implémenter l'envoie du message de fin via ``send_stop_coverage_criteria``

- Implémenter l'envoie de log et de telemetries

- Gooooooooooo !!!!
