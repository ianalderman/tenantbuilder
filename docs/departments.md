# Departments #

## About ##
The Departments functionality is responsible for configuring users and groups associated with an Organisation's structure.

### Departments ###
Each department will automatically have the following groups created (but not populated):
- <Department Name> Members
- <Department Name> Owners

A Department will have a Leadership Team and one or more Product Teams.  When processing the Leadership section the script will look for the ````IsManager```` property defined for a user, where this is ````true```` a _dynamic group_ called *<Manager Name> Directs* will be created.  This group will contain any user objects which have the manager set to this user.

### Product Teams ###
Product Teams are simply a team name and a list of team members

## Users ##

When creating users for both the ````Leadership```` and ````ProductTeam````sections the script will create a user with the following properties set:
- Given Name
- Surname
- Display Name
- Department - set to the _Department Name_ for _Leadership_ members or the _Product Team Name_ for Product Team Members
- Title
- Manager (if set)
- Usage Location (defaults to GB if not supplied)
- Licence (defaults to DEVELOPERPACK_E5 if not supplied)
- Random password (shared across all users for the script run)

## Technical Detail ##

### Objects Created ###
- Azure Active Directory User
- Azure Active Directory Group
- Azure Active Directory Dynamic Group

### JSON Template ###
TBC