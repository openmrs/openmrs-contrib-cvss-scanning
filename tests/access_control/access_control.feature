Feature: Access Control
    Background:
        Given a CVSS score is calculated and printed
    
    Scenario Outline: Users cannot edit the admin account password
        Non Admin users should not be able to edit the password of the admin account by posting to the API.

        Given the UUID of an admin user is known
        When a <nonAdminType> user attempts to change the password of the admin
        Then the system should respond with a http 500 error

    Examples:
        | nonAdminType |  
        | clerk        |
        | technician   |
        | nurse        |
        | doctor       |

    Scenario Outline: Users can edit their own passwords
        Non Admin users should be able to edit their passwords

        When a <nonAdminType> user attempts to change the password of their account
        Then the system should respond with a http 200 status

    Examples:
        | nonAdminType |  
        | clerk        |
        | technician   |
        | nurse        |
        | doctor       |