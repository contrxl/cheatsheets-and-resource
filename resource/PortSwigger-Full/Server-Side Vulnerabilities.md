# What is path traversal?

Also known as directory traversal, allows an attacker to read arbitrary files on a server which is running an application, this may include:

- Application code and data
- Credentials for back-end systems
- Sensitive operating system files

In some cases, an attacker may also be able to write arbitrary files on the server.

# Reading Arbitrary Files via Path Traversal

A shopping app displays images of items for sale, the images are loaded with the following HTML:
`<img src="/loadImage?filename=218.png">`

The `loadImage` URL takes a `filename` parameter and returns the contents of the specified file. These files are on disk at `/var/www/images`. To return an an image, the app appends the requested filename to this base directory and reads the contents of the file. The app is reading from:
`/var/www/images/218.png`

The app has no defences against path traversal, this means that the following URL could be requested to read the `/etc/passwd` file:
`https://example.com/loadImage?filename=../../../etc/passwd`

This causes the app to read from:
`/var/www/images/../../../etc/passwd

The `../` sequence indicates to step up one directory, this means the actual file being read is:
`/etc/passwd`

On UNIX OS, this is a standard file containing user details, however, this technique could be used to read any file on the system. On Windows, both of the below are valid:
```
../
..\ 
```

A similar technique on Windows would look like:
`https://example.com/loadImage?filename=../../../windows/win.ini`

# What is Access Control?

Access control is the application of constraints on who or what is authorised to perform actions or access resources, this is dependent on authentication and session management:

- Authentication confirms the user is who they claim to be
- Session Management identifies which HTTP requests are made by that same user
- Access control determines whether the user is allowed to carry out the action they are attempting to perform

Broken access controls are common, and present a critical security vulnerability.

# Vertical Privilege Escalation

If a user can gain access to functionality they should not have permission to access, this is vertical privilege escalation. If a non-admin user can access an admin page where they can delete accounts, this is vertical privilege escalation.

# Unprotected Functionality

When an app does not enforce protections on sensitive functionality, vertical privilege escalation can arise. For example, admin functions may be linked from an admins welcome page, but not a users welcome page. However, the user could still browse to the relevant admin URL. For example,
`https://example.com/admin`

This may be visible by any user, not only to admin users. The admin URL may also be disclosed in other locations like `robots.txt`:
`https://example.com/robots.txt`

Even if the URL is not disclosed, an attacker could use brute force to determine the location of sensitive functionality.

Sensitive functionality can be concealed by giving it a less obvious URL, this is an example of "security by obscurity", however, hiding sensitive functions does not always provide effective access control. For instance:
`https://example.com/admin-panel-yb556`

This may not be guessable, but the app may leak the URL by disclosing it in JavaScript assigned to the user based on their role:
```
<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('https://example.com/admin-panel-yb556);
		adminPanelTag.innerTet = 'Admin panel';
		...
	}
</script>
```

This script adds a link to the user UI if they are admin, however, the script is visible to all users regardless of role.

# Parameter Based Access Control

Some apps can determine the user access rights at login, then store this info in a user-controlled location. This could be:

- A hidden field
- A cookie
- A preset query string parameter

The app makes access control decisions based on the submitted value, for example:
```
https://example.com/login/home.jsp?admin=true
https://example.com/login/home.jsp?role=1
```

This approach is insecure because the user can modify the value and access functions they should not be able to.

# Horizontal Privilege Escalation

This occurs if a user can gain access belonging to other users, rather than their own resources. If an employee can access anothers records, this is horizontal privilege escalation. 

These attacks can use similar methods as vertical privilege escalation, for example, the following may be used to access a users homepage:
`https://example.com/myaccount?id=1`

If the `id` parameter is modified, another users account may be accessible. 
> [!NOTE] This is an example of an Insecure Direct Object Reference (IDOR) vulnerability. This arises when user-controlled parameters are used to access resources or functions directly.
> 

Some apps may use random, unpredictable values to try and prevent this, however, other IDs or values may be disclosed in other parts of the application.

# Horizontal to Vertical Privilege Escalation

Horizontal escalation can often turn into vertical escalation by means of compromising a more privileged user. For example, horizontal escalation may allow another users password to be captured or reset. Using previous techniques, it may be possible to latch onto an administrative accoutnt.