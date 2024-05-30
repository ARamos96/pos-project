Hello Everyone! 🙋‍♂️ Today will be recapping everything we’ve learned, and then build a Front-End that also handles auth. But first, I really want to reinforce your knowledge in this back-end part, and I’m going to have you make a mini POS back-end.

> But I’m so sleepy! I can’t hear Diogo for even 20 minutes!
> 

^ That’s perfectly okay! That’s why today I tailored an activity for you to work on your own while Diogo stalks your breakout room every 15 minutes. 😊

---

### Handling Auth in Front-End

We have covered the most complicated bit - the back-end - today we need to find a way for the front-end to save the `jwt` in the `localStorage` , and send that token whenever we need anything from the back-end.

### When is a jwt needed?

Whenever we’re trying to access protected routes. A user that doesn’t yet have an account can access any of the unprotected routes (like the `LoginPage.jsx` or the `SignUpPage.jsx` one).

### jwt or Cookies?

- **Cookies**: Best suited for traditional web applications with server-side rendered pages and session management.
- **JWT**: Ideal for single-page applications (SPAs), mobile apps, and microservices architecture where stateless and decentralized authentication is beneficial.
- Compare the Two! **[Table]**
    
    
    | Feature | Cookies | JWT |
    | --- | --- | --- |
    | Storage | Browser cookies | localStorage, sessionStorage, or cookies |
    | Session Management | Server-side | Client-side (stateless) |
    | Security | HttpOnly, Secure flags, CSRF tokens | Signature verification, less vulnerable to CSRF |
    | Statefulness | Stateful | Stateless |
    | Expiration | Set via cookie attributes | Managed via exp claim and refresh tokens |
    | Ease of Use | Built-in support in many frameworks | Requires manual implementation of storage and handling |
    | Use Cases | Traditional web apps | SPAs, APIs, microservices |

---

## Recapping

### jwt? more like jwtf

JWT - Json Web Tokens - is a way to combine data with a password and get a token that you can use to authenticate yourself and get access to protected actions.

JWTs are self-contained, meaning they carry all the information needed for authentication within the token itself. This makes the server stateless, as it doesn't need to maintain session information.

### **Structure of a JWT**

A JWT consists of three parts separated by dots (.), which are:

1. **Header**
2. **Payload**
3. **Signature**

These parts are encoded in Base64Url and concatenated to form the JWT string:

```
xxxxx.yyyyy.zzzzz
```

**Btw, about Base64:**

Base64 encoding is a method of converting binary data into an ASCII string format using a set of 64 characters (A-Z, a-z, 0-9, +, /). It is used to encode data for safe transmission over media that are designed to handle text, such as email and URLs. This encoding ensures that the data remains intact without modification during transport.

---

🙋‍♂️ - Ok now let’s start by generating our project without auth and incorporating it manually.

### 0. Use ironlauncher to generate your back-end

You can already include auth if you want to skip this part, but I would advise configuring it manually to assure info retention.

```bash
# 🙋‍♂️ make sure to select json > no authentication!
npx ironlauncher pos-project
```

### 1. Configuring jwt in a node project

You’ll need to install jsonwebtoken, bcryptjs and express-jwt.

```bash
# go inside the created folder and run this script
npm i bcryptjs jsonwebtoken express-jwt
```

This installs the dependencies in `node_modules` and references them in the `package.json` file.

![Make sure these are in your package.json file!](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/bddc0422-fba9-4194-bf9d-76c4f73c3a23/Screenshot_2024-05-25_at_09.41.34.png)

Make sure these are in your package.json file!

---

### 2. Creating an auth routes file

![^ In this example, you can create any other route files too, depending on your models! ](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/bc32a2d8-034b-4565-814e-33b031df2cdb/Screenshot_2024-05-25_at_09.38.29.png)

^ In this example, you can create any other route files too, depending on your models! 

This is a file that contains all routes related to authenticating - `/login` and `/signUp` are the most important ones.

Today, we’ll also have the `assignRole` route - which could be in auth or in admin depending on how scaled the app is. This route is where an admin can assign the a role to another user after registering. Ideally, you’d have a route just for creating a user through an **admin,** and the new user later gets to set their own password.

Let’s create the routes.  for `auth.routes.js` !

- ← You access them here.
    
    ```jsx
    // routes/auth.routes.js
    
    const express = require("express");
    const bcrypt = require('bcryptjs');
    const jwt = require("jsonwebtoken");
    const User = require("../models/User.model");
    
    const { isAuthenticated } = require("./../middleware/jwt.middleware")
    
    const router = express.Router();
    const saltRounds = 10;
    
    // POST /auth/signup  - Creates a new user in the database
    router.post('/signup', (req, res, next) => {
        const { email, password, name } = req.body;
    
        // Check if the email or password or name is provided as an empty string 
        if (email === '' || password === '' || name === '') {
            res.status(400).json({ message: "Provide email, password and name" });
            return;
        }
    
        // Use regex to validate the email format  a@a.bb
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!emailRegex.test(email)) {
            res.status(400).json({ message: 'Provide a valid email address.' });
            return;
        }
    
        // Use regex to validate the password format
        const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
        if (!passwordRegex.test(password)) {
            res.status(400).json({ message: 'Password must have at least 6 characters and contain at least one number, one lowercase and one uppercase letter.' });
            return;
        }
    
        // Check the users collection if a user with the same email already exists
        User.findOne({ email })
            .then((foundUser) => {
                // If the user with the same email already exists, send an error response
                if (foundUser) {
                    res.status(400).json({ message: "User already exists." });
                    return;
                }
    
                // If the email is unique, proceed to hash the password
                const salt = bcrypt.genSaltSync(saltRounds);
                const hashedPassword = bcrypt.hashSync(password, salt);
    
                // Create a new user in the database
                // We return a pending promise, which allows us to chain another `then` 
                return User.create({ email, password: hashedPassword, name });
            })
            .then((createdUser) => {
                // Deconstruct the newly created user object to omit the password
                // We should never expose passwords publicly
                const { email, name, _id } = createdUser;
    
                // Create a new object that doesn't expose the password
                const user = { email, name, _id };
    
                // Send a json response containing the user object
                res.status(201).json({ user: user });
            })
            .catch(err => {
                console.log(err);
                res.status(500).json({ message: "Internal Server Error" })
            });
    });
    
    // POST  /auth/login - Verifies email and password and returns a JWT
    router.post('/login', (req, res, next) => {
        const { email, password } = req.body;
    
        // Check if email or password are provided as empty string 
        if (email === '' || password === '') {
            res.status(400).json({ message: "Provide email and password." });
            return;
        }
    
        // Check the users collection if a user with the same email exists
        User.findOne({ email })
            .then((foundUser) => {
    
                if (!foundUser) {
                    // If the user is not found, send an error response
                    res.status(401).json({ message: "User not found." })
                    return;
                }
    
                // Compare the provided password with the one saved in the database
                const passwordCorrect = bcrypt.compareSync(password, foundUser.password);
    
                if (passwordCorrect) {
                    // Deconstruct the user object to omit the password
                    const { _id, email, role, name } = foundUser;
    
                    // Create an object that will be set as the token payload
                    const payload = { _id, email, role, name };
    
                    // Create and sign the token
                    const authToken = jwt.sign(
                        payload,
                        process.env.TOKEN_SECRET,
                        { algorithm: 'HS256', expiresIn: "6h" }
                    );
    
                    // Send the token as the response
                    res.status(200).json({ authToken: authToken });
                }
                else {
                    res.status(401).json({ message: "Unable to authenticate the user" });
                }
    
            })
            .catch(err => res.status(500).json({ message: "Internal Server Error", err: err.message }));
    });
    
    module.exports = router;
    ```
    

After this, you add them in `app.js` 

```jsx
// app.js
const authRouter = require("./routes/auth.routes");
app.use("/auth", authRouter);
```

*Make sure to check your understanding of how a password is hashed on registering, and how a jwt is signed and generated everytime a user logs in. Meanwhile, in the front-end, they save this jwt in the localStorage for like a couple of days, but not too long or Diogo will hack you like he showed you how he could!*

---

### 3. Creating middleware for jwt validation

This middleware starts with a function that verifies if the jwt has a correct signature. The function is processed in a way that we don’t need to use a function that recieves `req` and `res` , you just call it immediately.

```jsx
// middleware/jwt.middleware.js

const { expressjwt: jwt } = require("express-jwt");

// Instantiate the JWT token validation middleware
const isAuthenticated = jwt({
    secret: process.env.TOKEN_SECRET,
    algorithms: ["HS256"],
    requestProperty: 'payload',
    getToken: getTokenFromHeaders
});

// Function used to extracts the JWT token from the request's 'Authorization' Headers
function getTokenFromHeaders(req) {

    // Check if the token is available on the request Headers
    if (req.headers.authorization && req.headers.authorization.split(" ")[0] === "Bearer") {

        // Get the encoded token string and return it
        const token = req.headers.authorization.split(" ")[1];
        return token;
    }

    return null;
}

// Export the middleware so that we can use it to create a protected routes
module.exports = {
    isAuthenticated
}
```

*^ Do you understand this code?*

Update the .env file to contain the TOKEN_SECRET variable:

```
#.env
PORT=5005
ORIGIN=*
TOKEN_SECRET=1r0Nh4cK
```

Now, everytime a protected route is accessed, It gets the token in the HTTP object (as a Bearer Token) and checks if the signature is valid.

If it is valid, then the next middleware is called! If not, 403 error code!

---

### 4. Postman Testing: SignUp + Login

We did this last class - the big part here is to be able to use the token in the Authentication header. The flow here is to test all the auth routes before actually trying to access protected ones.

![An example on using the route for creating an user with Postman.](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/41822166-5314-41a9-baa9-91483ec68c16/Screenshot_2024-05-25_at_10.11.30.png)

An example on using the route for creating an user with Postman.

*Do you understand why this is necessary? The flow of why you need to login, why you get the jwt from the login, and why you always have to send back the jwt everytime you access anything? If you do, understanding front-end is going to flow like a breeze.*

---

### 5. Protecting Routes

The idea now is to protect certain routes in your application. Let’s use our  `index.routes`  file to do this!

```jsx
const router = require("express").Router();
const { isAuthenticated } = require("./../middleware/jwt.middleware")

router.get("/", (req, res, next) => {
  res.json("All good in here (accessible to anyone)");
});

router.get("/protected", isAuthenticated, (req, res, next) => {
  res.json("All good in here (only for logged in users!)");
});

module.exports = router;
```

ℹ️ Note! if you call the isAuthenticated middleware, you can access the content of the token by calling the property `req.payload`.

```jsx
router.get("/protected", isAuthenticated, (req, res, next) => {
	console.log(req.payload)
  res.json("All good in here for user " + req.payload.name);
});
```

🙋‍♂️ Now let’s try accessing these routes from Postman!

```
From postman, try to access this (with the Authorization Header):
[http://localhost:5005](http://localhost:5005/)/protected
```

![Include the Bearer Token with the generated JWT](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/64801daa-0354-4a4a-8fee-fde5ed46ee91/Screenshot_2024-05-25_at_10.39.44.png)

Include the Bearer Token with the generated JWT

---

## **✨ Expanding with Roles and Role Validation**

### **6. Adding Roles to the User Model**

Let's expand our User model to include roles. This will help us manage permissions and access control.

```jsx

// models/User.model.js

const mongoose = require("mongoose");
const { Schema, model } = mongoose;

const userSchema = new Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  
  // add -------
  role: { 
	  type: String,
	  required: true,
	  default: "user",
	  enum: ["user", "admin", "vendor"]
	}, 
	// add -------
	
****  name: { type: String, required: true },
});

module.exports = model("User", userSchema);
```

---

We also need to change the `login` route in `auth.routes.js` so that when we login, we also get the role of the user.

```jsx
// routes/auth.routes.js

// ... rest of code in /login

if (passwordCorrect) {
    // Deconstruct the user object to omit the password
    const { _id, email, role, name } = foundUser;

    // Create an object that will be set as the token payload
    const payload = { _id, email, role, name };

// ... 
```

The existing users in the database don’t yet have roles. We need to manually assign them if necessary, or if not, just create a new user and you’ll see “role” already comes in there.

![Notice that existing users do not yet have the property “role” imported, it’s therefore an earlier version of the database.](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/1adf2ae0-8e5b-4696-bcf6-a16daa16f029/Screenshot_2024-05-25_at_10.53.18.png)

Notice that existing users do not yet have the property “role” imported, it’s therefore an earlier version of the database.

You can manually assign the role “user” to existing users that don’t feature the field `role` yet.

![By editing in MongoDB Compass, you can add properties or change existing ones ](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/82ba6554-62f1-4f95-9935-45ffc9fc6bac/Screenshot_2024-05-25_at_10.53.40.png)

By editing in MongoDB Compass, you can add properties or change existing ones 

### Creating our first Admin

To create an admin, you can manually change, in the database, one single **superuser** that is an admin and will have rights to create new admins and new users.

![Using Compass to change a user’s role to admin](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/e2b3696e-2d30-4929-a9a1-4502f8b4c0cf/Screenshot_2024-05-25_at_10.53.50.png)

Using Compass to change a user’s role to admin

Now, in order to get a JWT that has a role `user` or a role `admin`, you have to log in again using that same user!

![You will obtain a new JWT token that contains the role “admin” and can be used in middleware validation](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/3726dde1-69a7-4abd-b006-6e4699584538/Screenshot_2024-05-25_at_10.58.19.png)

You will obtain a new JWT token that contains the role “admin” and can be used in middleware validation

### Debugging the jwt

Paste the jwt you got in [jwt.io](http://jwt.io) in order to check if it’s properly created and formatted.

![The more data you put in your payload, the longer the authToken becomes.](https://prod-files-secure.s3.us-west-2.amazonaws.com/0cedfc2c-48a9-4887-8a86-595f4a025dcf/6c279a91-6b5f-4e50-92c5-13891fe62b51/Screenshot_2024-05-25_at_10.59.45.png)

The more data you put in your payload, the longer the authToken becomes.

---

### **7. Creating Role Validation Middleware**

We will create middleware to validate user roles for protected routes.

🙋‍♂️ Now this middleware is more special than the simple one I taught - it takes an array of roles and checks if the role in the jwt is in the possible options for that route - because for example, an admin AND a vendor might be able to create a purchase.

I’m using a new file:

```jsx
// middleware/roleValidation.js
const roleValidation = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.payload.role)) {
      return res.status(403).json({ message: "Access forbidden: insufficient rights" });
    }
    next();
  };
};

module.exports = { roleValidation };
```

---

### **8. Using Role Validation Middleware in Routes**

Understand how admin can have their own routes file `admin.routes.js` for their own domain of the things they can do.

Let's protect our routes using the role validation middleware. See how roleValidation is being called.

```jsx
// routes/admin.routes.js
const express = require("express");
const router = express.Router();
const { isAuthenticated } = require("../middleware/jwt.middleware");
const { roleValidation } = require("../middleware/roleValidation");

// Example of a protected route for admins
router.patch("/assign-role", isAuthenticated, roleValidation(["admin"]), (req, res) => {
  // Logic to assign role
});

module.exports = router;
```

---

## **Making a Mini POS App**

Now that we have the authentication and role-based access control in place, let's create a mini POS (Point of Sale) app.

### **Models**

For our mini POS app, we'll need at least two models: **`Product`** and **`Purchase`**.

- Product Model
    
    ```jsx
    // models/Product.model.js
    
    const mongoose = require("mongoose");
    const { Schema, model } = mongoose;
    
    const productSchema = new Schema({
      name: { type: String, required: true },
      price: { type: Number, required: true },
      description: String,
      inStock: { type: Number, default: 0 },
    });
    
    module.exports = model("Product", productSchema);
    ```
    
- Purchase Model
    
    ```jsx
    // models/Purchase.model.js
    
    const mongoose = require("mongoose");
    const { Schema, model } = mongoose;
    
    const purchaseSchema = new Schema({
      product: { type: Schema.Types.ObjectId, ref: "Product", required: true },
      quantity: { type: Number, required: true },
      buyer: { type: Schema.Types.ObjectId, ref: "User", required: true },
      date: { type: Date, default: Date.now },
    });
    
    module.exports = model("Purchase", purchaseSchema);
    ```
    

---

### **Product Routes**

You can write your own script for this, or use this one as a reference. Getting or searching for products should be accessible to any logged in users (with any role); changing or creating products should only be an admin thing.

```jsx
// routes/product.routes.js
const express = require("express");
const router = express.Router();
const Product = require("../models/Product.model");
const { isAuthenticated } = require("../middleware/jwt.middleware");
const roleValidation = require("../middleware/roleValidation");

// Get all products (accessible to all users)
// 🥕 This one's easy, you can test it right away! 
router.get("/", (req, res) => {
  Product.find()
    .then(products => res.json(products))
    .catch(err => res.status(500).json({
	    message: "Internal Server Error", err 
	 }));
});

// Create a new product (only admin)
// ⛔️ you can only run this route if you actually logged in with admin!
router.post("/", isAuthenticated, roleValidation(["admin"]), (req, res) => {
  const { name, price, description, inStock } = req.body;
  Product.create({ name, price, description, inStock })
    .then(newProduct => res.status(201).json(newProduct))
		    .catch(err => res.status(500).json({ 
			    message: "Internal Server Error", err 
    }));
});

module.exports = router;
```

### What’s Up (Post)man?

Whenever you create a route, test it in Postman to see if it’s really working and you understand the flow of it. You probably will have to create documentation for it later anyway!

---

### **Purchase Routes**

Below I’m using `async` and `await`. These are alternatives to using the `.then()` Promise syntax. **It’s fundamental that you test these with Postman**.

```jsx
// routes/purchase.routes.js
const express = require("express");
const router = express.Router();
const Purchase = require("../models/Purchase.model");
const Product = require("../models/Product.model");
const { isAuthenticated } = require("../middleware/jwt.middleware");
const roleValidation = require("../middleware/roleValidation");

// Create a new purchase (only vendor)
router.post("/", isAuthenticated, roleValidation(["vendor"]), async (req, res) => {
  const { productId, quantity, buyerId } = req.body;

  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    if (product.inStock < quantity) {
      return res.status(400).json({ message: "Insufficient stock" });
    }

    const purchase = await Purchase.create({
	     product: productId,
	     quantity,
	     buyer: buyerId
	  });
	     
    product.inStock -= quantity;
    await product.save();

    res.status(201).json(purchase);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error", err });
  }
});

// Get all purchases (only admin)
router.get("/", isAuthenticated, roleValidation(["admin", "vendor"]), (req, res) => {
  Purchase.find()
    .populate("product")
    .populate("buyer")
    .then(purchases => res.json(purchases))
    .catch(err => res.status(500).json({
	     message: "Internal Server Error", err
   }));
});

module.exports = router;
```

---

### Okay, what now Diogo?… I am either way too far ahead (Arnau) or way too far behind (Everybody Else)

Now it’s time for you to develop the `assignRole`  functionality. Consider creating a `users.routes.js` file for this, as this is more related to managing users than to authenticate them. In this route, you can also get all users, get user by ID (along with all information). You can create a patch method for this, and just update the role!

- ← Code for Reference
    
    ```jsx
    // Assign role to a user (admin only)
    router.patch("/assign-role/:userId", isAuthenticated, roleValidation(["admin"]), (req, res) => {
        const { role } = req.body;
        if (!["user", "admin", "vendor"].includes(role)) {
            return res.status(400).json({ message: "Invalid role" });
        }
    
        User.findByIdAndUpdate(req.params.userId, { role }, { new: true })
            .then(updatedUser => {
                if (!updatedUser) {
                    return res.status(404).json({ message: "User not found" });
                }
                res.json(updatedUser);
            })
            .catch(err => res.status(500).json({ message: "Internal Server Error", err }));
    });
    ```
    

> 👱‍♂️ Is getting all this info from users legal?
> 

🙋‍♂️ Yes, but when the users register in your website or app, you have to tell them clearly that you’re using their information for management of the application and, ideally, would only work for business administration, not disclosing the information.

---

**Other routes to consider in this back-end:**

1. Get User Details (Admin Only)
2. Update User Details (Admin Only)
3. Update Product Details (Admin Only)
4. Delete a Product (Admin Only)
5. Get Purchase Details (Vendor/Admin Only)
6. Update Purchase Details (Vendor/Admin Only)
7. Delete a Purchase (Vendor/Admin Only)
8. Search Products
9. Get Purchases by User (User/Admin Only)
10. Get Products Low in Stock (Admin Only)
