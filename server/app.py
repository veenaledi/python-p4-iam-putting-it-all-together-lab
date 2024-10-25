from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from models import User, Recipe
from config import app, db, api


class Signup(Resource):
    def post(self):
        data = request.get_json()

        # Ensure both username and password are present
        if 'username' not in data or 'password' not in data:
            return make_response({"error": "Username and password are required"}, 422)

        try:
            new_user = User(
                username=data['username'],
                password_hash=data['password'],  # Use setter to hash password
                image_url=data.get('image_url', ""),
                bio=data.get('bio', "")
            )
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id  # Store user ID in session

            return make_response(new_user.to_dict(), 201)

        except IntegrityError:
            db.session.rollback()
            return make_response({"error": "Username already taken"}, 422)
        except Exception as e:
            # Catch unexpected errors to help with debugging
            print(f"Error during signup: {e}")
            return make_response({"error": "Internal server error"}, 500)


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            if user:
                return make_response(user.to_dict(), 200)
            else:
                return make_response({"error": "User not found"}, 404)

        return make_response({"error": "No active session"}, 401)


class Login(Resource):
    def post(self):
        data = request.get_json()

        # Validate username and password presence
        if 'username' not in data or 'password' not in data:
            return make_response({"error": "Username and password are required"}, 400)

        user = User.query.filter_by(username=data['username']).first()

        if user and user.check_password(data['password']):
            session['user_id'] = user.id
            return make_response(user.to_dict(), 200)
        else:
            return make_response({"error": "Invalid username or password"}, 401)


class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id', None)  # Clear the session
            return make_response({}, 204)  # Successfully logged out
        return make_response({"error": "No active session"}, 401)


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return make_response([recipe.to_dict() for recipe in recipes], 200)

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        data = request.get_json()

        if not data.get('title') or not data.get('instructions') or not data.get('minutes_to_complete'):
            return make_response({"error": "Missing fields in recipe data"}, 400)

        if len(data['instructions']) < 50:
            return make_response({"error": "Instructions must be at least 50 characters long"}, 422)

        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id  # Associate the recipe with the logged-in user
            )
            db.session.add(new_recipe)
            db.session.commit()

            return make_response(new_recipe.to_dict(), 201)

        except IntegrityError:
            db.session.rollback()
            return make_response({"error": "Failed to add recipe"}, 422)


# Register API routes
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)