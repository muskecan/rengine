import uuid
from dashboard.models import UserPreferences

class UserPreferencesMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		if request.user.is_authenticated:
			request.user_preferences, created = UserPreferences.objects.get_or_create(user=request.user)
			# Auto-generate unique ntfy topic if not set
			if created or not request.user_preferences.ntfy_topic:
				request.user_preferences.ntfy_topic = f"rengine-{uuid.uuid4().hex[:8]}"
				request.user_preferences.save()
		return self.get_response(request)
