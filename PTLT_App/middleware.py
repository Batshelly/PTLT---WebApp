from django.shortcuts import redirect

class SessionExpiredMiddleware:
    """
    Middleware to detect session expiration and redirect to login with a message.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if user was authenticated but session is now empty
        if request.user.is_authenticated:
            # If user is marked as authenticated but session is empty, session expired
            if not request.session.session_key:
                return redirect('/?session_expired=true')
        
        response = self.get_response(request)
        return response
