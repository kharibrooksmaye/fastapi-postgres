import stripe

from app.core.settings import settings

stripe.api_key = settings.stripe_api_key

def create_stripe_payment_intent(amount: float, currency: str = "usd", metadata: dict = None, user_id: int = None):
    try:
        if user_id:
            # Create or retrieve a Stripe Customer for the user
            customer = stripe.Customer.create(metadata={"user_id": str(user_id)})
            stripe_user_id = customer.id
        intent = stripe.PaymentIntent.create(
            amount=int(amount * 100),  # amount in cents
            currency=currency,
            metadata=metadata or {},
            customer=stripe_user_id if stripe_user_id else None,
        )
        return intent
    except stripe.StripeError as e:
        # Handle Stripe errors appropriately
        raise Exception(f"Stripe error: {e.user_message}")
    
def retrieve_stripe_payment_intent(intent_id: str):
    try:
        intent = stripe.PaymentIntent.retrieve(intent_id)
        return intent
    except stripe.error.StripeError as e:
        # Handle Stripe errors appropriately
        raise Exception(f"Stripe error: {e.user_message}")