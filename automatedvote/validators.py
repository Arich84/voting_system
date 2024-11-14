from django.core.exceptions import ValidationError
import re

class SpecialCharacterValidator:
  def validate(self,password, user=None):
      if not re.findall(r'[!@#&*^(),.?"./;:{}|]',password):
          raise ValidationError(
              "Password must contain at least one special character"
          )
          
      if not re.findall(r'\d',password):
          raise ValidationError(
              "Password must contain at least one digit"
          )
          
      if not re.findall(r'[A-Z]',password):
          raise ValidationError(
              "Password must contain at least one uppercase letter "
          )
          
  def get_help_text(self):
      return "Your password must contain at least one special character, one digit,one uppercase letter."
      