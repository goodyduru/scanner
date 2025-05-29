from django.core import checks, exceptions
from django.db import models
from django.utils.translation import ngettext_lazy

# Derived from https://github.com/openfun/richie/blob/8fcc6a380db5edfd774f7f8cac63f8d47f931e72/src/richie/apps/core/fields/multiselect.py#L61C1-L269C61
class MultiSelectField(models.CharField):
    """
    A custom database field to store a list of string values.
    This is an alternative to Django's ArrayField that is compatible with sqlite.
    The array of values is stored in a comma separated string.
    """

    description = "Multi select field"

    error_message = ngettext_lazy(
        "Value %(value)s is not a valid choice.",
        "Values %(value)s are not valid choices.",
        "number",
    )

    def __init__(self, *args, **kwargs):
        """
        We only need the max length option
        """
        super().__init__(*args, **kwargs)
        self.max_length = kwargs.pop("max_length", None)

    def deconstruct(self):
        """Return enough information to recreate the field as a 4-tuple."""
        name, path, args, kwargs = super().deconstruct()
        return name, path, args, kwargs

    def _check_choices(self):
        """Make the `choices` parameter required."""
        if not self.choices:
            return [
                checks.Error(
                    "MultiSelectFields must define a 'choices' attribute.",
                    obj=self,
                    id="fields.E1001",
                )
            ]
        return super()._check_choices()
    
    def check(self, **kwargs):
        return super().check(**kwargs)

    @staticmethod
    def from_db_value(value, *_args):
        """Convert a database value to a list value."""
        if not value:
            return None if value is None else []
        return list((v.strip() for v in value.split(",")))

    def to_python(self, value):
        """Convert a string value to a list value. Used for deserialization and in clean forms."""
        if not isinstance(value, str) and hasattr(value, "__iter__"):
            return list(value)
        if not value:
            return None if value is None else []
        return list((v.strip() for v in value.split(",")))

    def get_prep_value(self, value):
        """
        Transform the list value to a concatenation of comma separated strings.

        Arguments:
        ----------
        value (List[string]): a list of strings representing the Python representation
            of multiple Char values.

        Returns:
        --------
        string:
            [] > "" (to differentiate from the null value)
            ["critical"] > "critical"
            ["high", "critical"] > "high,critical"

        """
        if value is None or len(value) == 0:
            return None
        return ",".join(value)

    def value_to_string(self, obj):
        """Serialize the Python value. We can use existing methods as it is a CharField."""
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

    def validate(self, value, model_instance):
        """
        Validate each value in values and raise a ValidationError if something is wrong.
        """
        if not self.editable:
            # Skip validation for non-editable fields.
            return

        if self.choices and value:
            # Build a set of possible choices
            choices = set()
            for option_key, option_value in self.choices:
                if isinstance(option_value, (list, tuple)):
                    # This is an optgroup, so look inside the group for
                    # options.
                    for optgroup_key, _optgroup_value in option_value:
                        choices.add(optgroup_key)
                else:
                    choices.add(option_key)

            # Search each value in this set
            invalid_choices = [v for v in value if v not in choices]
            if invalid_choices:
                raise exceptions.ValidationError(
                    self.error_message,
                    code="invalid_choices",
                    params={
                        "number": len(invalid_choices),
                        "value": ", ".join(invalid_choices),
                    },
                )

        if value is None and not self.null:
            raise exceptions.ValidationError(self.error_messages["null"], code="null")

        if not self.blank and not value:
            raise exceptions.ValidationError(self.error_messages["blank"], code="blank")

