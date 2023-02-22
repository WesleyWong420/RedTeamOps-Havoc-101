using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace RatKing
{
    public static class CommandLineArgumentParser
    {
        public static ParsedOptionsResult<T> Parse<T>(string[] args) where T : class
        {
            var arguments = MapArgumentsToParameters(args);

            var options = CreateInstance<T>(arguments);

            var optionParameterProperties = AllPropertiesWithOptionsAttributeDefined(options);

            SetDefaultValues(optionParameterProperties, options);

            var matchedProperties = new List<PropertyInfo>();

            foreach (var arg in arguments.Skip(1))
            {
                var property = FindMatchingProperty(optionParameterProperties, options, arg.Key);

                if (property == null)
                {
                    continue;
                }

                matchedProperties.Add(property);

                var value = arguments[arg.Key];

                if (!value.Any())
                {
                    if (typeof(bool).IsAssignableFrom(property.PropertyType))
                    {
                        property.SetValue(options, true, null);
                    }

                    continue;
                }

                try
                {
                    SetPropertyValue(property, options, value);
                }
                catch (Exception)
                {
                    return CreateParseExceptionResult<T>(property);
                }
            }

            return CreateResult(options, optionParameterProperties, matchedProperties);
        }

        /// <summary>
        /// Maps the raw 'args' to dictionary of parameters with zero or more properties,
        /// e.g.
        /// --arg1 val1 --arg2 val2a val2b
        /// becomes
        /// { "arg1", ["val1"] },
        /// { "arg2", ["val2a", "val2b"] }
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        private static Dictionary<string, List<string>> MapArgumentsToParameters(IEnumerable<string> args)
        {
            var argumentsDictionary = new Dictionary<string, List<string>>();
            var currentArgument = VerbMarker;
            argumentsDictionary.Add(currentArgument, new List<string>());

            foreach (var argument in args)
            {
                if (IsSwitch(argument))
                {
                    var argParams = new List<string>();
                    currentArgument = argument.TrimStart('-');
                    argumentsDictionary.Add(currentArgument, argParams);
                }
                else
                {
                    var par = argumentsDictionary[currentArgument];
                    par.Add(argument);
                }
            }

            return argumentsDictionary;
        }

        private static bool IsSwitch(string argument)
        {
            if (argument.StartsWith("--"))
            {
                return true;
            }

            return argument.StartsWith("-") && char.IsLetter(argument[1]);
        }

        private const string VerbMarker = ":verb";

        /// <summary>
        /// Creates an instance of T if there is no verb argument, and tries to
        /// find and create an instance of a class with the same name as T, but with the
        /// verb as a prefix.
        /// <example>
        /// If T is StringOptions and the verb is "create", then if a class called CreateStringOptions
        /// will be instantiated and returned. If it isn't found, the fallback is to create T.</example>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="arguments"></param>
        /// <returns></returns>
        private static T CreateInstance<T>(Dictionary<string, List<string>> arguments)
        {
            if (arguments[VerbMarker].Count == 0)
            {
                return Activator.CreateInstance<T>();
            }
            else
            {
                var verbClassName = $"{arguments[VerbMarker][0]}{typeof(T).Name}";

                foreach (var type in Assembly.GetAssembly(typeof(T)).GetTypes()
                        .Where(myType => myType.IsClass && myType.IsSubclassOf(typeof(T))))
                {
                    if (string.Equals(verbClassName, type.Name, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return (T)Activator.CreateInstance(type);
                    }
                }

                return Activator.CreateInstance<T>();
            }
        }

        private static List<PropertyInfo> AllPropertiesWithOptionsAttributeDefined(object options)
        {
            return options.GetType().GetProperties().Where(
                prop => Attribute.IsDefined(prop, typeof(OptionParameterAttribute))).ToList();
        }

        private static void SetDefaultValues(List<PropertyInfo> optionParameterProperties, object options)
        {
            foreach (var property in optionParameterProperties)
            {
                SetDefaultValueForProperty(property, options);
            }
        }

        private static PropertyInfo FindMatchingProperty(List<PropertyInfo> optionParameterProperties, object options, string arg)
        {
            if (optionParameterProperties.Any())
            {
                return optionParameterProperties.FirstOrDefault(o => PropertyAttributeMatchesArgument(o, arg));
            }

            // if class has no OptionParameterAttributes, find property with matching name
            return options.GetType().GetProperties().FirstOrDefault(p =>
                string.Equals(p.Name, arg, StringComparison.InvariantCultureIgnoreCase));
        }

        private static bool PropertyAttributeMatchesArgument(PropertyInfo propertyInfo, string argument)
        {
            var attribute = GetAttributeForProperty(propertyInfo);

            if (string.Equals(argument, attribute.ShortName.ToString(), StringComparison.InvariantCultureIgnoreCase))
            {
                return true;
            }

            if (string.Equals(argument, attribute.LongName, StringComparison.InvariantCultureIgnoreCase))
            {
                return true;
            }

            if (string.Equals(argument, propertyInfo.Name, StringComparison.InvariantCultureIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private static void SetDefaultValueForProperty(PropertyInfo property, object options)
        {
            var attribute = GetAttributeForProperty(property);

            if (attribute.DefaultValue == null)
            {
                return;
            }

            if (attribute.DefaultValue.GetType() != property.PropertyType)
            {
                throw new ArgumentException($"Property expected type {property.PropertyType.Name} but OptionParameterAttribute DefaultValue was of type {attribute.DefaultValue.GetType().Name}.");
            }

            property.SetValue(options, attribute.DefaultValue, null);
        }

        private static OptionParameterAttribute GetAttributeForProperty(PropertyInfo property)
        {
            var customAttributes = property.GetCustomAttributes(true);
            var attribute = (OptionParameterAttribute)customAttributes[0];

            return attribute;
        }

        private static void SetPropertyValue(PropertyInfo property, object options, List<string> value)
        {
            if (property.PropertyType == typeof(string))
            {
                property.SetValue(options, value[0], null);
            }
            else if (property.PropertyType.IsArray)
            {
                var elementType = property.PropertyType.GetElementType();

                var array = Array.CreateInstance(elementType, value.Count);

                for (var index = 0; index < value.Count; index++)
                {
                    var val = value[index];
                    var convertedValue = Convert.ChangeType(val, elementType);
                    array.SetValue(convertedValue, index);
                }

                property.SetValue(options, array, null);
            }
            else
            {
                var convertedValue = Convert.ChangeType(value[0], property.PropertyType);

                property.SetValue(options, convertedValue, null);
            }
        }

        private static ParsedOptionsResult<T> CreateParseExceptionResult<T>(PropertyInfo exceptionProperty) where T : class
        {
            var parsedResult = new ParsedOptionsResult<T>();

            parsedResult.ParsedOptions = null;
            parsedResult.Result = OptionsResult.ParsingException;

            var attribute = GetAttributeForProperty(exceptionProperty);

            parsedResult.ExceptionParameter = string.IsNullOrEmpty(attribute.LongName)
                ? exceptionProperty.Name.ToLowerInvariant()
                : attribute.LongName;

            return parsedResult;
        }

        private static ParsedOptionsResult<T> CreateResult<T>(T options,
            List<PropertyInfo> optionParameterProperties, List<PropertyInfo> matchedProperties) where T : class
        {
            var parsedResult = new ParsedOptionsResult<T>();

            parsedResult.ParsedOptions = options;

            var missingRequiredOptions = FindUnsetRequiredOptions(optionParameterProperties, matchedProperties);

            parsedResult.MissingRequiredOptions = missingRequiredOptions;

            parsedResult.Result = missingRequiredOptions.Any()
                ? OptionsResult.MissingRequiredArgument
                : OptionsResult.Success;

            return parsedResult;
        }

        private static List<string> FindUnsetRequiredOptions(List<PropertyInfo> optionParameterProperties, List<PropertyInfo> matchedProperties)
        {
            var list = new List<string>();

            foreach (var requiredProperty in optionParameterProperties.Where(o => GetAttributeForProperty(o).IsRequired)
                .Except(matchedProperties))
            {
                var attribute = GetAttributeForProperty(requiredProperty);
                if (string.IsNullOrEmpty(attribute.LongName))
                {
                    list.Add(requiredProperty.Name.ToLowerInvariant());
                }
                else
                {
                    list.Add(attribute.LongName);
                }
            }

            return list;
        }
    }

    public class ParsedOptionsResult<T>
    {
        internal ParsedOptionsResult()
        {
        }

        public T ParsedOptions { get; internal set; }

        public OptionsResult Result { get; internal set; }

        public List<string> MissingRequiredOptions { get; internal set; }

        public string ExceptionParameter { get; internal set; }
    }

    [AttributeUsage(AttributeTargets.Property)]
    public class OptionParameterAttribute : Attribute
    {
        public OptionParameterAttribute(string parameterName = "", bool required = false)
        {
            LongName = parameterName;
            IsRequired = required;
        }

        public string LongName { get; set; }

        public char ShortName { get; set; }

        public bool IsRequired { get; set; }

        public object DefaultValue { get; set; }
    }

    public enum OptionsResult
    {
        Success,
        MissingRequiredArgument,
        ParsingException
    }
}