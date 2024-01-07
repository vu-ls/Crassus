using System;
using System.Runtime.Serialization;

namespace Crassus.Crassus.Exceptions
{
    /// <summary>
    ///     Exception thrown when a misconfiguration of Crassus
    ///     caused any issues.
    /// </summary>
    [Serializable]
    public class ConfigurationException : Exception
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ConfigurationException"/> class.
        /// </summary>
        public ConfigurationException() : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ConfigurationException"/> class with a specified error message.
        /// </summary>
        public ConfigurationException(string message) : base(message)
        {
        }
        /// <summary>
        /// Initializes a new instance of <see cref="ConfigurationException"/> class with a specified error message
        /// and a reference to the inner exception message that is the cause of this exception.
        /// </summary>
        public ConfigurationException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ConfigurationException"/> class with a serialized data.
        /// </summary>
        protected ConfigurationException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}