using System;
using System.Runtime.Serialization;

namespace Crassus.Crassus.Exceptions
{
    /// <summary>
    ///     Exception thrown when a parameter passed to Crassus
    ///     command line caused any issues.
    /// </summary>
    [Serializable]
    public class CommandLineException : Exception
    {
        /// <summary>
        /// Initializes a new instance of <see cref="CommandLineException"/> class.
        /// </summary>
        public CommandLineException()
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="CommandLineException"/> class with a specified error message.
        /// </summary>
        public CommandLineException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="CommandLineException"/> class with a specified error message
        /// and a reference to the inner exception message that is the cause of this exception.
        /// </summary>
        public CommandLineException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="CommandLineException"/> class with a serialized data.
        /// </summary>
        protected CommandLineException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}