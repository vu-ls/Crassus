using System;
using System.Runtime.Serialization;

namespace Crassus.Crassus.Exceptions
{
    /// <summary>
    ///     Exception thrown when a file read by Crassus
    ///     is not in the required binary format.
    /// </summary>
    [Serializable]
    public class FileFormatException : Exception
    {
        /// <summary>
        /// Initializes a new instance of <see cref="FileFormatException"/> class.
        /// </summary>
        public FileFormatException() : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="FileFormatException"/> class with a specified error message.
        /// </summary>
        public FileFormatException(string message) : base(message)
        {
        }
        /// <summary>
        /// Initializes a new instance of <see cref="FileFormatException"/> class with a specified error message
        /// and a reference to the inner exception message that is the cause of this exception.
        /// </summary>
        public FileFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="FileFormatException"/> class with a serialized data.
        /// </summary>
        protected FileFormatException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}