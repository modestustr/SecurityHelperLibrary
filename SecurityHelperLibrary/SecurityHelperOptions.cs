namespace SecurityHelperLibrary
{
    public sealed class SecurityHelperOptions
    {
        public int Argon2DefaultIterations { get; set; } = 4;
        public int Argon2DefaultMemoryKb { get; set; } = 131072;
        public int Argon2DefaultDegreeOfParallelism { get; set; } = 4;
        public int Argon2DefaultHashLength { get; set; } = 32;
    }
}
