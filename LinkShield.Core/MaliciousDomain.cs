using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace LinkShield.Core;

/// <summary>
/// Represents a single malicious domain entry in the local threat database.
/// </summary>
[Index(nameof(Domain), IsUnique = true)]
public class MaliciousDomain
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    /// <summary>
    /// The malicious domain string (e.g., "evil-phishing.com").
    /// Indexed for O(log n) lookups.
    /// </summary>
    [Required]
    [MaxLength(512)]
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    /// UTC timestamp when this domain was first added to the local cache.
    /// </summary>
    public DateTime AddedAtUtc { get; set; } = DateTime.UtcNow;
}
