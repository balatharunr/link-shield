using System.Threading.Tasks;

namespace LinkShield.Core;

public interface IUrlAnalyzer
{
    Task<bool> IsMaliciousAsync(string url);
}
