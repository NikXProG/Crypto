using Crypto.Core;
using Crypto.Core.Interfaces;
using Crypto.Symmetrical.Algorithms;

namespace Crypto.Symmetrical.Builders
{
    
    public class DesBuilder
    {
        private readonly SymmetricalParamsBuilder _symmetricalParamsBuilder;
        private FeistelNetSize _delBlockSize = FeistelNetSize.Classic;
        private int _roundsCount = 16;
        
        public DesBuilder()
        {
           _symmetricalParamsBuilder = new SymmetricalParamsBuilder();
        }
    
        public DesBuilder WithFeistelSize(FeistelNetSize feistelNetSize)
        {
            _delBlockSize = feistelNetSize;
            return this;
        }

        public DesBuilder WithRoundsCount(int roundsCount)
        {
            _roundsCount = roundsCount;
            return this;
        }
    
        public DesBuilder WithSymmetricalParams(Action<SymmetricalParamsBuilder> action)
        {
            action(_symmetricalParamsBuilder);
            return this;
        }
    
        public ISymmetrical Build()
        {
            return new Des(
                _symmetricalParamsBuilder.Build(),
                _delBlockSize,
                _roundsCount);
        }
        
    }
}