using System;
using System.Threading;
using System.Threading.Tasks;

namespace CEMCP
{
    /// <summary>
    /// Serializes access to Cheat Engine / CESDK Lua state.
    /// The underlying Lua stack is global and not safe for concurrent callers.
    /// </summary>
    public static class CeLuaGate
    {
        private static readonly SemaphoreSlim Gate = new(1, 1);

        public static void Run(Action action)
        {
            Gate.Wait();
            try
            {
                CESDK.Classes.CEObjectWrapper.ProcessDeferredDisposals();
                action();
            }
            finally
            {
                Gate.Release();
            }
        }

        public static T Run<T>(Func<T> func)
        {
            Gate.Wait();
            try
            {
                CESDK.Classes.CEObjectWrapper.ProcessDeferredDisposals();
                return func();
            }
            finally
            {
                Gate.Release();
            }
        }

        public static async Task RunAsync(Action action)
        {
            await Gate.WaitAsync();
            try
            {
                CESDK.Classes.CEObjectWrapper.ProcessDeferredDisposals();
                action();
            }
            finally
            {
                Gate.Release();
            }
        }

        public static async Task<T> RunAsync<T>(Func<T> func)
        {
            await Gate.WaitAsync();
            try
            {
                CESDK.Classes.CEObjectWrapper.ProcessDeferredDisposals();
                return func();
            }
            finally
            {
                Gate.Release();
            }
        }
    }
}
