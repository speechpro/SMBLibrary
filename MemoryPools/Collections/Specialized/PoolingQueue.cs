﻿using System;
using System.Runtime.CompilerServices;

namespace MemoryPools.Collections.Specialized
{
	public abstract class PoolingQueue<T> : IDisposable
	{
		private IPoolingNode<T> _enqueueTo;
		private IPoolingNode<T> _dequeueFrom;
		private int _enqueueIndex, _dequeueIndex;

		protected PoolingQueue()
		{
			Count = 0;
			_enqueueIndex = 0;
			_dequeueIndex = 0;
			_enqueueTo = _dequeueFrom = null;
		}

		public bool IsEmpty => Count == 0;

		public int Count { get; private set; }

		public void Dispose()
		{
			Clear();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Enqueue(T obj)
		{
			if (Count == 0 && _enqueueTo == null)
				_enqueueTo = _dequeueFrom = CreateNodeHolder();
      

			// don't change pool state before this line
			if (_enqueueIndex + 1 == PoolsDefaults.DefaultPoolBucketSize)
			{
				// Here we can get recursive call through CountdownMemoryOwner allocation from pool.
				// So state (_enqueueIndex + 1) == PoolsDefaults.DefaultPoolBucketSize can be changed
				var result = CreateNodeHolder();

				// if condition still works
				if ((_enqueueIndex + 1) == PoolsDefaults.DefaultPoolBucketSize)
				{
					_enqueueTo[_enqueueIndex] = obj;
					var enqueue = _enqueueTo;
					enqueue.Next = result;
					_enqueueTo = result;
					_enqueueIndex = 0;
					Count++;
					return;
				}
				else
				{
					// shit happens
					result.Dispose();
				}
			}

			_enqueueTo[_enqueueIndex] = obj;
			_enqueueIndex++;
			Count++;
		}

		protected abstract IPoolingNode<T> CreateNodeHolder();

		/// <summary>
		///     Tries to return queue element if any available via `val` parameter.
		/// </summary>
		/// <returns>
		///     true if element found or false otherwise
		/// </returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool TryDequeue(out T val)
		{
			if (IsEmpty)
			{
				val = default;
				return false;
			}

			val = Dequeue();
			return true;
		}

		/// <summary>
		///     Returns queue element
		/// </summary>
		/// <returns>
		///     Returns element or throws IndexOutOfRangeException if no element found
		/// </returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public T Dequeue()
		{
			if (IsEmpty) throw new IndexOutOfRangeException();

			var obj = _dequeueFrom[_dequeueIndex];
			_dequeueFrom[_dequeueIndex] = default;

			_dequeueIndex++;
			Count--;

			if (_dequeueIndex == PoolsDefaults.DefaultPoolBucketSize)
			{
				var dequeue = _dequeueFrom;
				_dequeueFrom = _dequeueFrom.Next;
				_dequeueIndex = 0;
				dequeue.Dispose();
			}

			if (Count == 0)
			{
				// return back to pool
				if (_enqueueTo != _dequeueFrom)
				{
					var empty = _dequeueFrom;
					_dequeueFrom = _dequeueFrom.Next;
					_dequeueIndex = 0;
					empty.Dispose();
				}
				else
					// reset to pool start
				{
					_enqueueIndex = 0;
					_dequeueIndex = 0;
				}
			}

			return obj;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Clear()
		{
			while (_enqueueTo != null)
			{
				var next = _enqueueTo.Next;
				_enqueueTo.Dispose();
				_enqueueTo = next;
			}

			_dequeueFrom = null;
		}
	}
}