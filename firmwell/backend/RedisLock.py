import redis
import time
import uuid
import os

class RedisLock:
	def __init__(self, lock_id="", name="", enable_redis_lock=False):
		self.redis_client = redis.StrictRedis(host='redis', port=6379, db=0)
		self.lock_id = lock_id
		# self.lock_value = str(uuid.uuid4())
		self.lock_value = name
		self.disable_redis = not enable_redis_lock # default is True

	def acquire(self, timeout=360):

		if self.disable_redis:
			return True
		else:
			end = time.time() + timeout
			while time.time() < end:
				if self.redis_client.set(self.lock_id, self.lock_value, nx=True, ex=360): # hold lock no longer than 360s
					return True
				time.sleep(0.5)
		return False

	def release(self):
		if self.disable_redis:
			return

		script = """
	        if redis.call("get",KEYS[1]) == ARGV[1] then
	            return redis.call("del",KEYS[1])
	        else
	            return 0
	        end
	        """
		self.redis_client.eval(script, 1, self.lock_id, self.lock_value)


if __name__ == '__main__':
	redis_client = redis.StrictRedis(host='redis', port=6379, db=0)
	lock = RedisLock("my_global_lock", name="redis_lock_test")
	lock.release()
	# exit(0)

	try:
		while True:
			start_time = time.time()
			if lock.acquire():
				try:
					curr_time = int(time.time() - start_time)
					print(f"Lock acquired")
					if curr_time > 0:
						print(f"Lock acquired: {curr_time}s") # Performing synchronized operations.
				finally:
					lock.release()
			else:
				print("Failed to acquire lock.")
	finally:
		lock.release()
