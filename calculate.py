import redis
import json


def get_redis_connection(host, port, db):
    """ Create a redis connection
        :params host: ip address to redis server
        :params port: port number of redis service
        :params db: specify which redis db to use
    """
    return redis.Redis(host=host, port=port, db=db)


def calculate_statistic(redis_connection):
    result = redis_connection.lrange("result", 0, -1)
    hop_distance = 0.0
    hop_distance_error = 0
    hop_distance_distri = dict()

    for record in result:
        record = json.loads(record.decode())
        hop_dis = record["hop_distance"]
        if hop_dis in hop_distance_distri:
            hop_distance_distri[hop_dis] += 1
        else:
            hop_distance_distri[hop_dis] = 0

        if hop_dis > 0:
            hop_distance += hop_dis
        else:
            hop_distance_error += 1

    for i in hop_distance_distri:
        print("{}\t{}".format(i, hop_distance_distri[i]))

    print("AVG Hop Distance: {}".format(hop_distance/len(result)))
    print("Abnormal Hop Distance: {}".format(hop_distance_error))
    print(hop_distance_distri)




if __name__ == "__main__":
    redis_connection = get_redis_connection("127.0.0.1", 6379, 2)
    calculate_statistic(redis_connection)
