using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApiUsuarios.Infra.RabbitMQ.Settings
{
    public class RabbitMQSettings
    {
        /// <summary>
        /// Endereço para conexão no servidor de mensageria
        /// </summary>
        public static string? ConnectionString 
        { 
            get => @"amqps://qturmdzu:WyUl3HO0CeTvLefKP8uSSlxLbP8a8RcR@woodpecker.rmq.cloudamqp.com/qturmdzu"; 
        }

        /// <summary>
        /// Nome da fila em que iremos conectar a aplicação
        /// </summary>
        public static string? QueueName 
        {
            get => "recuperacao_de_senha";
        }
    }
}
