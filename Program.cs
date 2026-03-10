using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

class Socks5Proxy
{
    class User
    {
        public string Password;
        public DateTime Expire;
        public int CurrentConnections = 0;
        public long Traffic = 0; // байты
        public bool IsAdmin = false;
    }

    static ConcurrentDictionary<string, User> users = new ConcurrentDictionary<string, User>();

    static int MAX_CONNECTIONS_TOTAL = 50;
    static int currentConnectionsTotal = 0;

    static async Task Main()
    {
        // Добавляем админа, который не имеет ограничений
        users.TryAdd("admin", new User { Password = "12345", IsAdmin = true, Expire = DateTime.MaxValue });

        TcpListener listener = new TcpListener(IPAddress.Any, 1080);
        listener.Start();
        Console.WriteLine("SOCKS5 Proxy started on port 1080");

        _ = Task.Run(ConsoleCommands);

        while (true)
        {
            TcpClient client = await listener.AcceptTcpClientAsync();

            if (currentConnectionsTotal >= MAX_CONNECTIONS_TOTAL)
            {
                client.Close();
                continue;
            }

            Interlocked.Increment(ref currentConnectionsTotal);
            _ = HandleClient(client);
        }
    }

    static async Task ConsoleCommands()
    {
        while (true)
        {
            string cmd = Console.ReadLine();

            if (cmd.StartsWith("add "))
            {
                string[] p = cmd.Split(' ');
                if (p.Length == 3)
                {
                    users[p[1]] = new User
                    {
                        Password = p[2],
                        Expire = DateTime.Now.AddHours(24) // подписка 24 часа
                    };
                    Console.WriteLine($"User added: {p[1]}");
                }
            }

            if (cmd.StartsWith("remove "))
            {
                string[] p = cmd.Split(' ');
                users.TryRemove(p[1], out _);
                Console.WriteLine($"User removed: {p[1]}");
            }

            if (cmd == "list")
            {
                Console.WriteLine("Users:");
                foreach (var u in users)
                {
                    string status = u.Value.IsAdmin ? "Admin" : $"Expire: {u.Value.Expire}, Connections: {u.Value.CurrentConnections}, Traffic: {u.Value.Traffic/1024}KB";
                    Console.WriteLine($"{u.Key} - {status}");
                }
            }
        }
    }

    static async Task HandleClient(TcpClient client)
    {
        NetworkStream clientStream = client.GetStream();
        User user = null;

        try
        {
            byte[] buffer = new byte[262];

            // handshake
            await clientStream.ReadAsync(buffer, 0, buffer.Length);
            await clientStream.WriteAsync(new byte[] { 0x05, 0x02 });

            // auth request
            int read = await clientStream.ReadAsync(buffer, 0, buffer.Length);

            int ulen = buffer[1];
            string username = Encoding.ASCII.GetString(buffer, 2, ulen);

            int plen = buffer[2 + ulen];
            string password = Encoding.ASCII.GetString(buffer, 3 + ulen, plen);

            if (!users.ContainsKey(username))
            {
                await clientStream.WriteAsync(new byte[] { 0x01, 0x01 });
                client.Close();
                return;
            }

            user = users[username];

            if (user.Password != password)
            {
                await clientStream.WriteAsync(new byte[] { 0x01, 0x01 });
                client.Close();
                return;
            }

            // Проверяем подписку и лимит
            if (!user.IsAdmin)
            {
                if (DateTime.Now > user.Expire)
                {
                    client.Close();
                    return;
                }

                if (user.CurrentConnections >= 3)
                {
                    client.Close();
                    return;
                }

                Interlocked.Increment(ref user.CurrentConnections);
            }

            await clientStream.WriteAsync(new byte[] { 0x01, 0x00 });

            // читаем запрос на подключение к удалённому серверу
            await clientStream.ReadAsync(buffer, 0, buffer.Length);

            string host = "";
            int port = 0;

            if (buffer[3] == 0x01) // IPv4
            {
                host = new IPAddress(new byte[] { buffer[4], buffer[5], buffer[6], buffer[7] }).ToString();
                port = (buffer[8] << 8) | buffer[9];
            }
            else if (buffer[3] == 0x03) // домен
            {
                int length = buffer[4];
                host = Encoding.ASCII.GetString(buffer, 5, length);
                port = (buffer[5 + length] << 8) | buffer[6 + length];
            }

            TcpClient remote = new TcpClient();
            await remote.ConnectAsync(host, port);
            NetworkStream remoteStream = remote.GetStream();

            byte[] response = new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
            await clientStream.WriteAsync(response, 0, response.Length);

            _ = Pipe(clientStream, remoteStream, user);
            _ = Pipe(remoteStream, clientStream, user);
        }
        catch { }

        client.Close();
        Interlocked.Decrement(ref currentConnectionsTotal);

        if (user != null && !user.IsAdmin)
            Interlocked.Decrement(ref user.CurrentConnections);
    }

    static async Task Pipe(NetworkStream input, NetworkStream output, User user)
    {
        byte[] buffer = new byte[8192];

        try
        {
            int bytes;
            while ((bytes = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                await output.WriteAsync(buffer, 0, bytes);

                if (!user.IsAdmin)
                    Interlocked.Add(ref user.Traffic, bytes);
            }
        }
        catch { }
    }
}
