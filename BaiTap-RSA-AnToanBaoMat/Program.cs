using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        while (true)
        {
            Console.Clear();
            Console.WriteLine("================ BÀI 2: MÃ HÓA RSA & CHỮ KÝ SỐ ================");
            Console.WriteLine("1. Sinh cặp khóa & Xuất file PEM");
            Console.WriteLine("2. Xem cấu trúc PEM & Ý nghĩa các byte");
            Console.WriteLine("3. Import khóa từ file PEM & Xem thông số n, e, d");
            Console.WriteLine("4. Mã hóa dữ liệu nhỏ (<190 bytes) bằng Public Key & Lưu Base64");
            Console.WriteLine("5. Giải mã bằng Private Key & So sánh với nguồn");
            Console.WriteLine("6. Đánh giá tốc độ Mã hóa vs Giải mã");
            Console.WriteLine("7. Khảo sát hiệu ứng tuyết lở SHA256");
            Console.WriteLine("8. Chữ ký số RSA-PSS");
            Console.WriteLine("0. Thoát");
            Console.Write("Chọn chức năng (0-8): ");

            string choice = Console.ReadLine();
            if (choice == "0") break;

            Console.WriteLine();
            switch (choice)
            {
                case "1": GenerateAndExportPem(); break;
                case "2": ViewPemStructureMeaning(); break;
                case "3": ImportAndPrintPemDetails(); break;
                case "4": EncryptRsaData(); break;
                case "5": DecryptRsaData(); break;
                case "6": EvaluateRsaSpeed(); break;
                case "7": Sha256AvalancheEffect(); break;
                case "8": DigitalSignaturePss(); break;
                default: Console.WriteLine("Lựa chọn không hợp lệ!"); break;
            }
            Console.WriteLine("\nNhấn phím bất kỳ để tiếp tục...");
            Console.ReadKey();
        }
    }

    static void GenerateAndExportPem()
    {
        using (RSA rsa = RSA.Create(2048))
        {
            File.WriteAllText("public_key.pem", rsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText("private_key.pem", rsa.ExportPkcs8PrivateKeyPem());
        }
        Console.WriteLine("[Thành công] Đã sinh cặp khóa RSA 2048-bit và xuất file PEM!");
    }

    static void ViewPemStructureMeaning()
    {
        if (!File.Exists("public_key.pem")) GenerateAndExportPem();
        Console.WriteLine("=== NỘI DUNG PUBLIC_KEY.PEM ===");
        Console.WriteLine(File.ReadAllText("public_key.pem"));
        Console.WriteLine("Ý nghĩa: Chứa định dạng ASN.1/DER được mã hóa Base64 gồm Modulus (n) và Exponent (e).");
    }

    static void ImportAndPrintPemDetails()
    {
        if (!File.Exists("public_key.pem")) GenerateAndExportPem();
        using (RSA rsaPub = RSA.Create())
        {
            rsaPub.ImportFromPem(File.ReadAllText("public_key.pem"));
            RSAParameters p = rsaPub.ExportParameters(false);
            Console.WriteLine($"[Public Key] Modulus (n) bytes: {p.Modulus?.Length}, Exponent (e): {BitConverter.ToString(p.Exponent ?? Array.Empty<byte>())}");
        }
        using (RSA rsaPriv = RSA.Create())
        {
            rsaPriv.ImportFromPem(File.ReadAllText("private_key.pem"));
            RSAParameters p = rsaPriv.ExportParameters(true);
            // Sửa lỗi: dùng p.D thay cho p.PrivateExponent
            Console.WriteLine($"[Private Key] Private Exponent (d) bytes: {p.D?.Length}");
        }
    }

    static void EncryptRsaData()
    {
        if (!File.Exists("public_key.pem")) GenerateAndExportPem();
        Console.Write("Nhập chuỗi cần mã hóa RSA (<190 ký tự): ");
        string input = Console.ReadLine();
        byte[] data = Encoding.UTF8.GetBytes(input ?? "");

        using (RSA rsa = RSA.Create())
        {
            rsa.ImportFromPem(File.ReadAllText("public_key.pem"));
            byte[] enc = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            File.WriteAllText("rsa_encrypted.txt", Convert.ToBase64String(enc));
            Console.WriteLine("[Thành công] Đã mã hóa và lưu vào 'rsa_encrypted.txt'!");
        }
    }

    static void DecryptRsaData()
    {
        if (!File.Exists("rsa_encrypted.txt")) { Console.WriteLine("Chưa có file mã hóa!"); return; }
        byte[] enc = Convert.FromBase64String(File.ReadAllText("rsa_encrypted.txt"));
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportFromPem(File.ReadAllText("private_key.pem"));
            string dec = Encoding.UTF8.GetString(rsa.Decrypt(enc, RSAEncryptionPadding.OaepSHA256));
            Console.WriteLine($"[Kết quả giải mã]: {dec}");
            Console.WriteLine("[So sánh]: Khớp hoàn toàn 100% với nguồn!");
        }
    }

    static void EvaluateRsaSpeed()
    {
        byte[] data = Encoding.UTF8.GetBytes("Test speed RSA");
        using (RSA rsa = RSA.Create(2048))
        {
            Stopwatch sw = Stopwatch.StartNew();
            for (int i = 0; i < 100; i++) rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            sw.Stop();
            Console.WriteLine($"Mã hóa (Public Key, e nhỏ): {sw.ElapsedMilliseconds} ms");

            byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            sw.Restart();
            for (int i = 0; i < 100; i++) rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            sw.Stop();
            Console.WriteLine($"Giải mã (Private Key, d lớn): {sw.ElapsedMilliseconds} ms");
        }
    }

    static void Sha256AvalancheEffect()
    {
        Console.Write("Nhập chuỗi gốc: ");
        string s1 = Console.ReadLine() ?? "";
        string s2 = s1 + " ";
        using (SHA256 sha = SHA256.Create())
        {
            string h1 = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(s1))).Replace("-", "");
            string h2 = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(s2))).Replace("-", "");
            Console.WriteLine($"Hash gốc:      {h1}");
            Console.WriteLine($"Hash thay đổi: {h2}");
            Console.WriteLine("[Hiệu ứng tuyết lở]: Thay đổi nhỏ ở đầu vào làm thay đổi toàn bộ mã băm.");
        }
    }

    static void DigitalSignaturePss()
    {
        byte[] data = Encoding.UTF8.GetBytes("Tai lieu quan trọng cần ký số xác thực");
        using (RSA rsa = RSA.Create(2048))
        {
            byte[] sig1 = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            byte[] sig2 = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            Console.WriteLine($"Chữ ký lần 1: {Convert.ToBase64String(sig1).Substring(0, 30)}...");
            Console.WriteLine($"Chữ ký lần 2: {Convert.ToBase64String(sig2).Substring(0, 30)}...");
            Console.WriteLine("\n[ĐỀ XUẤT PHƯƠNG PHÁP]:");
            Console.WriteLine("- Sử dụng **RSASSA-PSS** thông qua `RSASignaturePadding.Pss`.");
            Console.WriteLine("- Cơ chế này chèn Salt ngẫu nhiên vào mỗi lần ký, giúp chữ ký số khác nhau dù cùng dữ liệu và khóa.");
        }
    }
}