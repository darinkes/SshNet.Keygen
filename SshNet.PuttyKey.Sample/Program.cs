using System;
using System.IO;
using System.Reflection;
using Renci.SshNet;

// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMFKb9ssb3VHYh/R/vBx/0/nYrqUGqQibN7YaAo7PztZ ed25519-key-20210312
// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGNsY1vMX0acPcRtrShWKqdSpWKI5omJdMiCShnk++b ed25519-key-20210312
// ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCagnfkYmNXNlnVjIcIAWysh4JMApD9pefvRtVDJ+SbYX9/n+yZvYbonpgKF83vBI60/l5yJG81s5bZ78muEkkQ= ecdsa-key-20210312
// ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHhY99vQoPVT6F0PofvedF0lwEz0jx/b9eJTZWDdjWG3ElGV8OCoGjtSIFChASt9XXoHW4C9feuCnKJJLfmNcbA= ecdsa-key-20210312
// ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBEVWztj5M3PsCbbdwweE3eQjigjrlJz8dCZLvjpSulzc2ck6/s3oCaX7Pg/Sbvo2piAjduLWxsioowjJfsKz/nfaoaa9tfkOKf62aWISlOO1FfD9PbJtp3W2e06DTE1JTA== ecdsa-key-20210312
// ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMVJXj/SaVtmCpcQeDLIp5oyEEy8zzBS4uh2q/uZ3qkC6i20yErTR2wuWp+E/tRFvNK2m9kuvny+/eZzry62NNPhJdR7+dbbfCIGN9zoTe3UpSPj2MdmU1Frmbe3DJRshQ== ecdsa-key-20210312
// ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBADYWtDlG1mj5cUO6HTxIPXu/bWyNLJaVktlIWdivUX84gl/zjFKcLchQUG/jRgyiRBNAwxHT748GarGUwkAzB7KAgCfyjU0ux7egolYV5UAo/F9yXiQnPhudzvw9cImye5nOtW8Vq/2VlQSwe+vIFwuPGdV0/qeuPHS8tG3rPF6yB75dQ== ecdsa-key-20210312
// ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAIYjhprWSd0x4DLK3PWgh4ww16ZVYmv5PSBEeFBJCRcifXg+E7+Qex4s1vaPJWgqNfXjDgvf8/gnSON/460Yx66QE1Ib1C+hymE7NwfLg5tqfFHj32wj7uWkVktWupB940Q7X/S/UOPDI8ZpOOpUsC0+ZZIemHgGbAK0O4Ufn0yE6yVg== ecdsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAjfeoHlz1KHSwDhTSjnbeKSek/I/KjOSzViHeE7018KA4/UY91LTFHEc+vnkCWIYb2tvigZHusVlAg5QZHzBLN3XfJSH5iTtAPiM1D1m5Ir2iV2Fw1HHoRzPSx+ipacLbFvfePe9AUhPVzcmwq0uKPtZ8Tf1MJFHdyWofgaQr3WVZWm3wsxn59CqDhWQz9vdH5x3QOrEFrq0xfqFwR+KLkzmeuZBIoXK+2qfv/P4RrFhFgqZXNhdccADY8/zDsOQjpHu7yZQAgtfFILymSdWw3KkcPzr+Jiud3HEBAetuz2W4GpDEQk/PZ/+0UQZZt9vgKqx79Iv8/t8uAfTdgd/fkw== rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAl/v5jlT5CTLPJB8gGvcnfEMxQc8olDyZvoIDh/jdGYwGweGdDuLGQjyesadeqqPlv+zyzwQSZwK8UmPDzZz/nO6NPwvnlyNG1goySaNgCcYVkRhsyB0K2dXLAe+5Sccc+0rHtfetG5i2VzG/9UEJyRVLOFfEgatcH4OesbYEG84xFgH0I9DwcDgAiB2ac9Vt5lxkDHAowV61LMtDE/ZPV2bhRV9HvxGC/sXcKA3IbCGgyc2dihEYfDvt3RHq2krZiymPCyhYmTBxYpLLpNFevKoQtMZR7ujeWB4wE94QPqSU1gMahDnxONMFcTl7QQB1mqqsGZ2bFV0LPpbJ1D6d5w== rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAYEAldr4hr+lIwILyOT103TZ7+wrTFg3QObCGlBqtlwv/LuZitlPAc/swjVfzoZ7MfNxlKI/raiE5i077vQnqLRHTZsnas+8EFEgJmhdgxd5gxlTjHZDMH9RP4mQrWyIw+1nd5hF4olzWD9WdsArCZ9CNb9gTQiK68fRLEQcKrmwfijctecbfg5toLF344ojaghfDULBdLId9qIoeMLhvPfjZ3LEyPpYVTJ8TbOilkFSER+HyWg4RVrEJI9EI21XqkOZ3IyF253kTIdtMHQPKdSFxuEwJseDCcpAsCTUv/MRL3T5ZuLEqaKbwCA4ZPkc5srho85hdjRCnWakwGE7gU3r4LBsf+eIWHusj3jUhk65yvF3qJi4qFHNaZr2Pk9q+Ai7h6Ot5pE+cejmuGSxoQJBW+ekAbuMwtKfoSD5l1oywynZh3fbTkqzpLzJdm8veVrtSIwrvy/QzRmwgia90LJ9THQsFFW8PDPoTn2NqUeCjWua/lJjsPAIIlX32RNedi2Z rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAYEArVI7zzbTLTlYNEWXkCv4MtKklNYytnHwcCcGMKMQ+itf9q4AULLng9KqptDTuvFDekl/yWHaszXOJrB2cB263VuqybT2B1oCxMajyXVti4dIPV4Luz2txS4FEX8YqIXM0gfThtAwFI45XUdOEVpnnIH0ofbdGaoGAxMdGR4rPJRQdsQAla2zDYYx/apglTOUSsptaZU7ujzERutVxpZIxJXKf9TCNY5wPsrkN4ZY1KYuv1AB2iv+g4DgGSC1KFHw98nGSpBKIoAKv5MLIH/vCqCFTOzJSZR9qjHwN0SEjIs8mTjnPEtlMfo/X/O9XsuHYQY7zEFBE5iA6wAI5CtplgsLlg2Id8k/MADM9yFRk7rZiSjf77xKj80Hlc4joKtLT5mcqEmbUhIQ4CB5GMbbGezPzKTf0ICHw0yQtvEkaIB9QCjAQbtSr1ZAS8b+jmuxcOcCIcTNgnXZWXb37aYGf1lUM4afzPMuiQo5xRvpEC2xJFxV6k0/lx8t5JQSgDhH rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAgEArIKnfOxkOwdYah9O8q6humX4EfPoM840SadObrf0+32wawGjbbNLmhQtrKyeEJ7TQ/M0OAjmcS5B6PxGMHAOTHF6I1x/pkj9wAK6IJ7wmDm3NcPtRttonXHZgd6MugF6GrwzYuNbSa58vhSxIWh2gnONzRjbw6Im8HVMN8n2hgXt2UFsANUVMi4AosT46VZf4jeoN0JTWUAlTzwKdPJwoHax12+2CpmEiH0+DXpr2wYainpq4md9LizJEAAZ8ZyldtmvxHY8NpxPIJakGl6iNXNRz+UXcFh7tXSrYs6HTmqwQmkloBUTUrM6yafluC9cxf27vQSKx6ft7RB9gpgS2s6HAELtifuzbIeCQ3+KIL4r3csqA65MXUjh7L/i20FcuOz/aV+U+BuMKwvcipDis4XAmNzsnSq1/nSKj5ehTPyZ9D2hIZKUzw02dCqErHADx/BljtisBkKI8Savsy0uXgP/OPyfX3pm9gq6FYIg74g0q4fwUtrip6FuLr/TqKJkLLgPyA6tiH+fxdGH2hPa0To2EWG3LmOo6L1+WEXo/aNhmXPYSz2vtC+f6LsjXQEyEVaCLjfHx6M4nZe5cytzob1rH0XopfiSDg1E0LTndDc2sK1cgYjiU8sFLoD4tKiaJOL6UExHOISUQ7sUETnUCkyKDfpZQh1psAD/AbBBQBE= rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAgEAz7SPEGJRVOWEgl/FcJ4yTqKf9IdKTVD3vaUF4dSRqSI2ychAA6MW0m7JKKthekTT88l4+bOnClvPN78+4ImCPF72/eCB8ntikRS+nB17opqKNb1ST1XhyDpqADiKDmz6mGtq2mDkM1nKV46BSy7xi2WKcN91H6+iGa9GcMcxzbCKsKFRLyzcby2O3IpppQfhDXmpFBuM2UBcTSP2ESAygTFp8ewCiqzcE7AX2CRE64risC8G/1WdUFNWf8fpKGIpeh8Qc1gSXn0Fi9NUDAU05KXW+W48oMgCvhrA9SH4wPRBMRSx4qjC5UQydBzoOk3iPv4TjOqpBFBvSHJbLboSzvhe/8uEcRwvc7DYPCO87CNwAt8SBRAyoNlnEZgQCW5jCyRxwz3eEOqXENr9n6O2/zorJaveKQyF+7VqtgdNmFgjbJFkM9DH4zAbZWuKM8xHMvbc/w6Qb/D+YRdQRCAczB8WjrT6qSmTmahfV2nJXD3PSajSWgZE1/3Oex3POk0CResh/QOrJpm3YP+wE6xgjLHZF4TdVqikbRsckIivaR5KmymzhDcqdgLvIS/nAmCIheq/BitPA66XL5DFL5ec53Hhqafy/SU77Ztlu3kAXq2hh5En0AY/eFS/sYMTTvBJxPan81wcIdeosGJVF8vGuxI6pQn0B26VwWWFmwEmQfM= rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAABAEAiFZ4IAxGRgk4n2DRDLLNVBGp8sqSj0KTbIrhTexAJK5wN3j9aNOOA3P8Q8SSqYtyX4Fpdk1MZMZEa/e4PQTkOerGvdKUbd9TkuQYOtKMgd1393rdFNp4hb9gzLSr6QeqkAP16bKymm8LZH0YymDAqHdO0IK2bt13g5HGnbii5ok5dWx5Mt2+MOmw31qnZimt/kM/nzsHZEfd7A84HPDZZDWdxZh9A4nbANu28vupED9MkFUjOupBrY1DUXoQVVSrxxL3ghzHtAcjK905yEmZNbys7DVyd/PdDWHlDsKjv6nzAXmuvVVTlfKpQWTysq94vkLlgJIlv8xu4ON8hIhq4/K/Gr76Ko0aFlsy+82U4lVJQelMdm30G5Tpq8IEAiyclLZmnmGlVsZyc/ox5dJ0AW7XC/RQKEX3eQwszGdtSYROg9z8vc8gFDSxdxQuuBENAm+b3pPQonUSCkhmlMRkEF0Yh2Kiy5C2Au/Z+3RcdomPsV3ey6mMJV+x319BiMSa2KAyByynWZhjDU/nnWh6uK3xuwSGef3Cki/qx+4sETOlMqIt0fCzxRuQOYw4HYQHnYez8EJ3jOHT8ldAQyS8IcovtdU33D5/LrN5ICDx1supNYL+P4vrp42YZ4QdCCFrRTrQw/X3n9p5ejitptxEkr4hOoz9nfkmtXWw6KoTe8sid+ojVjsmzdf6uYLeeZuW9xgaV2VajV1+NiUl4XmtLNWn31hBxt9xqHukt5+yRDiS5vxz/iKRUHp9RnUpmRGKZbnizqkGONgdzAoU6tPrDnlSWyGok9Fzto8YZbG9TZW+WAR8j7KZztHgXUYRCVdKEsNGSMgKirK84VyuUcXBNZu87QmvW1LYYvy7tzez9yKx8f0x3H4yJZRHCIqEjgvLkFXOz4y307vZwhyDB80ogVFXzkNiq6KPpIIVPvOOin5dLexB2C6MlIQbIIEpDFXDd1Vt5/unxzJP3q77CxgL3P96fiTCEhDJmbNAAgI0xlljSt7RR41uadJEn91iAFs2Ug3Xy4Xii/CcBJCwmdYLeuKmtelAgHytvZ6IQufg4mPCpKk46oyad+cukjzfB/yEgd5uFi1KCVE00PCQzaz+erUNdqmguKOgBm+Eg+EFTbAdOlbGSICfpCLIjBD5MwnncYrDRp6diXtrdfxFV7OKoi60D7payzf3j9wyXdviEttM6i1SF5f/ePkL6N9ri/JJMzY9CkfW55BC95XdRKx0SxCkWUQAaIIbjcr4Nm+vpjNYIEaCvY8Nxg4jBXQTOGq570ozinJVGm6xB1FF/VR3NAksEF6UIyjkT9w+4juPBJHDDNTpCPN9R1AqX0MCUrO8wQIr3xmCZOtMCqOM1raKDw== rsa-key-20210312
// ssh-rsa AAAAB3NzaC1yc2EAAAABJQAABAEA8MaKLgqJdzHuXDSHe1jbhu3q4iYtQrpQMrIxx1p9tJ5ypMsysMNppGT1lL1kQ3gFetTA4S4PlXU9pZ/scrlKItTr+HPg+0mHqW47WK9Ql7cqcbwhZBn51kBWF3Th83fjsQg34HlvGPNLxA+9DwVgmFGtg++wOuxm6X0r05ZQC4AEXajr2oYtlL/AMT0401jviVOZIOCUBMLjTivA3Jd/GHLOPdqQQvnttztpX4AUbLFL4zGnO2utOE85f8K5SWNsFSbizl9RlFOZDAuGoIgxQ3CEtXGlFSdgo5fLSWVtJvgeMMY4TyJRvXUCNrVXbRbybz9hGKNcjalt94q8p/kP2c1vy1pLxtikc1TT9h4jEMoz5KJD5OkdfDkZUxK0Ud0AyJFw7TVvy/ww8gOVbm9JbzKy1fLZn96+iJYGv0mjJul8g3UbSFD84T3nsKEfrk6j8N9uZLhFEreEJZ/EmxYvu3i3ANXXXbkXZsttnII8kEqH+tDFQpvoYjI3d3147lPq2ehqAL/+RMW/9oENa/1oCKAq+0XwWcAoNi3b49k1szQv/tSEl+fadFybRHHPDI8u6lbAauxJTZ0xWfd3kAyN31ci+8txKqD8Jsf5pBSXxpS2X8vXrzarnQduUAF18ZOooO573h+YBp5TBro3o5LO9JGygZg8ROteGxvJSnx0G1Y+MjzWG+44b0WkoZLPKg5qLgEHX8U+aCvhJG7+jIWQnIb8tWkz8RZYwmZTi0eVRzGpqEpePzrwPOoRRvSqu69wUEICeRAj4gK0/+Yboko3vgxUhBk5Q/yLQHs+A/nc75hiAmi+ZRcl8FwKtCFKmDPLdYhiWM0gSYyH1MoyiyNmkfSTzUWsERi46CmdEU0tVt3x6RIy1Mt0yM3/lV7hIXyGD9oW6lUnj4VteEdrkeYox7Ee+/W4TFhESt33dqWT2Le2MBwKAjZcR0iAsJp2zVT2qtV8saeR+6ZqswVXTjK/FhX0SdSf8kpVnWBYtS/DDtDYGmFjHyayzLCz2YBpWvka6BZAg5fWuDCpzj5/iCF6fcFVsKdPuMIm1pKczC3ypJHfK37sMQ1E2cuzVXf3xNhJu7HZuiZTEPFJiIe1exVnBv8Y4PqWZ1uvYNTvLfrNE8/NNS3SvJyFJu/dJFRQnHWQuOVJB+gWfMKWN7tnM8wmW+g+/qogWWXJrQiFq2tGRcmiwX70Eos4NxGKTCyEgUVqpuJOysNWcCluujVYaFCNL5K1QbZJ+W1JXP2t2xMKuSIs3BzkMgExYKVJqfFnMrP9NAoVyBR3r6dGkjPjaWA1X2n2MsmqCr7P93imZ4zNnECGgc6hrr8oxur/JlMYSpoRErg4wR2ue1QwApvwvdKURw== rsa-key-20210312

namespace SshNet.PuttyKey.Sample
{
    class Program
    {
        static void Main(string[] args)
        {

            var testKeys = new[]
            {
                "ed25519", "ecdsa256", "ecdsa384", "ecdsa521", "rsa2048", "rsa3072", "rsa4096", "rsa8192",
                "ed25519pass", "ecdsa256pass", "ecdsa384pass", "ecdsa521pass", "rsa2048pass", "rsa3072pass", "rsa4096pass", "rsa8192pass",
            };

            foreach (var testKey in testKeys)
            {
                try
                {
                    var keyStream = GetKey($"{testKey}.ppk");
                    if (keyStream is null)
                        throw new NullReferenceException(nameof(keyStream));

                    IPrivateKeyFile key;
                    if (testKey.Contains("pass"))
                    {
                        key = new PuttyKeyFile(keyStream, "12345");
                    }
                    else
                    {
                        key = new PuttyKeyFile(keyStream);
                    }
                    using var client = new SshClient("schwanensee", "root", key);
                    client.Connect();
                    Console.WriteLine(client.RunCommand("hostname").Result.Trim());
                    Console.WriteLine($"Key {testKey} worked!");
                }
                catch (Exception e)
                {
                    Console.WriteLine(testKey);
                    Console.WriteLine(e);
                }
            }
        }

        private static Stream? GetKey(string keyName)
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.PuttyKey.Sample.TestKeys.{keyName}");
        }
    }
}