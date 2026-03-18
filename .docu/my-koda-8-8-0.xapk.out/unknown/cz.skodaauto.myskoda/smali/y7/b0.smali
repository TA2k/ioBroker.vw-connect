.class public final Ly7/b0;
.super Ly7/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:I

.field public final i:[B

.field public final j:Ljava/net/DatagramPacket;

.field public k:Landroid/net/Uri;

.field public l:Ljava/net/DatagramSocket;

.field public m:Ljava/net/MulticastSocket;

.field public n:Ljava/net/InetAddress;

.field public o:Z

.field public p:I


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0}, Ly7/c;-><init>(Z)V

    .line 3
    .line 4
    .line 5
    const/16 v0, 0x1f40

    .line 6
    .line 7
    iput v0, p0, Ly7/b0;->h:I

    .line 8
    .line 9
    const/16 v0, 0x7d0

    .line 10
    .line 11
    new-array v1, v0, [B

    .line 12
    .line 13
    iput-object v1, p0, Ly7/b0;->i:[B

    .line 14
    .line 15
    new-instance v2, Ljava/net/DatagramPacket;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-direct {v2, v1, v3, v0}, Ljava/net/DatagramPacket;-><init>([BII)V

    .line 19
    .line 20
    .line 21
    iput-object v2, p0, Ly7/b0;->j:Ljava/net/DatagramPacket;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Ly7/b0;->k:Landroid/net/Uri;

    .line 3
    .line 4
    iget-object v1, p0, Ly7/b0;->m:Ljava/net/MulticastSocket;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    :try_start_0
    iget-object v2, p0, Ly7/b0;->n:Ljava/net/InetAddress;

    .line 9
    .line 10
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1, v2}, Ljava/net/MulticastSocket;->leaveGroup(Ljava/net/InetAddress;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    :catch_0
    iput-object v0, p0, Ly7/b0;->m:Ljava/net/MulticastSocket;

    .line 17
    .line 18
    :cond_0
    iget-object v1, p0, Ly7/b0;->l:Ljava/net/DatagramSocket;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/net/DatagramSocket;->close()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Ly7/b0;->l:Ljava/net/DatagramSocket;

    .line 26
    .line 27
    :cond_1
    iput-object v0, p0, Ly7/b0;->n:Ljava/net/InetAddress;

    .line 28
    .line 29
    const/4 v0, 0x0

    .line 30
    iput v0, p0, Ly7/b0;->p:I

    .line 31
    .line 32
    iget-boolean v1, p0, Ly7/b0;->o:Z

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    iput-boolean v0, p0, Ly7/b0;->o:Z

    .line 37
    .line 38
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 39
    .line 40
    .line 41
    :cond_2
    return-void
.end method

.method public final g(Ly7/j;)J
    .locals 3

    .line 1
    iget-object v0, p1, Ly7/j;->a:Landroid/net/Uri;

    .line 2
    .line 3
    iput-object v0, p0, Ly7/b0;->k:Landroid/net/Uri;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/net/Uri;->getHost()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Ly7/b0;->k:Landroid/net/Uri;

    .line 13
    .line 14
    invoke-virtual {v1}, Landroid/net/Uri;->getPort()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {p0}, Ly7/c;->p()V

    .line 19
    .line 20
    .line 21
    :try_start_0
    invoke-static {v0}, Ljava/net/InetAddress;->getByName(Ljava/lang/String;)Ljava/net/InetAddress;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Ly7/b0;->n:Ljava/net/InetAddress;

    .line 26
    .line 27
    new-instance v0, Ljava/net/InetSocketAddress;

    .line 28
    .line 29
    iget-object v2, p0, Ly7/b0;->n:Ljava/net/InetAddress;

    .line 30
    .line 31
    invoke-direct {v0, v2, v1}, Ljava/net/InetSocketAddress;-><init>(Ljava/net/InetAddress;I)V

    .line 32
    .line 33
    .line 34
    iget-object v1, p0, Ly7/b0;->n:Ljava/net/InetAddress;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/net/InetAddress;->isMulticastAddress()Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_0

    .line 41
    .line 42
    new-instance v1, Ljava/net/MulticastSocket;

    .line 43
    .line 44
    invoke-direct {v1, v0}, Ljava/net/MulticastSocket;-><init>(Ljava/net/SocketAddress;)V

    .line 45
    .line 46
    .line 47
    iput-object v1, p0, Ly7/b0;->m:Ljava/net/MulticastSocket;

    .line 48
    .line 49
    iget-object v0, p0, Ly7/b0;->n:Ljava/net/InetAddress;

    .line 50
    .line 51
    invoke-virtual {v1, v0}, Ljava/net/MulticastSocket;->joinGroup(Ljava/net/InetAddress;)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Ly7/b0;->m:Ljava/net/MulticastSocket;

    .line 55
    .line 56
    iput-object v0, p0, Ly7/b0;->l:Ljava/net/DatagramSocket;

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    new-instance v1, Ljava/net/DatagramSocket;

    .line 60
    .line 61
    invoke-direct {v1, v0}, Ljava/net/DatagramSocket;-><init>(Ljava/net/SocketAddress;)V

    .line 62
    .line 63
    .line 64
    iput-object v1, p0, Ly7/b0;->l:Ljava/net/DatagramSocket;

    .line 65
    .line 66
    :goto_0
    iget-object v0, p0, Ly7/b0;->l:Ljava/net/DatagramSocket;

    .line 67
    .line 68
    iget v1, p0, Ly7/b0;->h:I

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/net/DatagramSocket;->setSoTimeout(I)V
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    .line 72
    .line 73
    const/4 v0, 0x1

    .line 74
    iput-boolean v0, p0, Ly7/b0;->o:Z

    .line 75
    .line 76
    invoke-virtual {p0, p1}, Ly7/c;->q(Ly7/j;)V

    .line 77
    .line 78
    .line 79
    const-wide/16 p0, -0x1

    .line 80
    .line 81
    return-wide p0

    .line 82
    :catch_0
    move-exception p0

    .line 83
    new-instance p1, Ly7/a0;

    .line 84
    .line 85
    const/16 v0, 0x7d1

    .line 86
    .line 87
    invoke-direct {p1, v0, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 88
    .line 89
    .line 90
    throw p1

    .line 91
    :catch_1
    move-exception p0

    .line 92
    new-instance p1, Ly7/a0;

    .line 93
    .line 94
    const/16 v0, 0x7d6

    .line 95
    .line 96
    invoke-direct {p1, v0, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 97
    .line 98
    .line 99
    throw p1
.end method

.method public final getUri()Landroid/net/Uri;
    .locals 0

    .line 1
    iget-object p0, p0, Ly7/b0;->k:Landroid/net/Uri;

    .line 2
    .line 3
    return-object p0
.end method

.method public final read([BII)I
    .locals 2

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    iget v0, p0, Ly7/b0;->p:I

    .line 6
    .line 7
    iget-object v1, p0, Ly7/b0;->j:Ljava/net/DatagramPacket;

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    :try_start_0
    iget-object v0, p0, Ly7/b0;->l:Ljava/net/DatagramSocket;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/net/DatagramSocket;->receive(Ljava/net/DatagramPacket;)V
    :try_end_0
    .catch Ljava/net/SocketTimeoutException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/net/DatagramPacket;->getLength()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iput v0, p0, Ly7/b0;->p:I

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ly7/c;->c(I)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catch_0
    move-exception p0

    .line 30
    new-instance p1, Ly7/a0;

    .line 31
    .line 32
    const/16 p2, 0x7d1

    .line 33
    .line 34
    invoke-direct {p1, p2, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 35
    .line 36
    .line 37
    throw p1

    .line 38
    :catch_1
    move-exception p0

    .line 39
    new-instance p1, Ly7/a0;

    .line 40
    .line 41
    const/16 p2, 0x7d2

    .line 42
    .line 43
    invoke-direct {p1, p2, p0}, Ly7/i;-><init>(ILjava/lang/Exception;)V

    .line 44
    .line 45
    .line 46
    throw p1

    .line 47
    :cond_1
    :goto_0
    invoke-virtual {v1}, Ljava/net/DatagramPacket;->getLength()I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget v1, p0, Ly7/b0;->p:I

    .line 52
    .line 53
    sub-int/2addr v0, v1

    .line 54
    invoke-static {v1, p3}, Ljava/lang/Math;->min(II)I

    .line 55
    .line 56
    .line 57
    move-result p3

    .line 58
    iget-object v1, p0, Ly7/b0;->i:[B

    .line 59
    .line 60
    invoke-static {v1, v0, p1, p2, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 61
    .line 62
    .line 63
    iget p1, p0, Ly7/b0;->p:I

    .line 64
    .line 65
    sub-int/2addr p1, p3

    .line 66
    iput p1, p0, Ly7/b0;->p:I

    .line 67
    .line 68
    return p3
.end method
