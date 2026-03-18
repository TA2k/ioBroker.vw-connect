.class public abstract Llp/zf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a()Ly51/e;
    .locals 6

    .line 1
    const-string v0, "1.1.1.1"

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    :try_start_0
    invoke-static {v0}, Ljava/net/InetAddress;->getByName(Ljava/lang/String;)Ljava/net/InetAddress;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    new-instance v3, Ljava/net/Socket;

    .line 13
    .line 14
    invoke-direct {v3}, Ljava/net/Socket;-><init>()V

    .line 15
    .line 16
    .line 17
    new-instance v4, Ljava/net/InetSocketAddress;

    .line 18
    .line 19
    const/16 v5, 0x50

    .line 20
    .line 21
    invoke-direct {v4, v0, v5}, Ljava/net/InetSocketAddress;-><init>(Ljava/net/InetAddress;I)V

    .line 22
    .line 23
    .line 24
    const/16 v0, 0x1f4

    .line 25
    .line 26
    invoke-virtual {v3, v4, v0}, Ljava/net/Socket;->connect(Ljava/net/SocketAddress;I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/net/Socket;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    .line 32
    move v2, v1

    .line 33
    :catch_0
    if-ne v2, v1, :cond_0

    .line 34
    .line 35
    sget-object v0, Ly51/c;->a:Ly51/c;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    if-nez v2, :cond_1

    .line 39
    .line 40
    sget-object v0, Ly51/d;->a:Ly51/d;

    .line 41
    .line 42
    :goto_0
    return-object v0

    .line 43
    :cond_1
    new-instance v0, La8/r0;

    .line 44
    .line 45
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw v0
.end method

.method public static final b(Landroid/net/Network;Ljava/lang/String;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;)V
    .locals 5

    .line 1
    const/4 v0, 0x7

    .line 2
    const/4 v1, 0x0

    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object v2, Lx51/c;->o1:Lx51/b;

    .line 6
    .line 7
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 8
    .line 9
    const/16 v4, 0xa

    .line 10
    .line 11
    invoke-direct {v3, p1, p2, p0, v4}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v2, v1, v3, v0}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 15
    .line 16
    .line 17
    :cond_0
    sget-object p0, Lx51/c;->o1:Lx51/b;

    .line 18
    .line 19
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 20
    .line 21
    const/16 v3, 0xb

    .line 22
    .line 23
    invoke-direct {v2, p1, p2, p4, v3}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {p0, v1, v2, v0}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 27
    .line 28
    .line 29
    new-instance p4, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 30
    .line 31
    const/16 v2, 0xc

    .line 32
    .line 33
    invoke-direct {p4, p1, p2, p3, v2}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {p0, v1, p4, v0}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 37
    .line 38
    .line 39
    new-instance p3, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 40
    .line 41
    const/16 p4, 0xd

    .line 42
    .line 43
    invoke-direct {p3, p1, p2, p5, p4}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {p0, v1, p3, v0}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public static synthetic c(Landroid/net/Network;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;I)V
    .locals 6

    .line 1
    and-int/lit8 p5, p5, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    :cond_0
    move-object v0, p0

    .line 7
    const-string v2, ""

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    move-object v3, p2

    .line 11
    move-object v4, p3

    .line 12
    move-object v5, p4

    .line 13
    invoke-static/range {v0 .. v5}, Llp/zf;->b(Landroid/net/Network;Ljava/lang/String;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public static final d(Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)Loo0/b;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;->getDistanceInMeters()Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    int-to-double v2, v0

    .line 13
    new-instance v0, Lqr0/d;

    .line 14
    .line 15
    invoke-direct {v0, v2, v3}, Lqr0/d;-><init>(D)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object v0, v1

    .line 20
    :goto_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;->getDurationInSeconds()Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    sget v1, Lmy0/c;->g:I

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 33
    .line 34
    invoke-static {p0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    new-instance p0, Lmy0/c;

    .line 39
    .line 40
    invoke-direct {p0, v1, v2}, Lmy0/c;-><init>(J)V

    .line 41
    .line 42
    .line 43
    move-object v1, p0

    .line 44
    :cond_1
    new-instance p0, Loo0/b;

    .line 45
    .line 46
    invoke-direct {p0, v0, v1}, Loo0/b;-><init>(Lqr0/d;Lmy0/c;)V

    .line 47
    .line 48
    .line 49
    return-object p0
.end method
