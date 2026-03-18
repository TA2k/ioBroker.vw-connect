.class public final synthetic Lx41/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lx41/d;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lx41/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx41/d;->a:Lx41/d;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.car2phone.pairing.Pairing.AntennaInformation"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "remoteCredentials"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "beaconMajor"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "beaconMinor"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Lx41/d;->descriptor:Lsz0/g;

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    const/4 p0, 0x3

    .line 2
    new-array p0, p0, [Lqz0/a;

    .line 3
    .line 4
    sget-object v0, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials$$serializer;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aput-object v0, p0, v1

    .line 8
    .line 9
    sget-object v0, Luz0/d2;->a:Luz0/d2;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    aput-object v0, p0, v1

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    aput-object v0, p0, v1

    .line 16
    .line 17
    return-object p0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object p0, Lx41/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v5, v0

    .line 11
    move v6, v1

    .line 12
    move-object v3, v2

    .line 13
    move-object v4, v3

    .line 14
    :goto_0
    if-eqz v5, :cond_4

    .line 15
    .line 16
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 17
    .line 18
    .line 19
    move-result v7

    .line 20
    const/4 v8, -0x1

    .line 21
    if-eq v7, v8, :cond_3

    .line 22
    .line 23
    if-eqz v7, :cond_2

    .line 24
    .line 25
    if-eq v7, v0, :cond_1

    .line 26
    .line 27
    const/4 v8, 0x2

    .line 28
    if-ne v7, v8, :cond_0

    .line 29
    .line 30
    sget-object v7, Luz0/d2;->a:Luz0/d2;

    .line 31
    .line 32
    invoke-interface {p1, p0, v8, v7, v4}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Llx0/z;

    .line 37
    .line 38
    or-int/lit8 v6, v6, 0x4

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Lqz0/k;

    .line 42
    .line 43
    invoke-direct {p0, v7}, Lqz0/k;-><init>(I)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    sget-object v7, Luz0/d2;->a:Luz0/d2;

    .line 48
    .line 49
    invoke-interface {p1, p0, v0, v7, v3}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Llx0/z;

    .line 54
    .line 55
    or-int/lit8 v6, v6, 0x2

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    sget-object v7, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials$$serializer;

    .line 59
    .line 60
    invoke-interface {p1, p0, v1, v7, v2}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 65
    .line 66
    or-int/lit8 v6, v6, 0x1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_3
    move v5, v1

    .line 70
    goto :goto_0

    .line 71
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 72
    .line 73
    .line 74
    new-instance p0, Lx41/f;

    .line 75
    .line 76
    invoke-direct {p0, v6, v2, v3, v4}, Lx41/f;-><init>(ILtechnology/cariad/cat/genx/crypto/RemoteCredentials;Llx0/z;Llx0/z;)V

    .line 77
    .line 78
    .line 79
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lx41/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lx41/f;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lx41/d;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials$$serializer;

    .line 15
    .line 16
    iget-object v1, p2, Lx41/f;->a:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Luz0/d2;->a:Luz0/d2;

    .line 23
    .line 24
    iget-short v1, p2, Lx41/f;->b:S

    .line 25
    .line 26
    new-instance v2, Llx0/z;

    .line 27
    .line 28
    invoke-direct {v2, v1}, Llx0/z;-><init>(S)V

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-short p2, p2, Lx41/f;->c:S

    .line 36
    .line 37
    new-instance v1, Llx0/z;

    .line 38
    .line 39
    invoke-direct {v1, p2}, Llx0/z;-><init>(S)V

    .line 40
    .line 41
    .line 42
    const/4 p2, 0x2

    .line 43
    invoke-interface {p1, p0, p2, v0, v1}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method
