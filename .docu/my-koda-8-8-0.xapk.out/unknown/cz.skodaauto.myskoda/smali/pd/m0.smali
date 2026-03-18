.class public final synthetic Lpd/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lpd/m0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd/m0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpd/m0;->a:Lpd/m0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.PowerCurveResponse"

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "id"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "currency"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "slots"

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "source"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    sput-object v1, Lpd/m0;->descriptor:Lsz0/g;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lpd/o0;->h:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 7
    .line 8
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    const/4 v3, 0x0

    .line 13
    aput-object v2, v0, v3

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    aput-object v3, v0, v2

    .line 21
    .line 22
    const/4 v2, 0x2

    .line 23
    aget-object p0, p0, v2

    .line 24
    .line 25
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    aput-object p0, v0, v2

    .line 30
    .line 31
    const/4 p0, 0x3

    .line 32
    aput-object v1, v0, p0

    .line 33
    .line 34
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object p0, Lpd/m0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lpd/o0;->h:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v5, v2

    .line 13
    move-object v6, v3

    .line 14
    move-object v7, v6

    .line 15
    move-object v8, v7

    .line 16
    move-object v9, v8

    .line 17
    move v3, v1

    .line 18
    :goto_0
    if-eqz v3, :cond_5

    .line 19
    .line 20
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    const/4 v10, -0x1

    .line 25
    if-eq v4, v10, :cond_4

    .line 26
    .line 27
    if-eqz v4, :cond_3

    .line 28
    .line 29
    if-eq v4, v1, :cond_2

    .line 30
    .line 31
    const/4 v10, 0x2

    .line 32
    if-eq v4, v10, :cond_1

    .line 33
    .line 34
    const/4 v9, 0x3

    .line 35
    if-ne v4, v9, :cond_0

    .line 36
    .line 37
    invoke-interface {p1, p0, v9}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v9

    .line 41
    or-int/lit8 v5, v5, 0x8

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    new-instance p0, Lqz0/k;

    .line 45
    .line 46
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_1
    aget-object v4, v0, v10

    .line 51
    .line 52
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    check-cast v4, Lqz0/a;

    .line 57
    .line 58
    invoke-interface {p1, p0, v10, v4, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    move-object v8, v4

    .line 63
    check-cast v8, Ljava/util/List;

    .line 64
    .line 65
    or-int/lit8 v5, v5, 0x4

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 69
    .line 70
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    move-object v7, v4

    .line 75
    check-cast v7, Ljava/lang/String;

    .line 76
    .line 77
    or-int/lit8 v5, v5, 0x2

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 81
    .line 82
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    move-object v6, v4

    .line 87
    check-cast v6, Ljava/lang/String;

    .line 88
    .line 89
    or-int/lit8 v5, v5, 0x1

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_4
    move v3, v2

    .line 93
    goto :goto_0

    .line 94
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 95
    .line 96
    .line 97
    new-instance v4, Lpd/o0;

    .line 98
    .line 99
    invoke-direct/range {v4 .. v9}, Lpd/o0;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lpd/m0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Lpd/o0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lpd/o0;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p2, Lpd/o0;->d:Ljava/lang/String;

    .line 11
    .line 12
    sget-object v1, Lpd/m0;->descriptor:Lsz0/g;

    .line 13
    .line 14
    invoke-interface {p1, v1}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    sget-object v2, Lpd/o0;->h:[Llx0/i;

    .line 19
    .line 20
    invoke-interface {p1, v1}, Ltz0/b;->e(Lsz0/g;)Z

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-eqz v3, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    if-eqz v0, :cond_1

    .line 28
    .line 29
    :goto_0
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    invoke-interface {p1, v1, v4, v3, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_1
    invoke-interface {p1, v1}, Ltz0/b;->e(Lsz0/g;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    if-eqz p0, :cond_3

    .line 43
    .line 44
    :goto_1
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 45
    .line 46
    const/4 v3, 0x1

    .line 47
    invoke-interface {p1, v1, v3, v0, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_3
    const/4 p0, 0x2

    .line 51
    aget-object v0, v2, p0

    .line 52
    .line 53
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    check-cast v0, Lqz0/a;

    .line 58
    .line 59
    iget-object v2, p2, Lpd/o0;->f:Ljava/util/List;

    .line 60
    .line 61
    invoke-interface {p1, v1, p0, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x3

    .line 65
    iget-object p2, p2, Lpd/o0;->g:Ljava/lang/String;

    .line 66
    .line 67
    invoke-interface {p1, v1, p0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-interface {p1, v1}, Ltz0/b;->b(Lsz0/g;)V

    .line 71
    .line 72
    .line 73
    return-void
.end method
