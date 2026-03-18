.class public final synthetic Lc61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lc61/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lc61/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc61/a;->a:Lc61/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.network.tracing.offline.model.Event.Log"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "message"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "attributes"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "logLevel"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "timestamp"

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "id"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Lc61/a;->descriptor:Lsz0/g;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lc61/c;->f:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    aput-object v1, v0, v2

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    aget-object v3, p0, v2

    .line 13
    .line 14
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    aput-object v3, v0, v2

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    aget-object p0, p0, v2

    .line 22
    .line 23
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    aput-object p0, v0, v2

    .line 28
    .line 29
    const/4 p0, 0x3

    .line 30
    sget-object v2, Lmz0/h;->a:Lmz0/h;

    .line 31
    .line 32
    aput-object v2, v0, p0

    .line 33
    .line 34
    const/4 p0, 0x4

    .line 35
    aput-object v1, v0, p0

    .line 36
    .line 37
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Lc61/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lc61/c;->f:[Llx0/i;

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
    move-object v10, v9

    .line 18
    move v3, v1

    .line 19
    :goto_0
    if-eqz v3, :cond_6

    .line 20
    .line 21
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    const/4 v11, -0x1

    .line 26
    if-eq v4, v11, :cond_5

    .line 27
    .line 28
    if-eqz v4, :cond_4

    .line 29
    .line 30
    if-eq v4, v1, :cond_3

    .line 31
    .line 32
    const/4 v11, 0x2

    .line 33
    if-eq v4, v11, :cond_2

    .line 34
    .line 35
    const/4 v11, 0x3

    .line 36
    if-eq v4, v11, :cond_1

    .line 37
    .line 38
    const/4 v10, 0x4

    .line 39
    if-ne v4, v10, :cond_0

    .line 40
    .line 41
    invoke-interface {p1, p0, v10}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v10

    .line 45
    or-int/lit8 v5, v5, 0x10

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    new-instance p0, Lqz0/k;

    .line 49
    .line 50
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_1
    sget-object v4, Lmz0/h;->a:Lmz0/h;

    .line 55
    .line 56
    invoke-interface {p1, p0, v11, v4, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    move-object v9, v4

    .line 61
    check-cast v9, Lgz0/w;

    .line 62
    .line 63
    or-int/lit8 v5, v5, 0x8

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    aget-object v4, v0, v11

    .line 67
    .line 68
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    check-cast v4, Lqz0/a;

    .line 73
    .line 74
    invoke-interface {p1, p0, v11, v4, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    move-object v8, v4

    .line 79
    check-cast v8, Lz51/c;

    .line 80
    .line 81
    or-int/lit8 v5, v5, 0x4

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_3
    aget-object v4, v0, v1

    .line 85
    .line 86
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    check-cast v4, Lqz0/a;

    .line 91
    .line 92
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    move-object v7, v4

    .line 97
    check-cast v7, Ljava/util/Map;

    .line 98
    .line 99
    or-int/lit8 v5, v5, 0x2

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_4
    invoke-interface {p1, p0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v6

    .line 106
    or-int/lit8 v5, v5, 0x1

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_5
    move v3, v2

    .line 110
    goto :goto_0

    .line 111
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 112
    .line 113
    .line 114
    new-instance v4, Lc61/c;

    .line 115
    .line 116
    invoke-direct/range {v4 .. v10}, Lc61/c;-><init>(ILjava/lang/String;Ljava/util/Map;Lz51/c;Lgz0/w;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lc61/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Lc61/c;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lc61/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lc61/c;->f:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lc61/c;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lc61/c;->e:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p2, Lc61/c;->d:Lgz0/w;

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-interface {p1, p0, v4, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    aget-object v4, v0, v1

    .line 28
    .line 29
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, Lqz0/a;

    .line 34
    .line 35
    iget-object v5, p2, Lc61/c;->b:Ljava/util/Map;

    .line 36
    .line 37
    invoke-interface {p1, p0, v1, v4, v5}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x2

    .line 41
    aget-object v0, v0, v1

    .line 42
    .line 43
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Lqz0/a;

    .line 48
    .line 49
    iget-object p2, p2, Lc61/c;->c:Lz51/c;

    .line 50
    .line 51
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_0

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    sget-object p2, Lmy0/g;->a:Lmy0/b;

    .line 62
    .line 63
    invoke-interface {p2}, Lmy0/b;->now()Lmy0/f;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    sget-object v0, Lgz0/b0;->Companion:Lgz0/a0;

    .line 68
    .line 69
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    invoke-static {}, Lgz0/a0;->a()Lgz0/b0;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-static {p2, v0}, Lkp/u9;->f(Lmy0/f;Lgz0/b0;)Lgz0/w;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    invoke-static {v3, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    if-nez p2, :cond_1

    .line 85
    .line 86
    :goto_0
    sget-object p2, Lmz0/h;->a:Lmz0/h;

    .line 87
    .line 88
    const/4 v0, 0x3

    .line 89
    invoke-interface {p1, p0, v0, p2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    if-eqz p2, :cond_2

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_2
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    invoke-virtual {p2}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    const-string v0, "toString(...)"

    .line 108
    .line 109
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v2, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p2

    .line 116
    if-nez p2, :cond_3

    .line 117
    .line 118
    :goto_1
    const/4 p2, 0x4

    .line 119
    invoke-interface {p1, p0, p2, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 120
    .line 121
    .line 122
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 123
    .line 124
    .line 125
    return-void
.end method
