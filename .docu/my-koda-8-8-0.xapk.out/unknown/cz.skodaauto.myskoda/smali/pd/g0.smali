.class public final synthetic Lpd/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lpd/g0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd/g0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpd/g0;->a:Lpd/g0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.PowerCurveData"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "powerCurve"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "socCurve"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "slots"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "currency"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "source"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Lpd/g0;->descriptor:Lsz0/g;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lpd/i0;->i:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget-object v2, p0, v1

    .line 8
    .line 9
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    aput-object v2, v0, v1

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    aget-object v2, p0, v1

    .line 17
    .line 18
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    aput-object v2, v0, v1

    .line 23
    .line 24
    const/4 v1, 0x2

    .line 25
    aget-object p0, p0, v1

    .line 26
    .line 27
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    aput-object p0, v0, v1

    .line 32
    .line 33
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 34
    .line 35
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    const/4 v2, 0x3

    .line 40
    aput-object v1, v0, v2

    .line 41
    .line 42
    const/4 v1, 0x4

    .line 43
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    aput-object p0, v0, v1

    .line 48
    .line 49
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Lpd/g0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lpd/i0;->i:[Llx0/i;

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
    const/4 v11, 0x4

    .line 39
    if-ne v4, v11, :cond_0

    .line 40
    .line 41
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 42
    .line 43
    invoke-interface {p1, p0, v11, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    move-object v10, v4

    .line 48
    check-cast v10, Ljava/lang/String;

    .line 49
    .line 50
    or-int/lit8 v5, v5, 0x10

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    new-instance p0, Lqz0/k;

    .line 54
    .line 55
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_1
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 60
    .line 61
    invoke-interface {p1, p0, v11, v4, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    move-object v9, v4

    .line 66
    check-cast v9, Ljava/lang/String;

    .line 67
    .line 68
    or-int/lit8 v5, v5, 0x8

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_2
    aget-object v4, v0, v11

    .line 72
    .line 73
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Lqz0/a;

    .line 78
    .line 79
    invoke-interface {p1, p0, v11, v4, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    move-object v8, v4

    .line 84
    check-cast v8, Ljava/util/List;

    .line 85
    .line 86
    or-int/lit8 v5, v5, 0x4

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    aget-object v4, v0, v1

    .line 90
    .line 91
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    check-cast v4, Lqz0/a;

    .line 96
    .line 97
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    move-object v7, v4

    .line 102
    check-cast v7, Ljava/util/List;

    .line 103
    .line 104
    or-int/lit8 v5, v5, 0x2

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_4
    aget-object v4, v0, v2

    .line 108
    .line 109
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    check-cast v4, Lqz0/a;

    .line 114
    .line 115
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    move-object v6, v4

    .line 120
    check-cast v6, Ljava/util/List;

    .line 121
    .line 122
    or-int/lit8 v5, v5, 0x1

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_5
    move v3, v2

    .line 126
    goto :goto_0

    .line 127
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 128
    .line 129
    .line 130
    new-instance v4, Lpd/i0;

    .line 131
    .line 132
    invoke-direct/range {v4 .. v10}, Lpd/i0;-><init>(ILjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lpd/g0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 8

    .line 1
    check-cast p2, Lpd/i0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lpd/i0;->h:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p2, Lpd/i0;->g:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v1, p2, Lpd/i0;->f:Ljava/util/List;

    .line 13
    .line 14
    iget-object v2, p2, Lpd/i0;->e:Ljava/util/List;

    .line 15
    .line 16
    iget-object p2, p2, Lpd/i0;->d:Ljava/util/List;

    .line 17
    .line 18
    sget-object v3, Lpd/g0;->descriptor:Lsz0/g;

    .line 19
    .line 20
    invoke-interface {p1, v3}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    sget-object v4, Lpd/i0;->i:[Llx0/i;

    .line 25
    .line 26
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 31
    .line 32
    if-eqz v5, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-static {p2, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    if-nez v5, :cond_1

    .line 40
    .line 41
    :goto_0
    const/4 v5, 0x0

    .line 42
    aget-object v7, v4, v5

    .line 43
    .line 44
    invoke-interface {v7}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v7

    .line 48
    check-cast v7, Lqz0/a;

    .line 49
    .line 50
    invoke-interface {p1, v3, v5, v7, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eqz p2, :cond_2

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-nez p2, :cond_3

    .line 65
    .line 66
    :goto_1
    const/4 p2, 0x1

    .line 67
    aget-object v5, v4, p2

    .line 68
    .line 69
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Lqz0/a;

    .line 74
    .line 75
    invoke-interface {p1, v3, p2, v5, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_3
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-eqz p2, :cond_4

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_4
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    if-nez p2, :cond_5

    .line 90
    .line 91
    :goto_2
    const/4 p2, 0x2

    .line 92
    aget-object v2, v4, p2

    .line 93
    .line 94
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    check-cast v2, Lqz0/a;

    .line 99
    .line 100
    invoke-interface {p1, v3, p2, v2, v1}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_5
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    if-eqz p2, :cond_6

    .line 108
    .line 109
    goto :goto_3

    .line 110
    :cond_6
    if-eqz v0, :cond_7

    .line 111
    .line 112
    :goto_3
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 113
    .line 114
    const/4 v1, 0x3

    .line 115
    invoke-interface {p1, v3, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_7
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    if-eqz p2, :cond_8

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_8
    if-eqz p0, :cond_9

    .line 126
    .line 127
    :goto_4
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 128
    .line 129
    const/4 v0, 0x4

    .line 130
    invoke-interface {p1, v3, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_9
    invoke-interface {p1, v3}, Ltz0/b;->b(Lsz0/g;)V

    .line 134
    .line 135
    .line 136
    return-void
.end method
