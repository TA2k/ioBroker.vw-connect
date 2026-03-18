.class public final synthetic Leg/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Leg/m;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Leg/m;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Leg/m;->a:Leg/m;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.remoteauthorization.models.RemoteAuthorizationOverviewResponse"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "pricing"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "priceExpiresAt"

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "priceExpiresAtText"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "priceValidationHash"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "isCtaEnabled"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Leg/m;->descriptor:Lsz0/g;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Leg/o;->f:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget-object p0, p0, v1

    .line 8
    .line 9
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    aput-object p0, v0, v1

    .line 14
    .line 15
    sget-object p0, Lmz0/f;->a:Lmz0/f;

    .line 16
    .line 17
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/4 v1, 0x1

    .line 22
    aput-object p0, v0, v1

    .line 23
    .line 24
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 25
    .line 26
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const/4 v2, 0x2

    .line 31
    aput-object v1, v0, v2

    .line 32
    .line 33
    const/4 v1, 0x3

    .line 34
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    aput-object p0, v0, v1

    .line 39
    .line 40
    const/4 p0, 0x4

    .line 41
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 42
    .line 43
    aput-object v1, v0, p0

    .line 44
    .line 45
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Leg/m;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Leg/o;->f:[Llx0/i;

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
    move v10, v5

    .line 14
    move-object v6, v3

    .line 15
    move-object v7, v6

    .line 16
    move-object v8, v7

    .line 17
    move-object v9, v8

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
    invoke-interface {p1, p0, v10}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 42
    .line 43
    .line 44
    move-result v10

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
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 55
    .line 56
    invoke-interface {p1, p0, v11, v4, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    move-object v9, v4

    .line 61
    check-cast v9, Ljava/lang/String;

    .line 62
    .line 63
    or-int/lit8 v5, v5, 0x8

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 67
    .line 68
    invoke-interface {p1, p0, v11, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    move-object v8, v4

    .line 73
    check-cast v8, Ljava/lang/String;

    .line 74
    .line 75
    or-int/lit8 v5, v5, 0x4

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_3
    sget-object v4, Lmz0/f;->a:Lmz0/f;

    .line 79
    .line 80
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    move-object v7, v4

    .line 85
    check-cast v7, Lgz0/p;

    .line 86
    .line 87
    or-int/lit8 v5, v5, 0x2

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_4
    aget-object v4, v0, v2

    .line 91
    .line 92
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    check-cast v4, Lqz0/a;

    .line 97
    .line 98
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    move-object v6, v4

    .line 103
    check-cast v6, Ljava/util/List;

    .line 104
    .line 105
    or-int/lit8 v5, v5, 0x1

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_5
    move v3, v2

    .line 109
    goto :goto_0

    .line 110
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 111
    .line 112
    .line 113
    new-instance v4, Leg/o;

    .line 114
    .line 115
    invoke-direct/range {v4 .. v10}, Leg/o;-><init>(ILjava/util/List;Lgz0/p;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 116
    .line 117
    .line 118
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Leg/m;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Leg/o;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Leg/m;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Leg/o;->f:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v0, v0, v1

    .line 18
    .line 19
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lqz0/a;

    .line 24
    .line 25
    iget-object v2, p2, Leg/o;->a:Ljava/util/List;

    .line 26
    .line 27
    iget-object v3, p2, Leg/o;->d:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v4, p2, Leg/o;->c:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v5, p2, Leg/o;->b:Lgz0/p;

    .line 32
    .line 33
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    if-eqz v5, :cond_1

    .line 44
    .line 45
    :goto_0
    sget-object v0, Lmz0/f;->a:Lmz0/f;

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    invoke-interface {p1, p0, v1, v0, v5}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    if-eqz v4, :cond_3

    .line 59
    .line 60
    :goto_1
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 61
    .line 62
    const/4 v1, 0x2

    .line 63
    invoke-interface {p1, p0, v1, v0, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    if-eqz v3, :cond_5

    .line 74
    .line 75
    :goto_2
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 76
    .line 77
    const/4 v1, 0x3

    .line 78
    invoke-interface {p1, p0, v1, v0, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_5
    const/4 v0, 0x4

    .line 82
    iget-boolean p2, p2, Leg/o;->e:Z

    .line 83
    .line 84
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 85
    .line 86
    .line 87
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 88
    .line 89
    .line 90
    return-void
.end method
