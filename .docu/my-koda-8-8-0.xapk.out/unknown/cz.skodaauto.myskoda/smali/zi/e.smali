.class public final synthetic Lzi/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lzi/e;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lzi/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzi/e;->a:Lzi/e;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.sdk.headless.internal.remoteauthorization.EvseIdLookupConnectorDetails"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "evseId"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "pricing"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "priceExpiresAt"

    .line 28
    .line 29
    const/4 v3, 0x1

    .line 30
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "priceExpiresAtText"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "priceValidationHash"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "isCtaEnabled"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    sput-object v1, Lzi/e;->descriptor:Lsz0/g;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lzi/g;->g:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x6

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
    aget-object p0, p0, v2

    .line 13
    .line 14
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    aput-object p0, v0, v2

    .line 19
    .line 20
    sget-object p0, Lmz0/f;->a:Lmz0/f;

    .line 21
    .line 22
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    const/4 v2, 0x2

    .line 27
    aput-object p0, v0, v2

    .line 28
    .line 29
    const/4 p0, 0x3

    .line 30
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    aput-object v2, v0, p0

    .line 35
    .line 36
    const/4 p0, 0x4

    .line 37
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    aput-object v1, v0, p0

    .line 42
    .line 43
    const/4 p0, 0x5

    .line 44
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 45
    .line 46
    aput-object v1, v0, p0

    .line 47
    .line 48
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lzi/e;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lzi/g;->g:[Llx0/i;

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
    move v11, v5

    .line 14
    move-object v6, v3

    .line 15
    move-object v7, v6

    .line 16
    move-object v8, v7

    .line 17
    move-object v9, v8

    .line 18
    move-object v10, v9

    .line 19
    move v3, v1

    .line 20
    :goto_0
    if-eqz v3, :cond_0

    .line 21
    .line 22
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    packed-switch v4, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    new-instance p0, Lqz0/k;

    .line 30
    .line 31
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :pswitch_0
    const/4 v4, 0x5

    .line 36
    invoke-interface {p1, p0, v4}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 37
    .line 38
    .line 39
    move-result v11

    .line 40
    or-int/lit8 v5, v5, 0x20

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_1
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 44
    .line 45
    const/4 v12, 0x4

    .line 46
    invoke-interface {p1, p0, v12, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    move-object v10, v4

    .line 51
    check-cast v10, Ljava/lang/String;

    .line 52
    .line 53
    or-int/lit8 v5, v5, 0x10

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :pswitch_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 57
    .line 58
    const/4 v12, 0x3

    .line 59
    invoke-interface {p1, p0, v12, v4, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    move-object v9, v4

    .line 64
    check-cast v9, Ljava/lang/String;

    .line 65
    .line 66
    or-int/lit8 v5, v5, 0x8

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_3
    sget-object v4, Lmz0/f;->a:Lmz0/f;

    .line 70
    .line 71
    const/4 v12, 0x2

    .line 72
    invoke-interface {p1, p0, v12, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    move-object v8, v4

    .line 77
    check-cast v8, Lgz0/p;

    .line 78
    .line 79
    or-int/lit8 v5, v5, 0x4

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :pswitch_4
    aget-object v4, v0, v1

    .line 83
    .line 84
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    check-cast v4, Lqz0/a;

    .line 89
    .line 90
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    move-object v7, v4

    .line 95
    check-cast v7, Ljava/util/List;

    .line 96
    .line 97
    or-int/lit8 v5, v5, 0x2

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :pswitch_5
    invoke-interface {p1, p0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    or-int/lit8 v5, v5, 0x1

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_6
    move v3, v2

    .line 108
    goto :goto_0

    .line 109
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 110
    .line 111
    .line 112
    new-instance v4, Lzi/g;

    .line 113
    .line 114
    invoke-direct/range {v4 .. v11}, Lzi/g;-><init>(ILjava/lang/String;Ljava/util/List;Lgz0/p;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 115
    .line 116
    .line 117
    return-object v4

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lzi/e;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Lzi/g;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lzi/e;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lzi/g;->g:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lzi/g;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lzi/g;->e:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p2, Lzi/g;->d:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v4, p2, Lzi/g;->c:Lgz0/p;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    invoke-interface {p1, p0, v5, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    aget-object v0, v0, v1

    .line 30
    .line 31
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lqz0/a;

    .line 36
    .line 37
    iget-object v5, p2, Lzi/g;->b:Ljava/util/List;

    .line 38
    .line 39
    invoke-interface {p1, p0, v1, v0, v5}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    if-eqz v4, :cond_1

    .line 50
    .line 51
    :goto_0
    sget-object v0, Lmz0/f;->a:Lmz0/f;

    .line 52
    .line 53
    const/4 v1, 0x2

    .line 54
    invoke-interface {p1, p0, v1, v0, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    if-eqz v3, :cond_3

    .line 65
    .line 66
    :goto_1
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 67
    .line 68
    const/4 v1, 0x3

    .line 69
    invoke-interface {p1, p0, v1, v0, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    if-eqz v2, :cond_5

    .line 80
    .line 81
    :goto_2
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 82
    .line 83
    const/4 v1, 0x4

    .line 84
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :cond_5
    const/4 v0, 0x5

    .line 88
    iget-boolean p2, p2, Lzi/g;->f:Z

    .line 89
    .line 90
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 91
    .line 92
    .line 93
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 94
    .line 95
    .line 96
    return-void
.end method
