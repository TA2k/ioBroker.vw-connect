.class public final synthetic Lkg/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lkg/s;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/s;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/s;->a:Lkg/s;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.SubscriptionCompleteRequest"

    .line 11
    .line 12
    const/4 v3, 0x7

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "orderRfidCard"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "tariffId"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "billingAddress"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "documents"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "shippingAddress"

    .line 38
    .line 39
    const/4 v2, 0x1

    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "taxNumber"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "vin"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    sput-object v1, Lkg/s;->descriptor:Lsz0/g;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lkg/u;->h:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x7

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    sget-object v2, Luz0/g;->a:Luz0/g;

    .line 8
    .line 9
    aput-object v2, v0, v1

    .line 10
    .line 11
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    aput-object v1, v0, v2

    .line 15
    .line 16
    sget-object v2, Lac/a;->a:Lac/a;

    .line 17
    .line 18
    const/4 v3, 0x2

    .line 19
    aput-object v2, v0, v3

    .line 20
    .line 21
    const/4 v3, 0x3

    .line 22
    aget-object p0, p0, v3

    .line 23
    .line 24
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    aput-object p0, v0, v3

    .line 29
    .line 30
    const/4 p0, 0x4

    .line 31
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    aput-object v2, v0, p0

    .line 36
    .line 37
    const/4 p0, 0x5

    .line 38
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    aput-object v2, v0, p0

    .line 43
    .line 44
    const/4 p0, 0x6

    .line 45
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    aput-object v1, v0, p0

    .line 50
    .line 51
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object p0, Lkg/s;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lkg/u;->h:[Llx0/i;

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
    move v6, v5

    .line 14
    move-object v7, v3

    .line 15
    move-object v8, v7

    .line 16
    move-object v9, v8

    .line 17
    move-object v10, v9

    .line 18
    move-object v11, v10

    .line 19
    move-object v12, v11

    .line 20
    move v3, v1

    .line 21
    :goto_0
    if-eqz v3, :cond_0

    .line 22
    .line 23
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    packed-switch v4, :pswitch_data_0

    .line 28
    .line 29
    .line 30
    new-instance p0, Lqz0/k;

    .line 31
    .line 32
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :pswitch_0
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 37
    .line 38
    const/4 v13, 0x6

    .line 39
    invoke-interface {p1, p0, v13, v4, v12}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    move-object v12, v4

    .line 44
    check-cast v12, Ljava/lang/String;

    .line 45
    .line 46
    or-int/lit8 v5, v5, 0x40

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_1
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 50
    .line 51
    const/4 v13, 0x5

    .line 52
    invoke-interface {p1, p0, v13, v4, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    move-object v11, v4

    .line 57
    check-cast v11, Ljava/lang/String;

    .line 58
    .line 59
    or-int/lit8 v5, v5, 0x20

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_2
    sget-object v4, Lac/a;->a:Lac/a;

    .line 63
    .line 64
    const/4 v13, 0x4

    .line 65
    invoke-interface {p1, p0, v13, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    move-object v10, v4

    .line 70
    check-cast v10, Lac/c;

    .line 71
    .line 72
    or-int/lit8 v5, v5, 0x10

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_3
    const/4 v4, 0x3

    .line 76
    aget-object v13, v0, v4

    .line 77
    .line 78
    invoke-interface {v13}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v13

    .line 82
    check-cast v13, Lqz0/a;

    .line 83
    .line 84
    invoke-interface {p1, p0, v4, v13, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    move-object v9, v4

    .line 89
    check-cast v9, Ljava/util/List;

    .line 90
    .line 91
    or-int/lit8 v5, v5, 0x8

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_4
    sget-object v4, Lac/a;->a:Lac/a;

    .line 95
    .line 96
    const/4 v13, 0x2

    .line 97
    invoke-interface {p1, p0, v13, v4, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    move-object v8, v4

    .line 102
    check-cast v8, Lac/c;

    .line 103
    .line 104
    or-int/lit8 v5, v5, 0x4

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_5
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v7

    .line 111
    or-int/lit8 v5, v5, 0x2

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :pswitch_6
    invoke-interface {p1, p0, v2}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 115
    .line 116
    .line 117
    move-result v6

    .line 118
    or-int/lit8 v5, v5, 0x1

    .line 119
    .line 120
    goto :goto_0

    .line 121
    :pswitch_7
    move v3, v2

    .line 122
    goto :goto_0

    .line 123
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 124
    .line 125
    .line 126
    new-instance v4, Lkg/u;

    .line 127
    .line 128
    invoke-direct/range {v4 .. v12}, Lkg/u;-><init>(IZLjava/lang/String;Lac/c;Ljava/util/List;Lac/c;Ljava/lang/String;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    return-object v4

    .line 132
    nop

    .line 133
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_7
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
    sget-object p0, Lkg/s;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Lkg/u;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lkg/s;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lkg/u;->h:[Llx0/i;

    .line 15
    .line 16
    iget-boolean v1, p2, Lkg/u;->a:Z

    .line 17
    .line 18
    iget-object v2, p2, Lkg/u;->g:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p2, Lkg/u;->f:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v4, p2, Lkg/u;->e:Lac/c;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    invoke-interface {p1, p0, v5, v1}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    iget-object v5, p2, Lkg/u;->b:Ljava/lang/String;

    .line 30
    .line 31
    invoke-interface {p1, p0, v1, v5}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 32
    .line 33
    .line 34
    sget-object v1, Lac/a;->a:Lac/a;

    .line 35
    .line 36
    iget-object v5, p2, Lkg/u;->c:Lac/c;

    .line 37
    .line 38
    const/4 v6, 0x2

    .line 39
    invoke-interface {p1, p0, v6, v1, v5}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    const/4 v5, 0x3

    .line 43
    aget-object v0, v0, v5

    .line 44
    .line 45
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Lqz0/a;

    .line 50
    .line 51
    iget-object p2, p2, Lkg/u;->d:Ljava/util/List;

    .line 52
    .line 53
    invoke-interface {p1, p0, v5, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    if-eqz p2, :cond_0

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    if-eqz v4, :cond_1

    .line 64
    .line 65
    :goto_0
    const/4 p2, 0x4

    .line 66
    invoke-interface {p1, p0, p2, v1, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    if-eqz p2, :cond_2

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    if-eqz v3, :cond_3

    .line 77
    .line 78
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 79
    .line 80
    const/4 v0, 0x5

    .line 81
    invoke-interface {p1, p0, v0, p2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    if-eqz p2, :cond_4

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_4
    if-eqz v2, :cond_5

    .line 92
    .line 93
    :goto_2
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 94
    .line 95
    const/4 v0, 0x6

    .line 96
    invoke-interface {p1, p0, v0, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_5
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 100
    .line 101
    .line 102
    return-void
.end method
