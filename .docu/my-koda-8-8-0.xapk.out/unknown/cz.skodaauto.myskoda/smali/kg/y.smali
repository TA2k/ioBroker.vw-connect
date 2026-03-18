.class public final synthetic Lkg/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lkg/y;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/y;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/y;->a:Lkg/y;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.SubscriptionInitResponse"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "availableShippingCountries"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "documents"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "requiresTaxNumber"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "userLegalCountry"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "tariffs"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "storedPaymentOption"

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    sput-object v1, Lkg/y;->descriptor:Lsz0/g;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lkg/a0;->g:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x6

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
    sget-object v2, Luz0/g;->a:Luz0/g;

    .line 26
    .line 27
    aput-object v2, v0, v1

    .line 28
    .line 29
    const/4 v1, 0x3

    .line 30
    sget-object v2, Lac/y;->a:Lac/y;

    .line 31
    .line 32
    aput-object v2, v0, v1

    .line 33
    .line 34
    const/4 v1, 0x4

    .line 35
    aget-object p0, p0, v1

    .line 36
    .line 37
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    aput-object p0, v0, v1

    .line 42
    .line 43
    sget-object p0, Lnc/x;->a:Lnc/x;

    .line 44
    .line 45
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const/4 v1, 0x5

    .line 50
    aput-object p0, v0, v1

    .line 51
    .line 52
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lkg/y;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lkg/a0;->g:[Llx0/i;

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
    move v8, v5

    .line 14
    move-object v6, v3

    .line 15
    move-object v7, v6

    .line 16
    move-object v9, v7

    .line 17
    move-object v10, v9

    .line 18
    move-object v11, v10

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
    sget-object v4, Lnc/x;->a:Lnc/x;

    .line 36
    .line 37
    const/4 v12, 0x5

    .line 38
    invoke-interface {p1, p0, v12, v4, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    move-object v11, v4

    .line 43
    check-cast v11, Lnc/z;

    .line 44
    .line 45
    or-int/lit8 v5, v5, 0x20

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    const/4 v4, 0x4

    .line 49
    aget-object v12, v0, v4

    .line 50
    .line 51
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v12

    .line 55
    check-cast v12, Lqz0/a;

    .line 56
    .line 57
    invoke-interface {p1, p0, v4, v12, v10}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    move-object v10, v4

    .line 62
    check-cast v10, Ljava/util/List;

    .line 63
    .line 64
    or-int/lit8 v5, v5, 0x10

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_2
    sget-object v4, Lac/y;->a:Lac/y;

    .line 68
    .line 69
    const/4 v12, 0x3

    .line 70
    invoke-interface {p1, p0, v12, v4, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    move-object v9, v4

    .line 75
    check-cast v9, Lac/a0;

    .line 76
    .line 77
    or-int/lit8 v5, v5, 0x8

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_3
    const/4 v4, 0x2

    .line 81
    invoke-interface {p1, p0, v4}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 82
    .line 83
    .line 84
    move-result v8

    .line 85
    or-int/lit8 v5, v5, 0x4

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_4
    aget-object v4, v0, v1

    .line 89
    .line 90
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    check-cast v4, Lqz0/a;

    .line 95
    .line 96
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    move-object v7, v4

    .line 101
    check-cast v7, Ljava/util/List;

    .line 102
    .line 103
    or-int/lit8 v5, v5, 0x2

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :pswitch_5
    aget-object v4, v0, v2

    .line 107
    .line 108
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v4

    .line 112
    check-cast v4, Lqz0/a;

    .line 113
    .line 114
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    move-object v6, v4

    .line 119
    check-cast v6, Ljava/util/List;

    .line 120
    .line 121
    or-int/lit8 v5, v5, 0x1

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :pswitch_6
    move v3, v2

    .line 125
    goto :goto_0

    .line 126
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 127
    .line 128
    .line 129
    new-instance v4, Lkg/a0;

    .line 130
    .line 131
    invoke-direct/range {v4 .. v11}, Lkg/a0;-><init>(ILjava/util/List;Ljava/util/List;ZLac/a0;Ljava/util/List;Lnc/z;)V

    .line 132
    .line 133
    .line 134
    return-object v4

    .line 135
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
    sget-object p0, Lkg/y;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Lkg/a0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lkg/y;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lkg/a0;->g:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v2, v0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lqz0/a;

    .line 24
    .line 25
    iget-object v3, p2, Lkg/a0;->a:Ljava/util/List;

    .line 26
    .line 27
    iget-object v4, p2, Lkg/a0;->f:Lnc/z;

    .line 28
    .line 29
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    aget-object v2, v0, v1

    .line 34
    .line 35
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lqz0/a;

    .line 40
    .line 41
    iget-object v3, p2, Lkg/a0;->b:Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    const/4 v1, 0x2

    .line 47
    iget-boolean v2, p2, Lkg/a0;->c:Z

    .line 48
    .line 49
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 50
    .line 51
    .line 52
    sget-object v1, Lac/y;->a:Lac/y;

    .line 53
    .line 54
    iget-object v2, p2, Lkg/a0;->d:Lac/a0;

    .line 55
    .line 56
    const/4 v3, 0x3

    .line 57
    invoke-interface {p1, p0, v3, v1, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const/4 v1, 0x4

    .line 61
    aget-object v0, v0, v1

    .line 62
    .line 63
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    check-cast v0, Lqz0/a;

    .line 68
    .line 69
    iget-object p2, p2, Lkg/a0;->e:Ljava/util/List;

    .line 70
    .line 71
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    if-eqz p2, :cond_0

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_0
    if-eqz v4, :cond_1

    .line 82
    .line 83
    :goto_0
    sget-object p2, Lnc/x;->a:Lnc/x;

    .line 84
    .line 85
    const/4 v0, 0x5

    .line 86
    invoke-interface {p1, p0, v0, p2, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 90
    .line 91
    .line 92
    return-void
.end method
