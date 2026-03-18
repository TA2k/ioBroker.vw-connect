.class public final synthetic Lwb/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lwb/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lwb/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lwb/a;->a:Lwb/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.common.api.chargingcard.models.ChargingCard"

    .line 11
    .line 12
    const/4 v3, 0x7

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "id"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "number"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "status"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "assetId"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "isHomeCharging"

    .line 38
    .line 39
    const/4 v3, 0x1

    .line 40
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "isPublicCharging"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "label"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    sput-object v1, Lwb/a;->descriptor:Lsz0/g;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lwb/e;->k:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x7

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
    aput-object v1, v0, v2

    .line 13
    .line 14
    const/4 v2, 0x2

    .line 15
    aget-object p0, p0, v2

    .line 16
    .line 17
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    aput-object p0, v0, v2

    .line 22
    .line 23
    const/4 p0, 0x3

    .line 24
    aput-object v1, v0, p0

    .line 25
    .line 26
    sget-object p0, Luz0/g;->a:Luz0/g;

    .line 27
    .line 28
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    const/4 v3, 0x4

    .line 33
    aput-object v2, v0, v3

    .line 34
    .line 35
    const/4 v2, 0x5

    .line 36
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    aput-object p0, v0, v2

    .line 41
    .line 42
    const/4 p0, 0x6

    .line 43
    aput-object v1, v0, p0

    .line 44
    .line 45
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object p0, Lwb/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lwb/e;->k:[Llx0/i;

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
    const/4 v4, 0x6

    .line 37
    invoke-interface {p1, p0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v12

    .line 41
    or-int/lit8 v5, v5, 0x40

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :pswitch_1
    sget-object v4, Luz0/g;->a:Luz0/g;

    .line 45
    .line 46
    const/4 v13, 0x5

    .line 47
    invoke-interface {p1, p0, v13, v4, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    move-object v11, v4

    .line 52
    check-cast v11, Ljava/lang/Boolean;

    .line 53
    .line 54
    or-int/lit8 v5, v5, 0x20

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_2
    sget-object v4, Luz0/g;->a:Luz0/g;

    .line 58
    .line 59
    const/4 v13, 0x4

    .line 60
    invoke-interface {p1, p0, v13, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    move-object v10, v4

    .line 65
    check-cast v10, Ljava/lang/Boolean;

    .line 66
    .line 67
    or-int/lit8 v5, v5, 0x10

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :pswitch_3
    const/4 v4, 0x3

    .line 71
    invoke-interface {p1, p0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    or-int/lit8 v5, v5, 0x8

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_4
    const/4 v4, 0x2

    .line 79
    aget-object v13, v0, v4

    .line 80
    .line 81
    invoke-interface {v13}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v13

    .line 85
    check-cast v13, Lqz0/a;

    .line 86
    .line 87
    invoke-interface {p1, p0, v4, v13, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    move-object v8, v4

    .line 92
    check-cast v8, Lwb/d;

    .line 93
    .line 94
    or-int/lit8 v5, v5, 0x4

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_5
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v7

    .line 101
    or-int/lit8 v5, v5, 0x2

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :pswitch_6
    invoke-interface {p1, p0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    or-int/lit8 v5, v5, 0x1

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :pswitch_7
    move v3, v2

    .line 112
    goto :goto_0

    .line 113
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 114
    .line 115
    .line 116
    new-instance v4, Lwb/e;

    .line 117
    .line 118
    invoke-direct/range {v4 .. v12}, Lwb/e;-><init>(ILjava/lang/String;Ljava/lang/String;Lwb/d;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    return-object v4

    .line 122
    nop

    .line 123
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
    sget-object p0, Lwb/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Lwb/e;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lwb/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lwb/e;->k:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lwb/e;->d:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lwb/e;->i:Ljava/lang/Boolean;

    .line 19
    .line 20
    iget-object v3, p2, Lwb/e;->h:Ljava/lang/Boolean;

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
    iget-object v4, p2, Lwb/e;->e:Ljava/lang/String;

    .line 28
    .line 29
    invoke-interface {p1, p0, v1, v4}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    aget-object v0, v0, v1

    .line 34
    .line 35
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lqz0/a;

    .line 40
    .line 41
    iget-object v4, p2, Lwb/e;->f:Lwb/d;

    .line 42
    .line 43
    invoke-interface {p1, p0, v1, v0, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    const/4 v0, 0x3

    .line 47
    iget-object v1, p2, Lwb/e;->g:Ljava/lang/String;

    .line 48
    .line 49
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_0

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    if-eqz v3, :cond_1

    .line 60
    .line 61
    :goto_0
    sget-object v0, Luz0/g;->a:Luz0/g;

    .line 62
    .line 63
    const/4 v1, 0x4

    .line 64
    invoke-interface {p1, p0, v1, v0, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_2

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_2
    if-eqz v2, :cond_3

    .line 75
    .line 76
    :goto_1
    sget-object v0, Luz0/g;->a:Luz0/g;

    .line 77
    .line 78
    const/4 v1, 0x5

    .line 79
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_3
    const/4 v0, 0x6

    .line 83
    iget-object p2, p2, Lwb/e;->j:Ljava/lang/String;

    .line 84
    .line 85
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 89
    .line 90
    .line 91
    return-void
.end method
