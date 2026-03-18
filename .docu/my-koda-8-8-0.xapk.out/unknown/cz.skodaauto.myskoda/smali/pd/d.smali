.class public final synthetic Lpd/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lpd/d;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpd/d;->a:Lpd/d;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.ChargingStatisticsEntry"

    .line 11
    .line 12
    const/16 v3, 0x8

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "id"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "title"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "subtitle"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "primaryValue"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "secondaryValue"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "chargingType"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "details"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "hideDetailView"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    sput-object v1, Lpd/d;->descriptor:Lsz0/g;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lpd/h;->i:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    aput-object v1, v0, v2

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    aput-object v1, v0, v2

    .line 14
    .line 15
    const/4 v2, 0x2

    .line 16
    aput-object v1, v0, v2

    .line 17
    .line 18
    const/4 v2, 0x3

    .line 19
    aput-object v1, v0, v2

    .line 20
    .line 21
    const/4 v2, 0x4

    .line 22
    aput-object v1, v0, v2

    .line 23
    .line 24
    const/4 v1, 0x5

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
    const/4 p0, 0x6

    .line 34
    sget-object v1, Lpd/i;->a:Lpd/i;

    .line 35
    .line 36
    aput-object v1, v0, p0

    .line 37
    .line 38
    const/4 p0, 0x7

    .line 39
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 40
    .line 41
    aput-object v1, v0, p0

    .line 42
    .line 43
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    sget-object v0, Lpd/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Lpd/h;->i:[Llx0/i;

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    const/4 v5, 0x0

    .line 13
    move-object v8, v5

    .line 14
    move-object v9, v8

    .line 15
    move-object v10, v9

    .line 16
    move-object v11, v10

    .line 17
    move-object v12, v11

    .line 18
    move-object v13, v12

    .line 19
    move-object v14, v13

    .line 20
    const/4 v7, 0x0

    .line 21
    const/4 v15, 0x0

    .line 22
    move v5, v3

    .line 23
    :goto_0
    if-eqz v5, :cond_0

    .line 24
    .line 25
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    packed-switch v6, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    new-instance v0, Lqz0/k;

    .line 33
    .line 34
    invoke-direct {v0, v6}, Lqz0/k;-><init>(I)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :pswitch_0
    const/4 v6, 0x7

    .line 39
    invoke-interface {v1, v0, v6}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 40
    .line 41
    .line 42
    move-result v15

    .line 43
    or-int/lit16 v7, v7, 0x80

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    sget-object v6, Lpd/i;->a:Lpd/i;

    .line 47
    .line 48
    const/4 v4, 0x6

    .line 49
    invoke-interface {v1, v0, v4, v6, v14}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    move-object v14, v4

    .line 54
    check-cast v14, Lpd/m;

    .line 55
    .line 56
    or-int/lit8 v7, v7, 0x40

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :pswitch_2
    const/4 v4, 0x5

    .line 60
    aget-object v6, v2, v4

    .line 61
    .line 62
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v6

    .line 66
    check-cast v6, Lqz0/a;

    .line 67
    .line 68
    invoke-interface {v1, v0, v4, v6, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    move-object v13, v4

    .line 73
    check-cast v13, Lpd/f;

    .line 74
    .line 75
    or-int/lit8 v7, v7, 0x20

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_3
    const/4 v4, 0x4

    .line 79
    invoke-interface {v1, v0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v12

    .line 83
    or-int/lit8 v7, v7, 0x10

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :pswitch_4
    const/4 v4, 0x3

    .line 87
    invoke-interface {v1, v0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v11

    .line 91
    or-int/lit8 v7, v7, 0x8

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_5
    const/4 v4, 0x2

    .line 95
    invoke-interface {v1, v0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v10

    .line 99
    or-int/lit8 v7, v7, 0x4

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :pswitch_6
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    or-int/lit8 v7, v7, 0x2

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :pswitch_7
    const/4 v4, 0x0

    .line 110
    invoke-interface {v1, v0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v8

    .line 114
    or-int/lit8 v7, v7, 0x1

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :pswitch_8
    const/4 v4, 0x0

    .line 118
    move v5, v4

    .line 119
    goto :goto_0

    .line 120
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 121
    .line 122
    .line 123
    new-instance v6, Lpd/h;

    .line 124
    .line 125
    invoke-direct/range {v6 .. v15}, Lpd/h;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lpd/f;Lpd/m;Z)V

    .line 126
    .line 127
    .line 128
    return-object v6

    .line 129
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_8
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
    sget-object p0, Lpd/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lpd/h;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lpd/d;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lpd/h;->i:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    iget-object v2, p2, Lpd/h;->a:Ljava/lang/String;

    .line 18
    .line 19
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v1, 0x1

    .line 23
    iget-object v2, p2, Lpd/h;->b:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x2

    .line 29
    iget-object v2, p2, Lpd/h;->c:Ljava/lang/String;

    .line 30
    .line 31
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const/4 v1, 0x3

    .line 35
    iget-object v2, p2, Lpd/h;->d:Ljava/lang/String;

    .line 36
    .line 37
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x4

    .line 41
    iget-object v2, p2, Lpd/h;->e:Ljava/lang/String;

    .line 42
    .line 43
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const/4 v1, 0x5

    .line 47
    aget-object v0, v0, v1

    .line 48
    .line 49
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, Lqz0/a;

    .line 54
    .line 55
    iget-object v2, p2, Lpd/h;->f:Lpd/f;

    .line 56
    .line 57
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    sget-object v0, Lpd/i;->a:Lpd/i;

    .line 61
    .line 62
    iget-object v1, p2, Lpd/h;->g:Lpd/m;

    .line 63
    .line 64
    const/4 v2, 0x6

    .line 65
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    const/4 v0, 0x7

    .line 69
    iget-boolean p2, p2, Lpd/h;->h:Z

    .line 70
    .line 71
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 72
    .line 73
    .line 74
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method
