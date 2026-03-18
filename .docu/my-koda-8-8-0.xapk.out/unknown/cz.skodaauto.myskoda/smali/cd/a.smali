.class public final synthetic Lcd/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lcd/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcd/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcd/a;->a:Lcd/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.charginghistory.models.home.HomeChargingHistoryDetail"

    .line 11
    .line 12
    const/16 v3, 0xa

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
    const-string v0, "chargingSessionId"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "stationName"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "stationImageId"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "formattedDuration"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "formattedStartDateTime"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "formattedEndDateTime"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "formattedEnergy"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    const-string v0, "formattedAuthentication"

    .line 59
    .line 60
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 61
    .line 62
    .line 63
    const-string v0, "containsMissingData"

    .line 64
    .line 65
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 66
    .line 67
    .line 68
    sput-object v1, Lcd/a;->descriptor:Lsz0/g;

    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 5

    .line 1
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const/16 v3, 0xa

    .line 16
    .line 17
    new-array v3, v3, [Lqz0/a;

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    aput-object p0, v3, v4

    .line 21
    .line 22
    const/4 v4, 0x1

    .line 23
    aput-object p0, v3, v4

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    aput-object p0, v3, v4

    .line 27
    .line 28
    const/4 v4, 0x3

    .line 29
    aput-object p0, v3, v4

    .line 30
    .line 31
    const/4 v4, 0x4

    .line 32
    aput-object v0, v3, v4

    .line 33
    .line 34
    const/4 v0, 0x5

    .line 35
    aput-object p0, v3, v0

    .line 36
    .line 37
    const/4 v0, 0x6

    .line 38
    aput-object p0, v3, v0

    .line 39
    .line 40
    const/4 p0, 0x7

    .line 41
    aput-object v1, v3, p0

    .line 42
    .line 43
    const/16 p0, 0x8

    .line 44
    .line 45
    aput-object v2, v3, p0

    .line 46
    .line 47
    sget-object p0, Luz0/g;->a:Luz0/g;

    .line 48
    .line 49
    const/16 v0, 0x9

    .line 50
    .line 51
    aput-object p0, v3, v0

    .line 52
    .line 53
    return-object v3
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    sget-object v0, Lcd/a;->descriptor:Lsz0/g;

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
    const/4 v2, 0x1

    .line 10
    const/4 v4, 0x0

    .line 11
    move-object v7, v4

    .line 12
    move-object v8, v7

    .line 13
    move-object v9, v8

    .line 14
    move-object v10, v9

    .line 15
    move-object v11, v10

    .line 16
    move-object v12, v11

    .line 17
    move-object v13, v12

    .line 18
    move-object v14, v13

    .line 19
    move-object v15, v14

    .line 20
    const/4 v6, 0x0

    .line 21
    const/16 v16, 0x0

    .line 22
    .line 23
    move v4, v2

    .line 24
    :goto_0
    if-eqz v4, :cond_0

    .line 25
    .line 26
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    packed-switch v5, :pswitch_data_0

    .line 31
    .line 32
    .line 33
    new-instance v0, Lqz0/k;

    .line 34
    .line 35
    invoke-direct {v0, v5}, Lqz0/k;-><init>(I)V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :pswitch_0
    const/16 v5, 0x9

    .line 40
    .line 41
    invoke-interface {v1, v0, v5}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 42
    .line 43
    .line 44
    move-result v16

    .line 45
    or-int/lit16 v6, v6, 0x200

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    sget-object v5, Luz0/q1;->a:Luz0/q1;

    .line 49
    .line 50
    const/16 v3, 0x8

    .line 51
    .line 52
    invoke-interface {v1, v0, v3, v5, v15}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    move-object v15, v3

    .line 57
    check-cast v15, Ljava/lang/String;

    .line 58
    .line 59
    or-int/lit16 v6, v6, 0x100

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_2
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 63
    .line 64
    const/4 v5, 0x7

    .line 65
    invoke-interface {v1, v0, v5, v3, v14}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    move-object v14, v3

    .line 70
    check-cast v14, Ljava/lang/String;

    .line 71
    .line 72
    or-int/lit16 v6, v6, 0x80

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_3
    const/4 v3, 0x6

    .line 76
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v13

    .line 80
    or-int/lit8 v6, v6, 0x40

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_4
    const/4 v3, 0x5

    .line 84
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v12

    .line 88
    or-int/lit8 v6, v6, 0x20

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :pswitch_5
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 92
    .line 93
    const/4 v5, 0x4

    .line 94
    invoke-interface {v1, v0, v5, v3, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    move-object v11, v3

    .line 99
    check-cast v11, Ljava/lang/String;

    .line 100
    .line 101
    or-int/lit8 v6, v6, 0x10

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :pswitch_6
    const/4 v3, 0x3

    .line 105
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v10

    .line 109
    or-int/lit8 v6, v6, 0x8

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :pswitch_7
    const/4 v3, 0x2

    .line 113
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v9

    .line 117
    or-int/lit8 v6, v6, 0x4

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :pswitch_8
    invoke-interface {v1, v0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    or-int/lit8 v6, v6, 0x2

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :pswitch_9
    const/4 v3, 0x0

    .line 128
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    or-int/lit8 v6, v6, 0x1

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :pswitch_a
    const/4 v3, 0x0

    .line 136
    move v4, v3

    .line 137
    goto :goto_0

    .line 138
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 139
    .line 140
    .line 141
    new-instance v5, Lcd/c;

    .line 142
    .line 143
    invoke-direct/range {v5 .. v16}, Lcd/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 144
    .line 145
    .line 146
    return-object v5

    .line 147
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_a
        :pswitch_9
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
    sget-object p0, Lcd/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lcd/c;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lcd/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const/4 v0, 0x0

    .line 15
    iget-object v1, p2, Lcd/c;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    iget-object v1, p2, Lcd/c;->b:Ljava/lang/String;

    .line 22
    .line 23
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x2

    .line 27
    iget-object v1, p2, Lcd/c;->c:Ljava/lang/String;

    .line 28
    .line 29
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x3

    .line 33
    iget-object v1, p2, Lcd/c;->d:Ljava/lang/String;

    .line 34
    .line 35
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 39
    .line 40
    iget-object v1, p2, Lcd/c;->e:Ljava/lang/String;

    .line 41
    .line 42
    const/4 v2, 0x4

    .line 43
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    const/4 v1, 0x5

    .line 47
    iget-object v2, p2, Lcd/c;->f:Ljava/lang/String;

    .line 48
    .line 49
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const/4 v1, 0x6

    .line 53
    iget-object v2, p2, Lcd/c;->g:Ljava/lang/String;

    .line 54
    .line 55
    invoke-interface {p1, p0, v1, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const/4 v1, 0x7

    .line 59
    iget-object v2, p2, Lcd/c;->h:Ljava/lang/String;

    .line 60
    .line 61
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    const/16 v1, 0x8

    .line 65
    .line 66
    iget-object v2, p2, Lcd/c;->i:Ljava/lang/String;

    .line 67
    .line 68
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    const/16 v0, 0x9

    .line 72
    .line 73
    iget-boolean p2, p2, Lcd/c;->j:Z

    .line 74
    .line 75
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 76
    .line 77
    .line 78
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method
