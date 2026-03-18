.class public final synthetic Lpd/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lpd/p0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd/p0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpd/p0;->a:Lpd/p0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.PowerCurveSlot"

    .line 11
    .line 12
    const/16 v3, 0x8

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "actual_soc"

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "charging_power"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "charging_reason"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "current_cost"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "power_limit_infrastructure"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "self_power"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "measurement_date"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "energy_charged"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    sput-object v1, Lpd/p0;->descriptor:Lsz0/g;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 9

    .line 1
    sget-object p0, Luz0/u;->a:Luz0/u;

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
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 12
    .line 13
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 22
    .line 23
    .line 24
    move-result-object v5

    .line 25
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 26
    .line 27
    .line 28
    move-result-object v6

    .line 29
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const/16 v7, 0x8

    .line 38
    .line 39
    new-array v7, v7, [Lqz0/a;

    .line 40
    .line 41
    const/4 v8, 0x0

    .line 42
    aput-object v0, v7, v8

    .line 43
    .line 44
    const/4 v0, 0x1

    .line 45
    aput-object v1, v7, v0

    .line 46
    .line 47
    const/4 v0, 0x2

    .line 48
    aput-object v3, v7, v0

    .line 49
    .line 50
    const/4 v0, 0x3

    .line 51
    aput-object v4, v7, v0

    .line 52
    .line 53
    const/4 v0, 0x4

    .line 54
    aput-object v5, v7, v0

    .line 55
    .line 56
    const/4 v0, 0x5

    .line 57
    aput-object v6, v7, v0

    .line 58
    .line 59
    const/4 v0, 0x6

    .line 60
    aput-object v2, v7, v0

    .line 61
    .line 62
    const/4 v0, 0x7

    .line 63
    aput-object p0, v7, v0

    .line 64
    .line 65
    return-object v7
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object p0, Lpd/p0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v4, v1

    .line 11
    move-object v5, v2

    .line 12
    move-object v6, v5

    .line 13
    move-object v7, v6

    .line 14
    move-object v8, v7

    .line 15
    move-object v9, v8

    .line 16
    move-object v10, v9

    .line 17
    move-object v11, v10

    .line 18
    move-object v12, v11

    .line 19
    move v2, v0

    .line 20
    :goto_0
    if-eqz v2, :cond_0

    .line 21
    .line 22
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    packed-switch v3, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    new-instance p0, Lqz0/k;

    .line 30
    .line 31
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :pswitch_0
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 36
    .line 37
    const/4 v13, 0x7

    .line 38
    invoke-interface {p1, p0, v13, v3, v12}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    move-object v12, v3

    .line 43
    check-cast v12, Ljava/lang/Double;

    .line 44
    .line 45
    or-int/lit16 v4, v4, 0x80

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 49
    .line 50
    const/4 v13, 0x6

    .line 51
    invoke-interface {p1, p0, v13, v3, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    move-object v11, v3

    .line 56
    check-cast v11, Ljava/lang/String;

    .line 57
    .line 58
    or-int/lit8 v4, v4, 0x40

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :pswitch_2
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 62
    .line 63
    const/4 v13, 0x5

    .line 64
    invoke-interface {p1, p0, v13, v3, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    move-object v10, v3

    .line 69
    check-cast v10, Ljava/lang/Double;

    .line 70
    .line 71
    or-int/lit8 v4, v4, 0x20

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_3
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 75
    .line 76
    const/4 v13, 0x4

    .line 77
    invoke-interface {p1, p0, v13, v3, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    move-object v9, v3

    .line 82
    check-cast v9, Ljava/lang/Double;

    .line 83
    .line 84
    or-int/lit8 v4, v4, 0x10

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :pswitch_4
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 88
    .line 89
    const/4 v13, 0x3

    .line 90
    invoke-interface {p1, p0, v13, v3, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    move-object v8, v3

    .line 95
    check-cast v8, Ljava/lang/Double;

    .line 96
    .line 97
    or-int/lit8 v4, v4, 0x8

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :pswitch_5
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 101
    .line 102
    const/4 v13, 0x2

    .line 103
    invoke-interface {p1, p0, v13, v3, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    move-object v7, v3

    .line 108
    check-cast v7, Ljava/lang/String;

    .line 109
    .line 110
    or-int/lit8 v4, v4, 0x4

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :pswitch_6
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 114
    .line 115
    invoke-interface {p1, p0, v0, v3, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    move-object v6, v3

    .line 120
    check-cast v6, Ljava/lang/Double;

    .line 121
    .line 122
    or-int/lit8 v4, v4, 0x2

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :pswitch_7
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 126
    .line 127
    invoke-interface {p1, p0, v1, v3, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    move-object v5, v3

    .line 132
    check-cast v5, Ljava/lang/Double;

    .line 133
    .line 134
    or-int/lit8 v4, v4, 0x1

    .line 135
    .line 136
    goto :goto_0

    .line 137
    :pswitch_8
    move v2, v1

    .line 138
    goto :goto_0

    .line 139
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 140
    .line 141
    .line 142
    new-instance v3, Lpd/r0;

    .line 143
    .line 144
    invoke-direct/range {v3 .. v12}, Lpd/r0;-><init>(ILjava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/Double;)V

    .line 145
    .line 146
    .line 147
    return-object v3

    .line 148
    nop

    .line 149
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
    sget-object p0, Lpd/p0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 9

    .line 1
    check-cast p2, Lpd/r0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lpd/r0;->k:Ljava/lang/Double;

    .line 9
    .line 10
    iget-object v0, p2, Lpd/r0;->j:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v1, p2, Lpd/r0;->i:Ljava/lang/Double;

    .line 13
    .line 14
    iget-object v2, p2, Lpd/r0;->h:Ljava/lang/Double;

    .line 15
    .line 16
    iget-object v3, p2, Lpd/r0;->g:Ljava/lang/Double;

    .line 17
    .line 18
    iget-object v4, p2, Lpd/r0;->f:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v5, p2, Lpd/r0;->e:Ljava/lang/Double;

    .line 21
    .line 22
    iget-object p2, p2, Lpd/r0;->d:Ljava/lang/Double;

    .line 23
    .line 24
    sget-object v6, Lpd/p0;->descriptor:Lsz0/g;

    .line 25
    .line 26
    invoke-interface {p1, v6}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    if-eqz v7, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    if-eqz p2, :cond_1

    .line 38
    .line 39
    :goto_0
    sget-object v7, Luz0/u;->a:Luz0/u;

    .line 40
    .line 41
    const/4 v8, 0x0

    .line 42
    invoke-interface {p1, v6, v8, v7, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    if-eqz v5, :cond_3

    .line 53
    .line 54
    :goto_1
    sget-object p2, Luz0/u;->a:Luz0/u;

    .line 55
    .line 56
    const/4 v7, 0x1

    .line 57
    invoke-interface {p1, v6, v7, p2, v5}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_3
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-eqz p2, :cond_4

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    if-eqz v4, :cond_5

    .line 68
    .line 69
    :goto_2
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 70
    .line 71
    const/4 v5, 0x2

    .line 72
    invoke-interface {p1, v6, v5, p2, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    :cond_5
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_6

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_6
    if-eqz v3, :cond_7

    .line 83
    .line 84
    :goto_3
    sget-object p2, Luz0/u;->a:Luz0/u;

    .line 85
    .line 86
    const/4 v4, 0x3

    .line 87
    invoke-interface {p1, v6, v4, p2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_7
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    if-eqz p2, :cond_8

    .line 95
    .line 96
    goto :goto_4

    .line 97
    :cond_8
    if-eqz v2, :cond_9

    .line 98
    .line 99
    :goto_4
    sget-object p2, Luz0/u;->a:Luz0/u;

    .line 100
    .line 101
    const/4 v3, 0x4

    .line 102
    invoke-interface {p1, v6, v3, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :cond_9
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 106
    .line 107
    .line 108
    move-result p2

    .line 109
    if-eqz p2, :cond_a

    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_a
    if-eqz v1, :cond_b

    .line 113
    .line 114
    :goto_5
    sget-object p2, Luz0/u;->a:Luz0/u;

    .line 115
    .line 116
    const/4 v2, 0x5

    .line 117
    invoke-interface {p1, v6, v2, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_b
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 121
    .line 122
    .line 123
    move-result p2

    .line 124
    if-eqz p2, :cond_c

    .line 125
    .line 126
    goto :goto_6

    .line 127
    :cond_c
    if-eqz v0, :cond_d

    .line 128
    .line 129
    :goto_6
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 130
    .line 131
    const/4 v1, 0x6

    .line 132
    invoke-interface {p1, v6, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_d
    invoke-interface {p1, v6}, Ltz0/b;->e(Lsz0/g;)Z

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    if-eqz p2, :cond_e

    .line 140
    .line 141
    goto :goto_7

    .line 142
    :cond_e
    if-eqz p0, :cond_f

    .line 143
    .line 144
    :goto_7
    sget-object p2, Luz0/u;->a:Luz0/u;

    .line 145
    .line 146
    const/4 v0, 0x7

    .line 147
    invoke-interface {p1, v6, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    :cond_f
    invoke-interface {p1, v6}, Ltz0/b;->b(Lsz0/g;)V

    .line 151
    .line 152
    .line 153
    return-void
.end method
