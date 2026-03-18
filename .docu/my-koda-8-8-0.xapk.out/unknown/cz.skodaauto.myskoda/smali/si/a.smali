.class public final synthetic Lsi/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lsi/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lsi/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lsi/a;->a:Lsi/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.sdk.headless.chargingsession.ChargingSession"

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
    const-string v0, "authId"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "evseId"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "updatedAt"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "status"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "locationId"

    .line 44
    .line 45
    const/4 v2, 0x1

    .line 46
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 47
    .line 48
    .line 49
    const-string v0, "chargingPointId"

    .line 50
    .line 51
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 52
    .line 53
    .line 54
    const-string v0, "connectorId"

    .line 55
    .line 56
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 57
    .line 58
    .line 59
    const-string v0, "energyConsumed"

    .line 60
    .line 61
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 62
    .line 63
    .line 64
    const-string v0, "startedAt"

    .line 65
    .line 66
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 67
    .line 68
    .line 69
    sput-object v1, Lsi/a;->descriptor:Lsz0/g;

    .line 70
    .line 71
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lsi/e;->k:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0xa

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
    aget-object p0, p0, v2

    .line 23
    .line 24
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    aput-object p0, v0, v2

    .line 29
    .line 30
    const/4 p0, 0x5

    .line 31
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    aput-object v2, v0, p0

    .line 36
    .line 37
    const/4 p0, 0x6

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
    const/4 p0, 0x7

    .line 45
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    aput-object v2, v0, p0

    .line 50
    .line 51
    sget-object p0, Luz0/u;->a:Luz0/u;

    .line 52
    .line 53
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    const/16 v2, 0x8

    .line 58
    .line 59
    aput-object p0, v0, v2

    .line 60
    .line 61
    const/16 p0, 0x9

    .line 62
    .line 63
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    aput-object v1, v0, p0

    .line 68
    .line 69
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    sget-object v0, Lsi/a;->descriptor:Lsz0/g;

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
    sget-object v2, Lsi/e;->k:[Llx0/i;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    move-object v6, v5

    .line 13
    move-object v8, v6

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
    move-object v15, v14

    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v7, 0x1

    .line 23
    :goto_0
    if-eqz v7, :cond_0

    .line 24
    .line 25
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    packed-switch v3, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    new-instance v0, Lqz0/k;

    .line 33
    .line 34
    invoke-direct {v0, v3}, Lqz0/k;-><init>(I)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :pswitch_0
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 39
    .line 40
    move-object/from16 v16, v2

    .line 41
    .line 42
    const/16 v2, 0x9

    .line 43
    .line 44
    invoke-interface {v1, v0, v2, v3, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    move-object v6, v2

    .line 49
    check-cast v6, Ljava/lang/String;

    .line 50
    .line 51
    or-int/lit16 v4, v4, 0x200

    .line 52
    .line 53
    :goto_1
    move-object/from16 v2, v16

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :pswitch_1
    move-object/from16 v16, v2

    .line 57
    .line 58
    sget-object v2, Luz0/u;->a:Luz0/u;

    .line 59
    .line 60
    const/16 v3, 0x8

    .line 61
    .line 62
    invoke-interface {v1, v0, v3, v2, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    move-object v5, v2

    .line 67
    check-cast v5, Ljava/lang/Double;

    .line 68
    .line 69
    or-int/lit16 v4, v4, 0x100

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :pswitch_2
    move-object/from16 v16, v2

    .line 73
    .line 74
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 75
    .line 76
    const/4 v3, 0x7

    .line 77
    invoke-interface {v1, v0, v3, v2, v15}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    move-object v15, v2

    .line 82
    check-cast v15, Ljava/lang/String;

    .line 83
    .line 84
    or-int/lit16 v4, v4, 0x80

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :pswitch_3
    move-object/from16 v16, v2

    .line 88
    .line 89
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 90
    .line 91
    const/4 v3, 0x6

    .line 92
    invoke-interface {v1, v0, v3, v2, v14}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    move-object v14, v2

    .line 97
    check-cast v14, Ljava/lang/String;

    .line 98
    .line 99
    or-int/lit8 v4, v4, 0x40

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :pswitch_4
    move-object/from16 v16, v2

    .line 103
    .line 104
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 105
    .line 106
    const/4 v3, 0x5

    .line 107
    invoke-interface {v1, v0, v3, v2, v13}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    move-object v13, v2

    .line 112
    check-cast v13, Ljava/lang/String;

    .line 113
    .line 114
    or-int/lit8 v4, v4, 0x20

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :pswitch_5
    move-object/from16 v16, v2

    .line 118
    .line 119
    const/4 v2, 0x4

    .line 120
    aget-object v3, v16, v2

    .line 121
    .line 122
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    check-cast v3, Lqz0/a;

    .line 127
    .line 128
    invoke-interface {v1, v0, v2, v3, v12}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    move-object v12, v2

    .line 133
    check-cast v12, Lsi/d;

    .line 134
    .line 135
    or-int/lit8 v4, v4, 0x10

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :pswitch_6
    move-object/from16 v16, v2

    .line 139
    .line 140
    const/4 v2, 0x3

    .line 141
    invoke-interface {v1, v0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v11

    .line 145
    or-int/lit8 v4, v4, 0x8

    .line 146
    .line 147
    goto :goto_1

    .line 148
    :pswitch_7
    move-object/from16 v16, v2

    .line 149
    .line 150
    const/4 v2, 0x2

    .line 151
    invoke-interface {v1, v0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v10

    .line 155
    or-int/lit8 v4, v4, 0x4

    .line 156
    .line 157
    goto :goto_1

    .line 158
    :pswitch_8
    move-object/from16 v16, v2

    .line 159
    .line 160
    const/4 v2, 0x1

    .line 161
    invoke-interface {v1, v0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    or-int/lit8 v4, v4, 0x2

    .line 166
    .line 167
    goto :goto_1

    .line 168
    :pswitch_9
    move-object/from16 v16, v2

    .line 169
    .line 170
    const/4 v2, 0x1

    .line 171
    const/4 v3, 0x0

    .line 172
    invoke-interface {v1, v0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v8

    .line 176
    or-int/lit8 v4, v4, 0x1

    .line 177
    .line 178
    goto :goto_1

    .line 179
    :pswitch_a
    const/4 v3, 0x0

    .line 180
    move v7, v3

    .line 181
    goto/16 :goto_0

    .line 182
    .line 183
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 184
    .line 185
    .line 186
    move-object/from16 v17, v6

    .line 187
    .line 188
    new-instance v6, Lsi/e;

    .line 189
    .line 190
    move v7, v4

    .line 191
    move-object/from16 v16, v5

    .line 192
    .line 193
    invoke-direct/range {v6 .. v17}, Lsi/e;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lsi/d;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    return-object v6

    .line 197
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
    sget-object p0, Lsi/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 8

    .line 1
    check-cast p2, Lsi/e;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lsi/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lsi/e;->k:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lsi/e;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lsi/e;->j:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p2, Lsi/e;->i:Ljava/lang/Double;

    .line 21
    .line 22
    iget-object v4, p2, Lsi/e;->h:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v5, p2, Lsi/e;->g:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v6, p2, Lsi/e;->f:Ljava/lang/String;

    .line 27
    .line 28
    const/4 v7, 0x0

    .line 29
    invoke-interface {p1, p0, v7, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    iget-object v7, p2, Lsi/e;->b:Ljava/lang/String;

    .line 34
    .line 35
    invoke-interface {p1, p0, v1, v7}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 v1, 0x2

    .line 39
    iget-object v7, p2, Lsi/e;->c:Ljava/lang/String;

    .line 40
    .line 41
    invoke-interface {p1, p0, v1, v7}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const/4 v1, 0x3

    .line 45
    iget-object v7, p2, Lsi/e;->d:Ljava/lang/String;

    .line 46
    .line 47
    invoke-interface {p1, p0, v1, v7}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const/4 v1, 0x4

    .line 51
    aget-object v0, v0, v1

    .line 52
    .line 53
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    check-cast v0, Lqz0/a;

    .line 58
    .line 59
    iget-object p2, p2, Lsi/e;->e:Lsi/d;

    .line 60
    .line 61
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 65
    .line 66
    .line 67
    move-result p2

    .line 68
    if-eqz p2, :cond_0

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    if-eqz v6, :cond_1

    .line 72
    .line 73
    :goto_0
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 74
    .line 75
    const/4 v0, 0x5

    .line 76
    invoke-interface {p1, p0, v0, p2, v6}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    if-eqz p2, :cond_2

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_2
    if-eqz v5, :cond_3

    .line 87
    .line 88
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 89
    .line 90
    const/4 v0, 0x6

    .line 91
    invoke-interface {p1, p0, v0, p2, v5}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    if-eqz p2, :cond_4

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_4
    if-eqz v4, :cond_5

    .line 102
    .line 103
    :goto_2
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 104
    .line 105
    const/4 v0, 0x7

    .line 106
    invoke-interface {p1, p0, v0, p2, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_5
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    if-eqz p2, :cond_6

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_6
    if-eqz v3, :cond_7

    .line 117
    .line 118
    :goto_3
    sget-object p2, Luz0/u;->a:Luz0/u;

    .line 119
    .line 120
    const/16 v0, 0x8

    .line 121
    .line 122
    invoke-interface {p1, p0, v0, p2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_7
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 126
    .line 127
    .line 128
    move-result p2

    .line 129
    if-eqz p2, :cond_8

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_8
    if-eqz v2, :cond_9

    .line 133
    .line 134
    :goto_4
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 135
    .line 136
    const/16 v0, 0x9

    .line 137
    .line 138
    invoke-interface {p1, p0, v0, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_9
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 142
    .line 143
    .line 144
    return-void
.end method
