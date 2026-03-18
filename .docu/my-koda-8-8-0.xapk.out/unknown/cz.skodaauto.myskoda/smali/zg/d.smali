.class public final synthetic Lzg/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lzg/d;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lzg/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzg/d;->a:Lzg/d;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "wallbox"

    .line 11
    .line 12
    const/16 v3, 0x13

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "imageIds"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "status"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "localizedStatus"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "description"

    .line 34
    .line 35
    const/4 v3, 0x1

    .line 36
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 37
    .line 38
    .line 39
    const-string v0, "name"

    .line 40
    .line 41
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 42
    .line 43
    .line 44
    const-string v0, "id"

    .line 45
    .line 46
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 47
    .line 48
    .line 49
    const-string v0, "sessionID"

    .line 50
    .line 51
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 52
    .line 53
    .line 54
    const-string v0, "amountCharged"

    .line 55
    .line 56
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 57
    .line 58
    .line 59
    const-string v0, "formattedStartDateTime"

    .line 60
    .line 61
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 62
    .line 63
    .line 64
    const-string v0, "chargingTime"

    .line 65
    .line 66
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 67
    .line 68
    .line 69
    const-string v0, "formattedAuthentication"

    .line 70
    .line 71
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 72
    .line 73
    .line 74
    const-string v0, "formattedAddress"

    .line 75
    .line 76
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 77
    .line 78
    .line 79
    const-string v0, "authenticationOn"

    .line 80
    .line 81
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 82
    .line 83
    .line 84
    const-string v0, "wallboxAppHyperlink"

    .line 85
    .line 86
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 87
    .line 88
    .line 89
    const-string v0, "isAuthenticationChangeAllowed"

    .line 90
    .line 91
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 92
    .line 93
    .line 94
    const-string v0, "locationId"

    .line 95
    .line 96
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 97
    .line 98
    .line 99
    const-string v0, "pvForecastCharging"

    .line 100
    .line 101
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 102
    .line 103
    .line 104
    const-string v0, "pvSurplusCharging"

    .line 105
    .line 106
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 107
    .line 108
    .line 109
    const-string v0, "isButtonLoading"

    .line 110
    .line 111
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 112
    .line 113
    .line 114
    sput-object v1, Lzg/d;->descriptor:Lsz0/g;

    .line 115
    .line 116
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lzg/h;->w:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0x13

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    aget-object v2, p0, v1

    .line 9
    .line 10
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    aput-object v2, v0, v1

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    aget-object p0, p0, v1

    .line 18
    .line 19
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    aput-object p0, v0, v1

    .line 24
    .line 25
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    aput-object p0, v0, v1

    .line 29
    .line 30
    sget-object v1, Lzg/o;->a:Lzg/o;

    .line 31
    .line 32
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    const/4 v2, 0x3

    .line 37
    aput-object v1, v0, v2

    .line 38
    .line 39
    const/4 v1, 0x4

    .line 40
    aput-object p0, v0, v1

    .line 41
    .line 42
    const/4 v1, 0x5

    .line 43
    aput-object p0, v0, v1

    .line 44
    .line 45
    const/4 v1, 0x6

    .line 46
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    aput-object v2, v0, v1

    .line 51
    .line 52
    const/4 v1, 0x7

    .line 53
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    aput-object v2, v0, v1

    .line 58
    .line 59
    const/16 v1, 0x8

    .line 60
    .line 61
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    aput-object v2, v0, v1

    .line 66
    .line 67
    const/16 v1, 0x9

    .line 68
    .line 69
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    aput-object v2, v0, v1

    .line 74
    .line 75
    const/16 v1, 0xa

    .line 76
    .line 77
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    aput-object v2, v0, v1

    .line 82
    .line 83
    const/16 v1, 0xb

    .line 84
    .line 85
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    aput-object v2, v0, v1

    .line 90
    .line 91
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 92
    .line 93
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    const/16 v3, 0xc

    .line 98
    .line 99
    aput-object v2, v0, v3

    .line 100
    .line 101
    const/16 v2, 0xd

    .line 102
    .line 103
    sget-object v3, Lzg/e2;->a:Lzg/e2;

    .line 104
    .line 105
    aput-object v3, v0, v2

    .line 106
    .line 107
    const/16 v2, 0xe

    .line 108
    .line 109
    aput-object v1, v0, v2

    .line 110
    .line 111
    const/16 v2, 0xf

    .line 112
    .line 113
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    aput-object p0, v0, v2

    .line 118
    .line 119
    sget-object p0, Lzg/o1;->a:Lzg/o1;

    .line 120
    .line 121
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    const/16 v2, 0x10

    .line 126
    .line 127
    aput-object p0, v0, v2

    .line 128
    .line 129
    sget-object p0, Lzg/r1;->a:Lzg/r1;

    .line 130
    .line 131
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    const/16 v2, 0x11

    .line 136
    .line 137
    aput-object p0, v0, v2

    .line 138
    .line 139
    const/16 p0, 0x12

    .line 140
    .line 141
    aput-object v1, v0, p0

    .line 142
    .line 143
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 27

    .line 1
    sget-object v0, Lzg/d;->descriptor:Lsz0/g;

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
    sget-object v2, Lzg/h;->w:[Llx0/i;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    move-object/from16 v16, v2

    .line 13
    .line 14
    move-object v2, v5

    .line 15
    move-object v3, v2

    .line 16
    move-object v4, v3

    .line 17
    move-object v6, v4

    .line 18
    move-object v7, v6

    .line 19
    move-object v9, v7

    .line 20
    move-object v10, v9

    .line 21
    move-object v11, v10

    .line 22
    move-object v12, v11

    .line 23
    move-object v13, v12

    .line 24
    move-object v14, v13

    .line 25
    move-object v15, v14

    .line 26
    move-object/from16 v17, v15

    .line 27
    .line 28
    move-object/from16 v18, v17

    .line 29
    .line 30
    move-object/from16 v19, v18

    .line 31
    .line 32
    move-object/from16 v21, v19

    .line 33
    .line 34
    const/16 p0, 0x0

    .line 35
    .line 36
    const/16 p1, 0x1

    .line 37
    .line 38
    const/4 v8, 0x0

    .line 39
    const/16 v20, 0x1

    .line 40
    .line 41
    const/16 v22, 0x0

    .line 42
    .line 43
    const/16 v26, 0x0

    .line 44
    .line 45
    :goto_0
    if-eqz v20, :cond_0

    .line 46
    .line 47
    move-object/from16 v23, v9

    .line 48
    .line 49
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 50
    .line 51
    .line 52
    move-result v9

    .line 53
    packed-switch v9, :pswitch_data_0

    .line 54
    .line 55
    .line 56
    new-instance v0, Lqz0/k;

    .line 57
    .line 58
    invoke-direct {v0, v9}, Lqz0/k;-><init>(I)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :pswitch_0
    const/16 v9, 0x12

    .line 63
    .line 64
    invoke-interface {v1, v0, v9}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 65
    .line 66
    .line 67
    move-result v26

    .line 68
    const/high16 v9, 0x40000

    .line 69
    .line 70
    or-int/2addr v8, v9

    .line 71
    :goto_1
    move-object/from16 v9, v23

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_1
    sget-object v9, Lzg/r1;->a:Lzg/r1;

    .line 75
    .line 76
    move-object/from16 v24, v11

    .line 77
    .line 78
    const/16 v11, 0x11

    .line 79
    .line 80
    invoke-interface {v1, v0, v11, v9, v13}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v9

    .line 84
    move-object v13, v9

    .line 85
    check-cast v13, Lzg/x1;

    .line 86
    .line 87
    const/high16 v9, 0x20000

    .line 88
    .line 89
    :goto_2
    or-int/2addr v8, v9

    .line 90
    :goto_3
    move-object/from16 v9, v23

    .line 91
    .line 92
    move-object/from16 v11, v24

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :pswitch_2
    move-object/from16 v24, v11

    .line 96
    .line 97
    sget-object v9, Lzg/o1;->a:Lzg/o1;

    .line 98
    .line 99
    const/16 v11, 0x10

    .line 100
    .line 101
    invoke-interface {v1, v0, v11, v9, v12}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v9

    .line 105
    move-object v12, v9

    .line 106
    check-cast v12, Lzg/q1;

    .line 107
    .line 108
    const/high16 v9, 0x10000

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :pswitch_3
    move-object/from16 v24, v11

    .line 112
    .line 113
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 114
    .line 115
    const/16 v11, 0xf

    .line 116
    .line 117
    invoke-interface {v1, v0, v11, v9, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v9

    .line 121
    move-object v10, v9

    .line 122
    check-cast v10, Ljava/lang/String;

    .line 123
    .line 124
    const v9, 0x8000

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :pswitch_4
    move-object/from16 v24, v11

    .line 129
    .line 130
    const/16 v9, 0xe

    .line 131
    .line 132
    invoke-interface {v1, v0, v9}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 133
    .line 134
    .line 135
    move-result v22

    .line 136
    or-int/lit16 v8, v8, 0x4000

    .line 137
    .line 138
    goto :goto_1

    .line 139
    :pswitch_5
    move-object/from16 v24, v11

    .line 140
    .line 141
    sget-object v9, Lzg/e2;->a:Lzg/e2;

    .line 142
    .line 143
    const/16 v11, 0xd

    .line 144
    .line 145
    invoke-interface {v1, v0, v11, v9, v2}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, Lzg/h2;

    .line 150
    .line 151
    or-int/lit16 v8, v8, 0x2000

    .line 152
    .line 153
    goto :goto_3

    .line 154
    :pswitch_6
    move-object/from16 v24, v11

    .line 155
    .line 156
    sget-object v9, Luz0/g;->a:Luz0/g;

    .line 157
    .line 158
    const/16 v11, 0xc

    .line 159
    .line 160
    invoke-interface {v1, v0, v11, v9, v3}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    check-cast v3, Ljava/lang/Boolean;

    .line 165
    .line 166
    or-int/lit16 v8, v8, 0x1000

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :pswitch_7
    move-object/from16 v24, v11

    .line 170
    .line 171
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 172
    .line 173
    const/16 v11, 0xb

    .line 174
    .line 175
    invoke-interface {v1, v0, v11, v9, v4}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v4

    .line 179
    check-cast v4, Ljava/lang/String;

    .line 180
    .line 181
    or-int/lit16 v8, v8, 0x800

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :pswitch_8
    move-object/from16 v24, v11

    .line 185
    .line 186
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 187
    .line 188
    const/16 v11, 0xa

    .line 189
    .line 190
    invoke-interface {v1, v0, v11, v9, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v7

    .line 194
    check-cast v7, Ljava/lang/String;

    .line 195
    .line 196
    or-int/lit16 v8, v8, 0x400

    .line 197
    .line 198
    goto :goto_3

    .line 199
    :pswitch_9
    move-object/from16 v24, v11

    .line 200
    .line 201
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 202
    .line 203
    const/16 v11, 0x9

    .line 204
    .line 205
    invoke-interface {v1, v0, v11, v9, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v6

    .line 209
    check-cast v6, Ljava/lang/String;

    .line 210
    .line 211
    or-int/lit16 v8, v8, 0x200

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :pswitch_a
    move-object/from16 v24, v11

    .line 215
    .line 216
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 217
    .line 218
    const/16 v11, 0x8

    .line 219
    .line 220
    invoke-interface {v1, v0, v11, v9, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v5

    .line 224
    check-cast v5, Ljava/lang/String;

    .line 225
    .line 226
    or-int/lit16 v8, v8, 0x100

    .line 227
    .line 228
    goto/16 :goto_3

    .line 229
    .line 230
    :pswitch_b
    move-object/from16 v24, v11

    .line 231
    .line 232
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 233
    .line 234
    const/4 v11, 0x7

    .line 235
    invoke-interface {v1, v0, v11, v9, v15}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v9

    .line 239
    move-object v15, v9

    .line 240
    check-cast v15, Ljava/lang/String;

    .line 241
    .line 242
    or-int/lit16 v8, v8, 0x80

    .line 243
    .line 244
    goto/16 :goto_3

    .line 245
    .line 246
    :pswitch_c
    move-object/from16 v24, v11

    .line 247
    .line 248
    sget-object v9, Luz0/q1;->a:Luz0/q1;

    .line 249
    .line 250
    const/4 v11, 0x6

    .line 251
    invoke-interface {v1, v0, v11, v9, v14}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v9

    .line 255
    move-object v14, v9

    .line 256
    check-cast v14, Ljava/lang/String;

    .line 257
    .line 258
    or-int/lit8 v8, v8, 0x40

    .line 259
    .line 260
    goto/16 :goto_3

    .line 261
    .line 262
    :pswitch_d
    move-object/from16 v24, v11

    .line 263
    .line 264
    const/4 v9, 0x5

    .line 265
    invoke-interface {v1, v0, v9}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v19

    .line 269
    or-int/lit8 v8, v8, 0x20

    .line 270
    .line 271
    goto/16 :goto_1

    .line 272
    .line 273
    :pswitch_e
    move-object/from16 v24, v11

    .line 274
    .line 275
    const/4 v9, 0x4

    .line 276
    invoke-interface {v1, v0, v9}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v18

    .line 280
    or-int/lit8 v8, v8, 0x10

    .line 281
    .line 282
    goto/16 :goto_1

    .line 283
    .line 284
    :pswitch_f
    move-object/from16 v24, v11

    .line 285
    .line 286
    sget-object v9, Lzg/o;->a:Lzg/o;

    .line 287
    .line 288
    const/4 v11, 0x3

    .line 289
    move-object/from16 v25, v2

    .line 290
    .line 291
    move-object/from16 v2, v24

    .line 292
    .line 293
    invoke-interface {v1, v0, v11, v9, v2}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v2

    .line 297
    move-object v11, v2

    .line 298
    check-cast v11, Lzg/q;

    .line 299
    .line 300
    or-int/lit8 v8, v8, 0x8

    .line 301
    .line 302
    :goto_4
    move-object/from16 v9, v23

    .line 303
    .line 304
    :goto_5
    move-object/from16 v2, v25

    .line 305
    .line 306
    goto/16 :goto_0

    .line 307
    .line 308
    :pswitch_10
    move-object/from16 v25, v2

    .line 309
    .line 310
    move-object v2, v11

    .line 311
    const/4 v9, 0x2

    .line 312
    invoke-interface {v1, v0, v9}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v17

    .line 316
    or-int/lit8 v8, v8, 0x4

    .line 317
    .line 318
    goto :goto_4

    .line 319
    :pswitch_11
    move-object/from16 v25, v2

    .line 320
    .line 321
    move-object v2, v11

    .line 322
    aget-object v9, v16, p1

    .line 323
    .line 324
    invoke-interface {v9}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v9

    .line 328
    check-cast v9, Lqz0/a;

    .line 329
    .line 330
    move-object/from16 v24, v2

    .line 331
    .line 332
    move-object/from16 v11, v23

    .line 333
    .line 334
    move/from16 v2, p1

    .line 335
    .line 336
    invoke-interface {v1, v0, v2, v9, v11}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v9

    .line 340
    check-cast v9, Lzg/g;

    .line 341
    .line 342
    or-int/lit8 v8, v8, 0x2

    .line 343
    .line 344
    move-object/from16 v11, v24

    .line 345
    .line 346
    goto :goto_5

    .line 347
    :pswitch_12
    move-object/from16 v25, v2

    .line 348
    .line 349
    move-object/from16 v24, v11

    .line 350
    .line 351
    move-object/from16 v11, v23

    .line 352
    .line 353
    move/from16 v2, p1

    .line 354
    .line 355
    aget-object v9, v16, p0

    .line 356
    .line 357
    invoke-interface {v9}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v9

    .line 361
    check-cast v9, Lqz0/a;

    .line 362
    .line 363
    move-object/from16 v2, v21

    .line 364
    .line 365
    move-object/from16 v21, v3

    .line 366
    .line 367
    move/from16 v3, p0

    .line 368
    .line 369
    invoke-interface {v1, v0, v3, v9, v2}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    check-cast v2, Ljava/util/List;

    .line 374
    .line 375
    or-int/lit8 v8, v8, 0x1

    .line 376
    .line 377
    :goto_6
    move-object v9, v11

    .line 378
    move-object/from16 v3, v21

    .line 379
    .line 380
    move-object/from16 v11, v24

    .line 381
    .line 382
    const/16 p1, 0x1

    .line 383
    .line 384
    move-object/from16 v21, v2

    .line 385
    .line 386
    goto :goto_5

    .line 387
    :pswitch_13
    move-object/from16 v25, v2

    .line 388
    .line 389
    move-object/from16 v24, v11

    .line 390
    .line 391
    move-object/from16 v2, v21

    .line 392
    .line 393
    move-object/from16 v11, v23

    .line 394
    .line 395
    move-object/from16 v21, v3

    .line 396
    .line 397
    move/from16 v3, p0

    .line 398
    .line 399
    move/from16 v20, p0

    .line 400
    .line 401
    goto :goto_6

    .line 402
    :cond_0
    move-object/from16 v25, v2

    .line 403
    .line 404
    move-object/from16 v24, v11

    .line 405
    .line 406
    move-object/from16 v2, v21

    .line 407
    .line 408
    move-object/from16 v21, v3

    .line 409
    .line 410
    move-object v11, v9

    .line 411
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 412
    .line 413
    .line 414
    move-object/from16 v23, v10

    .line 415
    .line 416
    move-object/from16 v10, v17

    .line 417
    .line 418
    move-object/from16 v17, v6

    .line 419
    .line 420
    new-instance v6, Lzg/h;

    .line 421
    .line 422
    move-object/from16 v16, v5

    .line 423
    .line 424
    move-object/from16 v20, v21

    .line 425
    .line 426
    move-object/from16 v11, v24

    .line 427
    .line 428
    move-object/from16 v21, v25

    .line 429
    .line 430
    move-object/from16 v24, v12

    .line 431
    .line 432
    move-object/from16 v25, v13

    .line 433
    .line 434
    move-object/from16 v12, v18

    .line 435
    .line 436
    move-object/from16 v13, v19

    .line 437
    .line 438
    move-object/from16 v19, v4

    .line 439
    .line 440
    move-object/from16 v18, v7

    .line 441
    .line 442
    move v7, v8

    .line 443
    move-object v8, v2

    .line 444
    invoke-direct/range {v6 .. v26}, Lzg/h;-><init>(ILjava/util/List;Lzg/g;Ljava/lang/String;Lzg/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lzg/h2;ZLjava/lang/String;Lzg/q1;Lzg/x1;Z)V

    .line 445
    .line 446
    .line 447
    return-object v6

    .line 448
    nop

    .line 449
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
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
    sget-object p0, Lzg/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 16

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    check-cast v0, Lzg/h;

    .line 4
    .line 5
    const-string v1, "value"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, v0, Lzg/h;->u:Lzg/x1;

    .line 11
    .line 12
    sget-object v2, Lzg/d;->descriptor:Lsz0/g;

    .line 13
    .line 14
    move-object/from16 v3, p1

    .line 15
    .line 16
    invoke-interface {v3, v2}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    sget-object v4, Lzg/h;->w:[Llx0/i;

    .line 21
    .line 22
    const/4 v5, 0x0

    .line 23
    aget-object v6, v4, v5

    .line 24
    .line 25
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v6

    .line 29
    check-cast v6, Lqz0/a;

    .line 30
    .line 31
    iget-object v7, v0, Lzg/h;->d:Ljava/util/List;

    .line 32
    .line 33
    iget-object v8, v0, Lzg/h;->t:Lzg/q1;

    .line 34
    .line 35
    iget-object v9, v0, Lzg/h;->s:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v10, v0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 38
    .line 39
    iget-object v11, v0, Lzg/h;->o:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v12, v0, Lzg/h;->n:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v13, v0, Lzg/h;->m:Ljava/lang/String;

    .line 44
    .line 45
    iget-object v14, v0, Lzg/h;->l:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v15, v0, Lzg/h;->k:Ljava/lang/String;

    .line 48
    .line 49
    move-object/from16 p0, v4

    .line 50
    .line 51
    iget-object v4, v0, Lzg/h;->j:Ljava/lang/String;

    .line 52
    .line 53
    move-object/from16 p2, v1

    .line 54
    .line 55
    iget-object v1, v0, Lzg/h;->g:Lzg/q;

    .line 56
    .line 57
    invoke-interface {v3, v2, v5, v6, v7}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const/4 v5, 0x1

    .line 61
    aget-object v6, p0, v5

    .line 62
    .line 63
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    check-cast v6, Lqz0/a;

    .line 68
    .line 69
    iget-object v7, v0, Lzg/h;->e:Lzg/g;

    .line 70
    .line 71
    invoke-interface {v3, v2, v5, v6, v7}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const/4 v5, 0x2

    .line 75
    iget-object v6, v0, Lzg/h;->f:Ljava/lang/String;

    .line 76
    .line 77
    invoke-interface {v3, v2, v5, v6}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_0

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_0
    if-eqz v1, :cond_1

    .line 88
    .line 89
    :goto_0
    sget-object v5, Lzg/o;->a:Lzg/o;

    .line 90
    .line 91
    const/4 v6, 0x3

    .line 92
    invoke-interface {v3, v2, v6, v5, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_1
    const/4 v1, 0x4

    .line 96
    iget-object v5, v0, Lzg/h;->h:Ljava/lang/String;

    .line 97
    .line 98
    invoke-interface {v3, v2, v1, v5}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const/4 v1, 0x5

    .line 102
    iget-object v5, v0, Lzg/h;->i:Ljava/lang/String;

    .line 103
    .line 104
    invoke-interface {v3, v2, v1, v5}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_2

    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_2
    if-eqz v4, :cond_3

    .line 115
    .line 116
    :goto_1
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 117
    .line 118
    const/4 v5, 0x6

    .line 119
    invoke-interface {v3, v2, v5, v1, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_3
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-eqz v1, :cond_4

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_4
    if-eqz v15, :cond_5

    .line 130
    .line 131
    :goto_2
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 132
    .line 133
    const/4 v4, 0x7

    .line 134
    invoke-interface {v3, v2, v4, v1, v15}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    :cond_5
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-eqz v1, :cond_6

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_6
    if-eqz v14, :cond_7

    .line 145
    .line 146
    :goto_3
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 147
    .line 148
    const/16 v4, 0x8

    .line 149
    .line 150
    invoke-interface {v3, v2, v4, v1, v14}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :cond_7
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    if-eqz v1, :cond_8

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_8
    if-eqz v13, :cond_9

    .line 161
    .line 162
    :goto_4
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 163
    .line 164
    const/16 v4, 0x9

    .line 165
    .line 166
    invoke-interface {v3, v2, v4, v1, v13}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    :cond_9
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    if-eqz v1, :cond_a

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_a
    if-eqz v12, :cond_b

    .line 177
    .line 178
    :goto_5
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 179
    .line 180
    const/16 v4, 0xa

    .line 181
    .line 182
    invoke-interface {v3, v2, v4, v1, v12}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    :cond_b
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    if-eqz v1, :cond_c

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_c
    if-eqz v11, :cond_d

    .line 193
    .line 194
    :goto_6
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 195
    .line 196
    const/16 v4, 0xb

    .line 197
    .line 198
    invoke-interface {v3, v2, v4, v1, v11}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    :cond_d
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 202
    .line 203
    .line 204
    move-result v1

    .line 205
    if-eqz v1, :cond_e

    .line 206
    .line 207
    goto :goto_7

    .line 208
    :cond_e
    if-eqz v10, :cond_f

    .line 209
    .line 210
    :goto_7
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 211
    .line 212
    const/16 v4, 0xc

    .line 213
    .line 214
    invoke-interface {v3, v2, v4, v1, v10}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    :cond_f
    sget-object v1, Lzg/e2;->a:Lzg/e2;

    .line 218
    .line 219
    iget-object v4, v0, Lzg/h;->q:Lzg/h2;

    .line 220
    .line 221
    const/16 v5, 0xd

    .line 222
    .line 223
    invoke-interface {v3, v2, v5, v1, v4}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    const/16 v1, 0xe

    .line 227
    .line 228
    iget-boolean v4, v0, Lzg/h;->r:Z

    .line 229
    .line 230
    invoke-interface {v3, v2, v1, v4}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 231
    .line 232
    .line 233
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    if-eqz v1, :cond_10

    .line 238
    .line 239
    goto :goto_8

    .line 240
    :cond_10
    if-eqz v9, :cond_11

    .line 241
    .line 242
    :goto_8
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 243
    .line 244
    const/16 v4, 0xf

    .line 245
    .line 246
    invoke-interface {v3, v2, v4, v1, v9}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    :cond_11
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    if-eqz v1, :cond_12

    .line 254
    .line 255
    goto :goto_9

    .line 256
    :cond_12
    if-eqz v8, :cond_13

    .line 257
    .line 258
    :goto_9
    sget-object v1, Lzg/o1;->a:Lzg/o1;

    .line 259
    .line 260
    const/16 v4, 0x10

    .line 261
    .line 262
    invoke-interface {v3, v2, v4, v1, v8}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    :cond_13
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 266
    .line 267
    .line 268
    move-result v1

    .line 269
    if-eqz v1, :cond_14

    .line 270
    .line 271
    goto :goto_a

    .line 272
    :cond_14
    if-eqz p2, :cond_15

    .line 273
    .line 274
    :goto_a
    sget-object v1, Lzg/r1;->a:Lzg/r1;

    .line 275
    .line 276
    const/16 v4, 0x11

    .line 277
    .line 278
    move-object/from16 v5, p2

    .line 279
    .line 280
    invoke-interface {v3, v2, v4, v1, v5}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 281
    .line 282
    .line 283
    :cond_15
    invoke-interface {v3, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 284
    .line 285
    .line 286
    move-result v1

    .line 287
    if-eqz v1, :cond_16

    .line 288
    .line 289
    goto :goto_b

    .line 290
    :cond_16
    iget-boolean v1, v0, Lzg/h;->v:Z

    .line 291
    .line 292
    if-eqz v1, :cond_17

    .line 293
    .line 294
    :goto_b
    iget-boolean v0, v0, Lzg/h;->v:Z

    .line 295
    .line 296
    const/16 v1, 0x12

    .line 297
    .line 298
    invoke-interface {v3, v2, v1, v0}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 299
    .line 300
    .line 301
    :cond_17
    invoke-interface {v3, v2}, Ltz0/b;->b(Lsz0/g;)V

    .line 302
    .line 303
    .line 304
    return-void
.end method
