.class public abstract Lh2/l5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgz0/e0;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 9
    .line 10
    .line 11
    new-instance v0, Lgz0/e0;

    .line 12
    .line 13
    const/16 v1, 0xf

    .line 14
    .line 15
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Ll2/u2;

    .line 19
    .line 20
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Lh2/l5;->a:Ll2/u2;

    .line 24
    .line 25
    return-void
.end method

.method public static final a(Lh2/f1;Lh2/n6;Lh2/h8;Lh2/dc;Lt2/b;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move-object/from16 v5, p4

    .line 10
    .line 11
    move/from16 v6, p6

    .line 12
    .line 13
    move-object/from16 v0, p5

    .line 14
    .line 15
    check-cast v0, Ll2/t;

    .line 16
    .line 17
    const v7, 0x35e9c094

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v7}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v7, v6, 0x6

    .line 24
    .line 25
    if-nez v7, :cond_1

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v7

    .line 31
    if-eqz v7, :cond_0

    .line 32
    .line 33
    const/4 v7, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v7, 0x2

    .line 36
    :goto_0
    or-int/2addr v7, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v7, v6

    .line 39
    :goto_1
    and-int/lit8 v8, v6, 0x30

    .line 40
    .line 41
    if-nez v8, :cond_3

    .line 42
    .line 43
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v8

    .line 47
    if-eqz v8, :cond_2

    .line 48
    .line 49
    const/16 v8, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v8, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v7, v8

    .line 55
    :cond_3
    and-int/lit16 v8, v6, 0x180

    .line 56
    .line 57
    if-nez v8, :cond_5

    .line 58
    .line 59
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    if-eqz v8, :cond_4

    .line 64
    .line 65
    const/16 v8, 0x100

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_4
    const/16 v8, 0x80

    .line 69
    .line 70
    :goto_3
    or-int/2addr v7, v8

    .line 71
    :cond_5
    and-int/lit16 v8, v6, 0xc00

    .line 72
    .line 73
    if-nez v8, :cond_7

    .line 74
    .line 75
    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v8

    .line 79
    if-eqz v8, :cond_6

    .line 80
    .line 81
    const/16 v8, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v8, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v7, v8

    .line 87
    :cond_7
    and-int/lit16 v8, v6, 0x6000

    .line 88
    .line 89
    if-nez v8, :cond_9

    .line 90
    .line 91
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v8

    .line 95
    if-eqz v8, :cond_8

    .line 96
    .line 97
    const/16 v8, 0x4000

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_8
    const/16 v8, 0x2000

    .line 101
    .line 102
    :goto_5
    or-int/2addr v7, v8

    .line 103
    :cond_9
    and-int/lit16 v8, v7, 0x2493

    .line 104
    .line 105
    const/16 v9, 0x2492

    .line 106
    .line 107
    const/4 v10, 0x0

    .line 108
    const/4 v11, 0x1

    .line 109
    if-eq v8, v9, :cond_a

    .line 110
    .line 111
    move v8, v11

    .line 112
    goto :goto_6

    .line 113
    :cond_a
    move v8, v10

    .line 114
    :goto_6
    and-int/2addr v7, v11

    .line 115
    invoke-virtual {v0, v7, v8}, Ll2/t;->O(IZ)Z

    .line 116
    .line 117
    .line 118
    move-result v7

    .line 119
    if-eqz v7, :cond_f

    .line 120
    .line 121
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 122
    .line 123
    .line 124
    and-int/lit8 v7, v6, 0x1

    .line 125
    .line 126
    if-eqz v7, :cond_c

    .line 127
    .line 128
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 129
    .line 130
    .line 131
    move-result v7

    .line 132
    if-eqz v7, :cond_b

    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_b
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 136
    .line 137
    .line 138
    :cond_c
    :goto_7
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 139
    .line 140
    .line 141
    const-wide/16 v7, 0x0

    .line 142
    .line 143
    const/4 v9, 0x7

    .line 144
    const/4 v11, 0x0

    .line 145
    invoke-static {v7, v8, v11, v9, v10}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 146
    .line 147
    .line 148
    move-result-object v7

    .line 149
    iget-wide v8, v1, Lh2/f1;->a:J

    .line 150
    .line 151
    invoke-virtual {v0, v8, v9}, Ll2/t;->f(J)Z

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v11

    .line 159
    if-nez v10, :cond_d

    .line 160
    .line 161
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 162
    .line 163
    if-ne v11, v10, :cond_e

    .line 164
    .line 165
    :cond_d
    new-instance v11, Le2/d1;

    .line 166
    .line 167
    const v10, 0x3ecccccd    # 0.4f

    .line 168
    .line 169
    .line 170
    invoke-static {v8, v9, v10}, Le3/s;->b(JF)J

    .line 171
    .line 172
    .line 173
    move-result-wide v12

    .line 174
    invoke-direct {v11, v8, v9, v12, v13}, Le2/d1;-><init>(JJ)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v0, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    :cond_e
    check-cast v11, Le2/d1;

    .line 181
    .line 182
    sget-object v8, Lh2/g1;->a:Ll2/u2;

    .line 183
    .line 184
    invoke-virtual {v8, v1}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 185
    .line 186
    .line 187
    move-result-object v12

    .line 188
    sget-object v8, Lh2/l5;->a:Ll2/u2;

    .line 189
    .line 190
    invoke-virtual {v8, v2}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 191
    .line 192
    .line 193
    move-result-object v13

    .line 194
    sget-object v8, Landroidx/compose/foundation/c;->a:Ll2/e0;

    .line 195
    .line 196
    invoke-virtual {v8, v7}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 197
    .line 198
    .line 199
    move-result-object v14

    .line 200
    sget-object v7, Lh2/i8;->a:Ll2/u2;

    .line 201
    .line 202
    invoke-virtual {v7, v3}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 203
    .line 204
    .line 205
    move-result-object v15

    .line 206
    sget-object v7, Le2/e1;->a:Ll2/e0;

    .line 207
    .line 208
    invoke-virtual {v7, v11}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 209
    .line 210
    .line 211
    move-result-object v16

    .line 212
    sget-object v7, Lh2/ec;->a:Ll2/u2;

    .line 213
    .line 214
    invoke-virtual {v7, v4}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 215
    .line 216
    .line 217
    move-result-object v17

    .line 218
    filled-new-array/range {v12 .. v17}, [Ll2/t1;

    .line 219
    .line 220
    .line 221
    move-result-object v7

    .line 222
    new-instance v8, Laa/p;

    .line 223
    .line 224
    const/16 v9, 0x8

    .line 225
    .line 226
    invoke-direct {v8, v9, v4, v5}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    const v9, -0x68571c2c

    .line 230
    .line 231
    .line 232
    invoke-static {v9, v0, v8}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 233
    .line 234
    .line 235
    move-result-object v8

    .line 236
    const/16 v9, 0x38

    .line 237
    .line 238
    invoke-static {v7, v8, v0, v9}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 239
    .line 240
    .line 241
    goto :goto_8

    .line 242
    :cond_f
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 243
    .line 244
    .line 245
    :goto_8
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 246
    .line 247
    .line 248
    move-result-object v7

    .line 249
    if-eqz v7, :cond_10

    .line 250
    .line 251
    new-instance v0, La71/c0;

    .line 252
    .line 253
    invoke-direct/range {v0 .. v6}, La71/c0;-><init>(Lh2/f1;Lh2/n6;Lh2/h8;Lh2/dc;Lt2/b;I)V

    .line 254
    .line 255
    .line 256
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 257
    .line 258
    :cond_10
    return-void
.end method

.method public static final b(Lh2/f1;Lh2/h8;Lh2/dc;Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    move-object v5, p4

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p4, -0x1ace2e0b

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p4, p5, 0x6

    .line 11
    .line 12
    if-nez p4, :cond_1

    .line 13
    .line 14
    invoke-virtual {v5, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p4

    .line 18
    if-eqz p4, :cond_0

    .line 19
    .line 20
    const/4 p4, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p4, 0x2

    .line 23
    :goto_0
    or-int/2addr p4, p5

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p4, p5

    .line 26
    :goto_1
    and-int/lit8 v0, p5, 0x30

    .line 27
    .line 28
    if-nez v0, :cond_2

    .line 29
    .line 30
    or-int/lit8 p4, p4, 0x10

    .line 31
    .line 32
    :cond_2
    and-int/lit16 v0, p5, 0x180

    .line 33
    .line 34
    if-nez v0, :cond_3

    .line 35
    .line 36
    or-int/lit16 p4, p4, 0x80

    .line 37
    .line 38
    :cond_3
    and-int/lit16 v0, p5, 0xc00

    .line 39
    .line 40
    if-nez v0, :cond_5

    .line 41
    .line 42
    invoke-virtual {v5, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_4

    .line 47
    .line 48
    const/16 v0, 0x800

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_4
    const/16 v0, 0x400

    .line 52
    .line 53
    :goto_2
    or-int/2addr p4, v0

    .line 54
    :cond_5
    and-int/lit16 v0, p4, 0x493

    .line 55
    .line 56
    const/16 v1, 0x492

    .line 57
    .line 58
    if-eq v0, v1, :cond_6

    .line 59
    .line 60
    const/4 v0, 0x1

    .line 61
    goto :goto_3

    .line 62
    :cond_6
    const/4 v0, 0x0

    .line 63
    :goto_3
    and-int/lit8 v1, p4, 0x1

    .line 64
    .line 65
    invoke-virtual {v5, v1, v0}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_9

    .line 70
    .line 71
    invoke-virtual {v5}, Ll2/t;->T()V

    .line 72
    .line 73
    .line 74
    and-int/lit8 v0, p5, 0x1

    .line 75
    .line 76
    if-eqz v0, :cond_8

    .line 77
    .line 78
    invoke-virtual {v5}, Ll2/t;->y()Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_7

    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_7
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    :goto_4
    and-int/lit16 p4, p4, -0x3f1

    .line 89
    .line 90
    move-object v2, p1

    .line 91
    move-object v3, p2

    .line 92
    goto :goto_6

    .line 93
    :cond_8
    :goto_5
    sget-object p1, Lh2/i8;->a:Ll2/u2;

    .line 94
    .line 95
    invoke-virtual {v5, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    check-cast p1, Lh2/h8;

    .line 100
    .line 101
    sget-object p2, Lh2/ec;->a:Ll2/u2;

    .line 102
    .line 103
    invoke-virtual {v5, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    check-cast p2, Lh2/dc;

    .line 108
    .line 109
    goto :goto_4

    .line 110
    :goto_6
    invoke-virtual {v5}, Ll2/t;->r()V

    .line 111
    .line 112
    .line 113
    sget-object p1, Lh2/l5;->a:Ll2/u2;

    .line 114
    .line 115
    invoke-virtual {v5, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    move-object v1, p1

    .line 120
    check-cast v1, Lh2/n6;

    .line 121
    .line 122
    and-int/lit8 p1, p4, 0xe

    .line 123
    .line 124
    shl-int/lit8 p2, p4, 0x3

    .line 125
    .line 126
    const p4, 0xe000

    .line 127
    .line 128
    .line 129
    and-int/2addr p2, p4

    .line 130
    or-int v6, p1, p2

    .line 131
    .line 132
    move-object v0, p0

    .line 133
    move-object v4, p3

    .line 134
    invoke-static/range {v0 .. v6}, Lh2/l5;->a(Lh2/f1;Lh2/n6;Lh2/h8;Lh2/dc;Lt2/b;Ll2/o;I)V

    .line 135
    .line 136
    .line 137
    move-object p4, v4

    .line 138
    move-object p2, v2

    .line 139
    move-object p3, v3

    .line 140
    goto :goto_7

    .line 141
    :cond_9
    move-object v0, p0

    .line 142
    move-object p4, p3

    .line 143
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 144
    .line 145
    .line 146
    move-object p3, p2

    .line 147
    move-object p2, p1

    .line 148
    :goto_7
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    if-eqz v1, :cond_a

    .line 153
    .line 154
    new-instance p0, La71/e;

    .line 155
    .line 156
    move-object p1, v0

    .line 157
    invoke-direct/range {p0 .. p5}, La71/e;-><init>(Lh2/f1;Lh2/h8;Lh2/dc;Lt2/b;I)V

    .line 158
    .line 159
    .line 160
    iput-object p0, v1, Ll2/u1;->d:Lay0/n;

    .line 161
    .line 162
    :cond_a
    return-void
.end method
