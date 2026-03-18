.class public abstract Lh2/vb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:Lk1/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x4

    .line 2
    int-to-float v0, v0

    .line 3
    sput v0, Lh2/vb;->a:F

    .line 4
    .line 5
    const/16 v1, 0x18

    .line 6
    .line 7
    int-to-float v1, v1

    .line 8
    sput v1, Lh2/vb;->b:F

    .line 9
    .line 10
    const/16 v1, 0x28

    .line 11
    .line 12
    int-to-float v1, v1

    .line 13
    sput v1, Lh2/vb;->c:F

    .line 14
    .line 15
    const/16 v1, 0x8

    .line 16
    .line 17
    int-to-float v1, v1

    .line 18
    new-instance v2, Lk1/a1;

    .line 19
    .line 20
    invoke-direct {v2, v1, v0, v1, v0}, Lk1/a1;-><init>(FFFF)V

    .line 21
    .line 22
    .line 23
    sput-object v2, Lh2/vb;->d:Lk1/a1;

    .line 24
    .line 25
    return-void
.end method

.method public static final a(Lh2/xb;Lx2/s;FLe3/n0;JJFFLt2/b;Ll2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v11, p10

    .line 4
    .line 5
    move/from16 v12, p12

    .line 6
    .line 7
    move-object/from16 v0, p11

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v2, -0x147d586e

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v2, v12, 0x6

    .line 18
    .line 19
    if-nez v2, :cond_2

    .line 20
    .line 21
    and-int/lit8 v2, v12, 0x8

    .line 22
    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    :goto_0
    if-eqz v2, :cond_1

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/4 v2, 0x2

    .line 39
    :goto_1
    or-int/2addr v2, v12

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    move v2, v12

    .line 42
    :goto_2
    or-int/lit16 v3, v2, 0xdb0

    .line 43
    .line 44
    and-int/lit16 v4, v12, 0x6000

    .line 45
    .line 46
    if-nez v4, :cond_3

    .line 47
    .line 48
    or-int/lit16 v3, v2, 0x2db0

    .line 49
    .line 50
    :cond_3
    const/high16 v2, 0x30000

    .line 51
    .line 52
    and-int/2addr v2, v12

    .line 53
    if-nez v2, :cond_4

    .line 54
    .line 55
    const/high16 v2, 0x10000

    .line 56
    .line 57
    or-int/2addr v3, v2

    .line 58
    :cond_4
    const/high16 v2, 0x180000

    .line 59
    .line 60
    and-int/2addr v2, v12

    .line 61
    if-nez v2, :cond_5

    .line 62
    .line 63
    const/high16 v2, 0x80000

    .line 64
    .line 65
    or-int/2addr v3, v2

    .line 66
    :cond_5
    const/high16 v2, 0x6c00000

    .line 67
    .line 68
    or-int/2addr v2, v3

    .line 69
    const/high16 v3, 0x30000000

    .line 70
    .line 71
    and-int/2addr v3, v12

    .line 72
    if-nez v3, :cond_7

    .line 73
    .line 74
    invoke-virtual {v0, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-eqz v3, :cond_6

    .line 79
    .line 80
    const/high16 v3, 0x20000000

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_6
    const/high16 v3, 0x10000000

    .line 84
    .line 85
    :goto_3
    or-int/2addr v2, v3

    .line 86
    :cond_7
    const v3, 0x12492493

    .line 87
    .line 88
    .line 89
    and-int/2addr v3, v2

    .line 90
    const v4, 0x12492492

    .line 91
    .line 92
    .line 93
    const/4 v5, 0x0

    .line 94
    if-eq v3, v4, :cond_8

    .line 95
    .line 96
    const/4 v3, 0x1

    .line 97
    goto :goto_4

    .line 98
    :cond_8
    move v3, v5

    .line 99
    :goto_4
    and-int/lit8 v4, v2, 0x1

    .line 100
    .line 101
    invoke-virtual {v0, v4, v3}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    if-eqz v3, :cond_b

    .line 106
    .line 107
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 108
    .line 109
    .line 110
    and-int/lit8 v3, v12, 0x1

    .line 111
    .line 112
    const v4, -0x3fe001

    .line 113
    .line 114
    .line 115
    if-eqz v3, :cond_a

    .line 116
    .line 117
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-eqz v3, :cond_9

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_9
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 125
    .line 126
    .line 127
    and-int/2addr v2, v4

    .line 128
    move-object/from16 v13, p1

    .line 129
    .line 130
    move/from16 v3, p2

    .line 131
    .line 132
    move-object/from16 v14, p3

    .line 133
    .line 134
    move-wide/from16 v7, p4

    .line 135
    .line 136
    move-wide/from16 v15, p6

    .line 137
    .line 138
    move/from16 v19, p8

    .line 139
    .line 140
    move/from16 v20, p9

    .line 141
    .line 142
    goto :goto_6

    .line 143
    :cond_a
    :goto_5
    sget v3, Lh2/sb;->a:F

    .line 144
    .line 145
    sget-object v6, Lk2/b0;->b:Lk2/f0;

    .line 146
    .line 147
    invoke-static {v6, v0}, Lh2/i8;->b(Lk2/f0;Ll2/o;)Le3/n0;

    .line 148
    .line 149
    .line 150
    move-result-object v6

    .line 151
    sget-object v7, Lk2/b0;->c:Lk2/l;

    .line 152
    .line 153
    invoke-static {v7, v0}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 154
    .line 155
    .line 156
    move-result-wide v7

    .line 157
    sget-object v9, Lk2/b0;->a:Lk2/l;

    .line 158
    .line 159
    invoke-static {v9, v0}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 160
    .line 161
    .line 162
    move-result-wide v9

    .line 163
    and-int/2addr v2, v4

    .line 164
    int-to-float v4, v5

    .line 165
    int-to-float v13, v5

    .line 166
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 167
    .line 168
    move/from16 v19, v4

    .line 169
    .line 170
    move-wide v15, v9

    .line 171
    move/from16 v20, v13

    .line 172
    .line 173
    move-object v13, v14

    .line 174
    move-object v14, v6

    .line 175
    :goto_6
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 176
    .line 177
    .line 178
    const v4, -0x66828db7

    .line 179
    .line 180
    .line 181
    invoke-virtual {v0, v4}, Ll2/t;->Y(I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0, v5}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    new-instance v4, Lh2/ub;

    .line 188
    .line 189
    invoke-direct {v4, v3, v7, v8, v11}, Lh2/ub;-><init>(FJLt2/b;)V

    .line 190
    .line 191
    .line 192
    const v5, -0x5dd15193

    .line 193
    .line 194
    .line 195
    invoke-static {v5, v0, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 196
    .line 197
    .line 198
    move-result-object v22

    .line 199
    shr-int/lit8 v2, v2, 0x9

    .line 200
    .line 201
    const v4, 0xe000

    .line 202
    .line 203
    .line 204
    and-int/2addr v4, v2

    .line 205
    const/high16 v5, 0xc00000

    .line 206
    .line 207
    or-int/2addr v4, v5

    .line 208
    const/high16 v5, 0x70000

    .line 209
    .line 210
    and-int/2addr v2, v5

    .line 211
    or-int v24, v4, v2

    .line 212
    .line 213
    const/16 v25, 0x48

    .line 214
    .line 215
    const-wide/16 v17, 0x0

    .line 216
    .line 217
    const/16 v21, 0x0

    .line 218
    .line 219
    move-object/from16 v23, v0

    .line 220
    .line 221
    invoke-static/range {v13 .. v25}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 222
    .line 223
    .line 224
    move-wide v5, v7

    .line 225
    move-object v2, v13

    .line 226
    move-object v4, v14

    .line 227
    move-wide v7, v15

    .line 228
    move/from16 v9, v19

    .line 229
    .line 230
    move/from16 v10, v20

    .line 231
    .line 232
    goto :goto_7

    .line 233
    :cond_b
    move-object/from16 v23, v0

    .line 234
    .line 235
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 236
    .line 237
    .line 238
    move-object/from16 v2, p1

    .line 239
    .line 240
    move/from16 v3, p2

    .line 241
    .line 242
    move-object/from16 v4, p3

    .line 243
    .line 244
    move-wide/from16 v5, p4

    .line 245
    .line 246
    move-wide/from16 v7, p6

    .line 247
    .line 248
    move/from16 v9, p8

    .line 249
    .line 250
    move/from16 v10, p9

    .line 251
    .line 252
    :goto_7
    invoke-virtual/range {v23 .. v23}, Ll2/t;->s()Ll2/u1;

    .line 253
    .line 254
    .line 255
    move-result-object v13

    .line 256
    if-eqz v13, :cond_c

    .line 257
    .line 258
    new-instance v0, Lh2/tb;

    .line 259
    .line 260
    invoke-direct/range {v0 .. v12}, Lh2/tb;-><init>(Lh2/xb;Lx2/s;FLe3/n0;JJFFLt2/b;I)V

    .line 261
    .line 262
    .line 263
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 264
    .line 265
    :cond_c
    return-void
.end method

.method public static final b(Lx4/v;Lt2/b;Lh2/yb;Lx2/s;ZLt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    move-object v4, p6

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p6, -0x11825480

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p6}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p6, p7, 0x6

    .line 11
    .line 12
    if-nez p6, :cond_1

    .line 13
    .line 14
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p6

    .line 18
    if-eqz p6, :cond_0

    .line 19
    .line 20
    const/4 p6, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p6, 0x2

    .line 23
    :goto_0
    or-int/2addr p6, p7

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p6, p7

    .line 26
    :goto_1
    and-int/lit8 v0, p7, 0x30

    .line 27
    .line 28
    if-nez v0, :cond_3

    .line 29
    .line 30
    invoke-virtual {v4, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    const/16 v0, 0x20

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/16 v0, 0x10

    .line 40
    .line 41
    :goto_2
    or-int/2addr p6, v0

    .line 42
    :cond_3
    and-int/lit16 v0, p7, 0x180

    .line 43
    .line 44
    if-nez v0, :cond_6

    .line 45
    .line 46
    and-int/lit16 v0, p7, 0x200

    .line 47
    .line 48
    if-nez v0, :cond_4

    .line 49
    .line 50
    invoke-virtual {v4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    goto :goto_3

    .line 55
    :cond_4
    invoke-virtual {v4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    :goto_3
    if-eqz v0, :cond_5

    .line 60
    .line 61
    const/16 v0, 0x100

    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_5
    const/16 v0, 0x80

    .line 65
    .line 66
    :goto_4
    or-int/2addr p6, v0

    .line 67
    :cond_6
    const v0, 0xdb6c00

    .line 68
    .line 69
    .line 70
    or-int/2addr p6, v0

    .line 71
    const/high16 v0, 0x6000000

    .line 72
    .line 73
    and-int/2addr v0, p7

    .line 74
    if-nez v0, :cond_8

    .line 75
    .line 76
    invoke-virtual {v4, p5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_7

    .line 81
    .line 82
    const/high16 v0, 0x4000000

    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_7
    const/high16 v0, 0x2000000

    .line 86
    .line 87
    :goto_5
    or-int/2addr p6, v0

    .line 88
    :cond_8
    const v0, 0x2492493

    .line 89
    .line 90
    .line 91
    and-int/2addr v0, p6

    .line 92
    const v1, 0x2492492

    .line 93
    .line 94
    .line 95
    const/4 v6, 0x1

    .line 96
    if-eq v0, v1, :cond_9

    .line 97
    .line 98
    move v0, v6

    .line 99
    goto :goto_6

    .line 100
    :cond_9
    const/4 v0, 0x0

    .line 101
    :goto_6
    and-int/lit8 v1, p6, 0x1

    .line 102
    .line 103
    invoke-virtual {v4, v1, v0}, Ll2/t;->O(IZ)Z

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    if-eqz v0, :cond_c

    .line 108
    .line 109
    iget-object p3, p2, Lh2/yb;->b:Lc1/n0;

    .line 110
    .line 111
    const-string p4, "tooltip transition"

    .line 112
    .line 113
    const/16 v0, 0x30

    .line 114
    .line 115
    invoke-static {p3, p4, v4, v0}, Lc1/z1;->e(Lc1/n0;Ljava/lang/String;Ll2/o;I)Lc1/w1;

    .line 116
    .line 117
    .line 118
    move-result-object p3

    .line 119
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p4

    .line 123
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 124
    .line 125
    if-ne p4, v0, :cond_a

    .line 126
    .line 127
    const/4 p4, 0x0

    .line 128
    invoke-static {p4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 129
    .line 130
    .line 131
    move-result-object p4

    .line 132
    invoke-virtual {v4, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_a
    check-cast p4, Ll2/b1;

    .line 136
    .line 137
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    if-ne v1, v0, :cond_b

    .line 142
    .line 143
    new-instance v1, Lh2/xb;

    .line 144
    .line 145
    new-instance v0, La2/h;

    .line 146
    .line 147
    const/16 v2, 0x17

    .line 148
    .line 149
    invoke-direct {v0, p4, v2}, La2/h;-><init>(Ll2/b1;I)V

    .line 150
    .line 151
    .line 152
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v4, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_b
    check-cast v1, Lh2/xb;

    .line 159
    .line 160
    new-instance v0, Laa/p;

    .line 161
    .line 162
    const/16 v2, 0xc

    .line 163
    .line 164
    invoke-direct {v0, v2, p4, p5}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    const p4, -0x16cb6ae

    .line 168
    .line 169
    .line 170
    invoke-static {p4, v4, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    new-instance p4, Lf2/f;

    .line 175
    .line 176
    invoke-direct {p4, p3, p1, v1}, Lf2/f;-><init>(Lc1/w1;Lt2/b;Lh2/xb;)V

    .line 177
    .line 178
    .line 179
    const p3, -0x1f6f824a

    .line 180
    .line 181
    .line 182
    invoke-static {p3, v4, p4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    and-int/lit8 p3, p6, 0xe

    .line 187
    .line 188
    const p4, 0x6000030

    .line 189
    .line 190
    .line 191
    or-int/2addr p3, p4

    .line 192
    and-int/lit16 p4, p6, 0x380

    .line 193
    .line 194
    or-int/2addr p3, p4

    .line 195
    and-int/lit16 p4, p6, 0x1c00

    .line 196
    .line 197
    or-int/2addr p3, p4

    .line 198
    const p4, 0xe000

    .line 199
    .line 200
    .line 201
    and-int/2addr p4, p6

    .line 202
    or-int/2addr p3, p4

    .line 203
    const/high16 p4, 0x70000

    .line 204
    .line 205
    and-int/2addr p4, p6

    .line 206
    or-int/2addr p3, p4

    .line 207
    const/high16 p4, 0x380000

    .line 208
    .line 209
    and-int/2addr p4, p6

    .line 210
    or-int/2addr p3, p4

    .line 211
    const/high16 p4, 0x1c00000

    .line 212
    .line 213
    and-int/2addr p4, p6

    .line 214
    or-int v5, p3, p4

    .line 215
    .line 216
    move-object v0, p0

    .line 217
    move-object v2, p2

    .line 218
    invoke-static/range {v0 .. v5}, Li2/a1;->b(Lx4/v;Lt2/b;Lh2/yb;Lt2/b;Ll2/o;I)V

    .line 219
    .line 220
    .line 221
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 222
    .line 223
    move-object p6, p5

    .line 224
    move p5, v6

    .line 225
    :goto_7
    move-object p4, p3

    .line 226
    goto :goto_8

    .line 227
    :cond_c
    move-object v0, p0

    .line 228
    move-object v2, p2

    .line 229
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 230
    .line 231
    .line 232
    move-object p6, p5

    .line 233
    move p5, p4

    .line 234
    goto :goto_7

    .line 235
    :goto_8
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    if-eqz v1, :cond_d

    .line 240
    .line 241
    new-instance p0, Le71/c;

    .line 242
    .line 243
    move-object p2, p1

    .line 244
    move-object p1, v0

    .line 245
    move-object p3, v2

    .line 246
    invoke-direct/range {p0 .. p7}, Le71/c;-><init>(Lx4/v;Lt2/b;Lh2/yb;Lx2/s;ZLt2/b;I)V

    .line 247
    .line 248
    .line 249
    iput-object p0, v1, Ll2/u1;->d:Lay0/n;

    .line 250
    .line 251
    :cond_d
    return-void
.end method

.method public static final c(Ll2/o;)Lh2/yb;
    .locals 3

    .line 1
    sget-object v0, Li2/s;->a:Le1/b1;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Ll2/t;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-virtual {v1, v2}, Ll2/t;->h(Z)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    move-object v2, p0

    .line 12
    check-cast v2, Ll2/t;

    .line 13
    .line 14
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    or-int/2addr v1, v2

    .line 19
    check-cast p0, Ll2/t;

    .line 20
    .line 21
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 28
    .line 29
    if-ne v2, v1, :cond_1

    .line 30
    .line 31
    :cond_0
    new-instance v2, Lh2/yb;

    .line 32
    .line 33
    invoke-direct {v2, v0}, Lh2/yb;-><init>(Le1/b1;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    check-cast v2, Lh2/yb;

    .line 40
    .line 41
    return-object v2
.end method
