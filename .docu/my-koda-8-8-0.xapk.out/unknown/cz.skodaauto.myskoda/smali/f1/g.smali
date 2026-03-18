.class public abstract Lf1/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lf1/c;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 2
    .line 3
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 4
    .line 5
    sget-object v0, Lx4/i;->a:Ll2/e0;

    .line 6
    .line 7
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 8
    .line 9
    new-instance v1, Lf1/c;

    .line 10
    .line 11
    sget-wide v2, Le3/s;->e:J

    .line 12
    .line 13
    sget-wide v4, Le3/s;->b:J

    .line 14
    .line 15
    const v0, 0x3ec28f5c    # 0.38f

    .line 16
    .line 17
    .line 18
    invoke-static {v4, v5, v0}, Le3/s;->b(JF)J

    .line 19
    .line 20
    .line 21
    move-result-wide v8

    .line 22
    invoke-static {v4, v5, v0}, Le3/s;->b(JF)J

    .line 23
    .line 24
    .line 25
    move-result-wide v10

    .line 26
    move-wide v6, v4

    .line 27
    invoke-direct/range {v1 .. v11}, Lf1/c;-><init>(JJJJJ)V

    .line 28
    .line 29
    .line 30
    sput-object v1, Lf1/g;->a:Lf1/c;

    .line 31
    .line 32
    return-void
.end method

.method public static final a(Lf1/c;Lx2/s;Lt2/b;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p4

    .line 6
    .line 7
    move-object/from16 v0, p3

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v2, 0x250a92d0

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v2, v4, 0x6

    .line 18
    .line 19
    if-nez v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v2, 0x2

    .line 30
    :goto_0
    or-int/2addr v2, v4

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v2, v4

    .line 33
    :goto_1
    and-int/lit8 v5, v4, 0x30

    .line 34
    .line 35
    move-object/from16 v6, p1

    .line 36
    .line 37
    if-nez v5, :cond_3

    .line 38
    .line 39
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-eqz v5, :cond_2

    .line 44
    .line 45
    const/16 v5, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v5, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v2, v5

    .line 51
    :cond_3
    and-int/lit16 v5, v4, 0x180

    .line 52
    .line 53
    if-nez v5, :cond_5

    .line 54
    .line 55
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    if-eqz v5, :cond_4

    .line 60
    .line 61
    const/16 v5, 0x100

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_4
    const/16 v5, 0x80

    .line 65
    .line 66
    :goto_3
    or-int/2addr v2, v5

    .line 67
    :cond_5
    and-int/lit16 v5, v2, 0x93

    .line 68
    .line 69
    const/16 v7, 0x92

    .line 70
    .line 71
    const/4 v15, 0x0

    .line 72
    const/4 v8, 0x1

    .line 73
    if-eq v5, v7, :cond_6

    .line 74
    .line 75
    move v5, v8

    .line 76
    goto :goto_4

    .line 77
    :cond_6
    move v5, v15

    .line 78
    :goto_4
    and-int/lit8 v7, v2, 0x1

    .line 79
    .line 80
    invoke-virtual {v0, v7, v5}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_a

    .line 85
    .line 86
    sget v7, Lf1/f;->d:F

    .line 87
    .line 88
    sget v5, Lf1/f;->e:F

    .line 89
    .line 90
    invoke-static {v5}, Ls1/f;->b(F)Ls1/e;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    const-wide/16 v12, 0x0

    .line 95
    .line 96
    const/16 v14, 0x1c

    .line 97
    .line 98
    const/4 v9, 0x0

    .line 99
    const-wide/16 v10, 0x0

    .line 100
    .line 101
    move/from16 v16, v8

    .line 102
    .line 103
    move-object v8, v5

    .line 104
    move/from16 v5, v16

    .line 105
    .line 106
    invoke-static/range {v6 .. v14}, Ljp/ea;->b(Lx2/s;FLe3/n0;ZJJI)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    iget-wide v8, v1, Lf1/c;->a:J

    .line 111
    .line 112
    sget-object v6, Le3/j0;->a:Le3/i0;

    .line 113
    .line 114
    invoke-static {v7, v8, v9, v6}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v6

    .line 118
    sget-object v7, Lk1/r0;->d:Lk1/r0;

    .line 119
    .line 120
    invoke-static {v6}, Landroidx/compose/foundation/layout/a;->r(Lx2/s;)Lx2/s;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    const/4 v7, 0x0

    .line 125
    sget v8, Lf1/f;->i:F

    .line 126
    .line 127
    invoke-static {v6, v7, v8, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    invoke-static {v15, v5, v0}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    const/16 v8, 0xe

    .line 136
    .line 137
    invoke-static {v6, v7, v8}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 138
    .line 139
    .line 140
    move-result-object v6

    .line 141
    shl-int/lit8 v2, v2, 0x3

    .line 142
    .line 143
    and-int/lit16 v2, v2, 0x1c00

    .line 144
    .line 145
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 146
    .line 147
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 148
    .line 149
    invoke-static {v7, v8, v0, v15}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    iget-wide v8, v0, Ll2/t;->T:J

    .line 154
    .line 155
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 156
    .line 157
    .line 158
    move-result v8

    .line 159
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 160
    .line 161
    .line 162
    move-result-object v9

    .line 163
    invoke-static {v0, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 164
    .line 165
    .line 166
    move-result-object v6

    .line 167
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 168
    .line 169
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 170
    .line 171
    .line 172
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 173
    .line 174
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 175
    .line 176
    .line 177
    iget-boolean v11, v0, Ll2/t;->S:Z

    .line 178
    .line 179
    if-eqz v11, :cond_7

    .line 180
    .line 181
    invoke-virtual {v0, v10}, Ll2/t;->l(Lay0/a;)V

    .line 182
    .line 183
    .line 184
    goto :goto_5

    .line 185
    :cond_7
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 186
    .line 187
    .line 188
    :goto_5
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 189
    .line 190
    invoke-static {v10, v7, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 191
    .line 192
    .line 193
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 194
    .line 195
    invoke-static {v7, v9, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 196
    .line 197
    .line 198
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 199
    .line 200
    iget-boolean v9, v0, Ll2/t;->S:Z

    .line 201
    .line 202
    if-nez v9, :cond_8

    .line 203
    .line 204
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v9

    .line 208
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 209
    .line 210
    .line 211
    move-result-object v10

    .line 212
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v9

    .line 216
    if-nez v9, :cond_9

    .line 217
    .line 218
    :cond_8
    invoke-static {v8, v0, v8, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 219
    .line 220
    .line 221
    :cond_9
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 222
    .line 223
    invoke-static {v7, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 224
    .line 225
    .line 226
    shr-int/lit8 v2, v2, 0x6

    .line 227
    .line 228
    and-int/lit8 v2, v2, 0x70

    .line 229
    .line 230
    or-int/lit8 v2, v2, 0x6

    .line 231
    .line 232
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    sget-object v6, Lk1/t;->a:Lk1/t;

    .line 237
    .line 238
    invoke-virtual {v3, v6, v0, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    invoke-virtual {v0, v5}, Ll2/t;->q(Z)V

    .line 242
    .line 243
    .line 244
    goto :goto_6

    .line 245
    :cond_a
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 246
    .line 247
    .line 248
    :goto_6
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 249
    .line 250
    .line 251
    move-result-object v6

    .line 252
    if-eqz v6, :cond_b

    .line 253
    .line 254
    new-instance v0, La2/f;

    .line 255
    .line 256
    const/16 v5, 0xf

    .line 257
    .line 258
    move-object/from16 v2, p1

    .line 259
    .line 260
    invoke-direct/range {v0 .. v5}, La2/f;-><init>(Ljava/lang/Object;Lx2/s;Lay0/o;II)V

    .line 261
    .line 262
    .line 263
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 264
    .line 265
    :cond_b
    return-void
.end method

.method public static final b(Lx2/s;Lf1/c;Lay0/k;Ll2/o;II)V
    .locals 9

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x55480bb2

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p5, 0x1

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    or-int/lit8 v1, p4, 0x6

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    const/4 v1, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    const/4 v1, 0x2

    .line 25
    :goto_0
    or-int/2addr v1, p4

    .line 26
    :goto_1
    and-int/lit8 v2, p5, 0x2

    .line 27
    .line 28
    if-eqz v2, :cond_2

    .line 29
    .line 30
    or-int/lit8 v1, v1, 0x30

    .line 31
    .line 32
    goto :goto_3

    .line 33
    :cond_2
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_3

    .line 38
    .line 39
    const/16 v3, 0x20

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_3
    const/16 v3, 0x10

    .line 43
    .line 44
    :goto_2
    or-int/2addr v1, v3

    .line 45
    :goto_3
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    if-eqz v3, :cond_4

    .line 50
    .line 51
    const/16 v3, 0x100

    .line 52
    .line 53
    goto :goto_4

    .line 54
    :cond_4
    const/16 v3, 0x80

    .line 55
    .line 56
    :goto_4
    or-int/2addr v1, v3

    .line 57
    and-int/lit16 v3, v1, 0x93

    .line 58
    .line 59
    const/16 v4, 0x92

    .line 60
    .line 61
    if-eq v3, v4, :cond_5

    .line 62
    .line 63
    const/4 v3, 0x1

    .line 64
    goto :goto_5

    .line 65
    :cond_5
    const/4 v3, 0x0

    .line 66
    :goto_5
    and-int/lit8 v4, v1, 0x1

    .line 67
    .line 68
    invoke-virtual {p3, v4, v3}, Ll2/t;->O(IZ)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_8

    .line 73
    .line 74
    if-eqz v0, :cond_6

    .line 75
    .line 76
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 77
    .line 78
    :cond_6
    if-eqz v2, :cond_7

    .line 79
    .line 80
    sget-object p1, Lf1/g;->a:Lf1/c;

    .line 81
    .line 82
    :cond_7
    new-instance v0, Le2/e0;

    .line 83
    .line 84
    const/4 v2, 0x1

    .line 85
    invoke-direct {v0, v2, p2, p1}, Le2/e0;-><init>(ILay0/k;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    const v2, 0x33468687

    .line 89
    .line 90
    .line 91
    invoke-static {v2, p3, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    shr-int/lit8 v2, v1, 0x3

    .line 96
    .line 97
    and-int/lit8 v2, v2, 0xe

    .line 98
    .line 99
    or-int/lit16 v2, v2, 0x180

    .line 100
    .line 101
    shl-int/lit8 v1, v1, 0x3

    .line 102
    .line 103
    and-int/lit8 v1, v1, 0x70

    .line 104
    .line 105
    or-int/2addr v1, v2

    .line 106
    invoke-static {p1, p0, v0, p3, v1}, Lf1/g;->a(Lf1/c;Lx2/s;Lt2/b;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    :goto_6
    move-object v3, p0

    .line 110
    move-object v4, p1

    .line 111
    goto :goto_7

    .line 112
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 113
    .line 114
    .line 115
    goto :goto_6

    .line 116
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    if-eqz p0, :cond_9

    .line 121
    .line 122
    new-instance v2, La2/f;

    .line 123
    .line 124
    const/16 v8, 0xe

    .line 125
    .line 126
    move-object v5, p2

    .line 127
    move v6, p4

    .line 128
    move v7, p5

    .line 129
    invoke-direct/range {v2 .. v8}, La2/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llx0/e;III)V

    .line 130
    .line 131
    .line 132
    iput-object v2, p0, Ll2/u1;->d:Lay0/n;

    .line 133
    .line 134
    :cond_9
    return-void
.end method

.method public static final c(Ljava/lang/String;Lf1/c;Lx2/s;Lay0/o;Lay0/a;Ll2/o;I)V
    .locals 31

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move-object/from16 v5, p4

    .line 6
    .line 7
    move/from16 v6, p6

    .line 8
    .line 9
    move-object/from16 v0, p5

    .line 10
    .line 11
    check-cast v0, Ll2/t;

    .line 12
    .line 13
    const v1, -0x3d3c5ad4

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v1, v6, 0x6

    .line 20
    .line 21
    const/4 v3, 0x2

    .line 22
    move-object/from16 v9, p0

    .line 23
    .line 24
    if-nez v1, :cond_1

    .line 25
    .line 26
    invoke-virtual {v0, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_0

    .line 31
    .line 32
    const/4 v1, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v1, v3

    .line 35
    :goto_0
    or-int/2addr v1, v6

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v1, v6

    .line 38
    :goto_1
    and-int/lit8 v7, v6, 0x30

    .line 39
    .line 40
    const/4 v8, 0x1

    .line 41
    const/16 v10, 0x20

    .line 42
    .line 43
    if-nez v7, :cond_3

    .line 44
    .line 45
    invoke-virtual {v0, v8}, Ll2/t;->h(Z)Z

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    if-eqz v7, :cond_2

    .line 50
    .line 51
    move v7, v10

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v7, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v1, v7

    .line 56
    :cond_3
    and-int/lit16 v7, v6, 0x180

    .line 57
    .line 58
    if-nez v7, :cond_5

    .line 59
    .line 60
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    if-eqz v7, :cond_4

    .line 65
    .line 66
    const/16 v7, 0x100

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_4
    const/16 v7, 0x80

    .line 70
    .line 71
    :goto_3
    or-int/2addr v1, v7

    .line 72
    :cond_5
    and-int/lit16 v7, v6, 0xc00

    .line 73
    .line 74
    if-nez v7, :cond_7

    .line 75
    .line 76
    move-object/from16 v7, p2

    .line 77
    .line 78
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    if-eqz v11, :cond_6

    .line 83
    .line 84
    const/16 v11, 0x800

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_6
    const/16 v11, 0x400

    .line 88
    .line 89
    :goto_4
    or-int/2addr v1, v11

    .line 90
    goto :goto_5

    .line 91
    :cond_7
    move-object/from16 v7, p2

    .line 92
    .line 93
    :goto_5
    and-int/lit16 v11, v6, 0x6000

    .line 94
    .line 95
    if-nez v11, :cond_9

    .line 96
    .line 97
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v11

    .line 101
    if-eqz v11, :cond_8

    .line 102
    .line 103
    const/16 v11, 0x4000

    .line 104
    .line 105
    goto :goto_6

    .line 106
    :cond_8
    const/16 v11, 0x2000

    .line 107
    .line 108
    :goto_6
    or-int/2addr v1, v11

    .line 109
    :cond_9
    const/high16 v11, 0x30000

    .line 110
    .line 111
    and-int/2addr v11, v6

    .line 112
    const/high16 v12, 0x20000

    .line 113
    .line 114
    if-nez v11, :cond_b

    .line 115
    .line 116
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v11

    .line 120
    if-eqz v11, :cond_a

    .line 121
    .line 122
    move v11, v12

    .line 123
    goto :goto_7

    .line 124
    :cond_a
    const/high16 v11, 0x10000

    .line 125
    .line 126
    :goto_7
    or-int/2addr v1, v11

    .line 127
    :cond_b
    const v11, 0x12493

    .line 128
    .line 129
    .line 130
    and-int/2addr v11, v1

    .line 131
    const v13, 0x12492

    .line 132
    .line 133
    .line 134
    if-eq v11, v13, :cond_c

    .line 135
    .line 136
    const/4 v11, 0x1

    .line 137
    goto :goto_8

    .line 138
    :cond_c
    const/4 v11, 0x0

    .line 139
    :goto_8
    and-int/lit8 v13, v1, 0x1

    .line 140
    .line 141
    invoke-virtual {v0, v13, v11}, Ll2/t;->O(IZ)Z

    .line 142
    .line 143
    .line 144
    move-result v11

    .line 145
    if-eqz v11, :cond_19

    .line 146
    .line 147
    sget-object v13, Lf1/f;->f:Lx2/i;

    .line 148
    .line 149
    sget-object v11, Lk1/j;->a:Lk1/c;

    .line 150
    .line 151
    sget v11, Lf1/f;->h:F

    .line 152
    .line 153
    invoke-static {v11}, Lk1/j;->g(F)Lk1/h;

    .line 154
    .line 155
    .line 156
    move-result-object v15

    .line 157
    and-int/lit8 v8, v1, 0x70

    .line 158
    .line 159
    if-ne v8, v10, :cond_d

    .line 160
    .line 161
    const/4 v8, 0x1

    .line 162
    goto :goto_9

    .line 163
    :cond_d
    const/4 v8, 0x0

    .line 164
    :goto_9
    const/high16 v10, 0x70000

    .line 165
    .line 166
    and-int/2addr v10, v1

    .line 167
    if-ne v10, v12, :cond_e

    .line 168
    .line 169
    const/4 v10, 0x1

    .line 170
    goto :goto_a

    .line 171
    :cond_e
    const/4 v10, 0x0

    .line 172
    :goto_a
    or-int/2addr v8, v10

    .line 173
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v10

    .line 177
    if-nez v8, :cond_f

    .line 178
    .line 179
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 180
    .line 181
    if-ne v10, v8, :cond_10

    .line 182
    .line 183
    :cond_f
    new-instance v10, Lb71/i;

    .line 184
    .line 185
    const/16 v8, 0xd

    .line 186
    .line 187
    invoke-direct {v10, v5, v8}, Lb71/i;-><init>(Lay0/a;I)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v0, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    :cond_10
    check-cast v10, Lay0/a;

    .line 194
    .line 195
    const/16 v12, 0xc

    .line 196
    .line 197
    move v8, v11

    .line 198
    move-object v11, v10

    .line 199
    const/4 v10, 0x0

    .line 200
    move v14, v8

    .line 201
    const/4 v8, 0x1

    .line 202
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 203
    .line 204
    .line 205
    move-result-object v8

    .line 206
    const/high16 v7, 0x3f800000    # 1.0f

    .line 207
    .line 208
    invoke-static {v8, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 209
    .line 210
    .line 211
    move-result-object v8

    .line 212
    sget v9, Lf1/f;->a:F

    .line 213
    .line 214
    sget v10, Lf1/f;->b:F

    .line 215
    .line 216
    sget v11, Lf1/f;->c:F

    .line 217
    .line 218
    invoke-static {v8, v9, v11, v10, v11}, Landroidx/compose/foundation/layout/d;->p(Lx2/s;FFFF)Lx2/s;

    .line 219
    .line 220
    .line 221
    move-result-object v8

    .line 222
    const/4 v9, 0x0

    .line 223
    invoke-static {v8, v14, v9, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    const/16 v8, 0x36

    .line 228
    .line 229
    invoke-static {v15, v13, v0, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 230
    .line 231
    .line 232
    move-result-object v8

    .line 233
    iget-wide v9, v0, Ll2/t;->T:J

    .line 234
    .line 235
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 236
    .line 237
    .line 238
    move-result v9

    .line 239
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 240
    .line 241
    .line 242
    move-result-object v10

    .line 243
    invoke-static {v0, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 244
    .line 245
    .line 246
    move-result-object v3

    .line 247
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 248
    .line 249
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 250
    .line 251
    .line 252
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 253
    .line 254
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 255
    .line 256
    .line 257
    iget-boolean v12, v0, Ll2/t;->S:Z

    .line 258
    .line 259
    if-eqz v12, :cond_11

    .line 260
    .line 261
    invoke-virtual {v0, v11}, Ll2/t;->l(Lay0/a;)V

    .line 262
    .line 263
    .line 264
    goto :goto_b

    .line 265
    :cond_11
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 266
    .line 267
    .line 268
    :goto_b
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 269
    .line 270
    invoke-static {v12, v8, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 271
    .line 272
    .line 273
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 274
    .line 275
    invoke-static {v8, v10, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 276
    .line 277
    .line 278
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 279
    .line 280
    iget-boolean v13, v0, Ll2/t;->S:Z

    .line 281
    .line 282
    if-nez v13, :cond_12

    .line 283
    .line 284
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v13

    .line 288
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 289
    .line 290
    .line 291
    move-result-object v14

    .line 292
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result v13

    .line 296
    if-nez v13, :cond_13

    .line 297
    .line 298
    :cond_12
    invoke-static {v9, v0, v9, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 299
    .line 300
    .line 301
    :cond_13
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 302
    .line 303
    invoke-static {v9, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 304
    .line 305
    .line 306
    if-nez v4, :cond_14

    .line 307
    .line 308
    const v3, -0x586c6915

    .line 309
    .line 310
    .line 311
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 312
    .line 313
    .line 314
    const/4 v3, 0x0

    .line 315
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 316
    .line 317
    .line 318
    goto :goto_d

    .line 319
    :cond_14
    const v3, -0x586c6914

    .line 320
    .line 321
    .line 322
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 323
    .line 324
    .line 325
    sget v19, Lf1/f;->j:F

    .line 326
    .line 327
    const/16 v20, 0x0

    .line 328
    .line 329
    const/16 v23, 0x2

    .line 330
    .line 331
    sget-object v18, Lx2/p;->b:Lx2/p;

    .line 332
    .line 333
    move/from16 v21, v19

    .line 334
    .line 335
    move/from16 v22, v19

    .line 336
    .line 337
    invoke-static/range {v18 .. v23}, Landroidx/compose/foundation/layout/d;->l(Lx2/s;FFFFI)Lx2/s;

    .line 338
    .line 339
    .line 340
    move-result-object v3

    .line 341
    sget-object v13, Lx2/c;->d:Lx2/j;

    .line 342
    .line 343
    const/4 v14, 0x0

    .line 344
    invoke-static {v13, v14}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 345
    .line 346
    .line 347
    move-result-object v13

    .line 348
    iget-wide v14, v0, Ll2/t;->T:J

    .line 349
    .line 350
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 351
    .line 352
    .line 353
    move-result v14

    .line 354
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 355
    .line 356
    .line 357
    move-result-object v15

    .line 358
    invoke-static {v0, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 359
    .line 360
    .line 361
    move-result-object v3

    .line 362
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 363
    .line 364
    .line 365
    iget-boolean v7, v0, Ll2/t;->S:Z

    .line 366
    .line 367
    if-eqz v7, :cond_15

    .line 368
    .line 369
    invoke-virtual {v0, v11}, Ll2/t;->l(Lay0/a;)V

    .line 370
    .line 371
    .line 372
    goto :goto_c

    .line 373
    :cond_15
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 374
    .line 375
    .line 376
    :goto_c
    invoke-static {v12, v13, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 377
    .line 378
    .line 379
    invoke-static {v8, v15, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 380
    .line 381
    .line 382
    iget-boolean v7, v0, Ll2/t;->S:Z

    .line 383
    .line 384
    if-nez v7, :cond_16

    .line 385
    .line 386
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v7

    .line 390
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 391
    .line 392
    .line 393
    move-result-object v8

    .line 394
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 395
    .line 396
    .line 397
    move-result v7

    .line 398
    if-nez v7, :cond_17

    .line 399
    .line 400
    :cond_16
    invoke-static {v14, v0, v14, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 401
    .line 402
    .line 403
    :cond_17
    invoke-static {v9, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 404
    .line 405
    .line 406
    iget-wide v7, v2, Lf1/c;->c:J

    .line 407
    .line 408
    new-instance v3, Le3/s;

    .line 409
    .line 410
    invoke-direct {v3, v7, v8}, Le3/s;-><init>(J)V

    .line 411
    .line 412
    .line 413
    const/4 v14, 0x0

    .line 414
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 415
    .line 416
    .line 417
    move-result-object v7

    .line 418
    invoke-interface {v4, v3, v0, v7}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    const/4 v3, 0x1

    .line 422
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v0, v14}, Ll2/t;->q(Z)V

    .line 426
    .line 427
    .line 428
    :goto_d
    iget-wide v7, v2, Lf1/c;->b:J

    .line 429
    .line 430
    sget v27, Lf1/f;->g:I

    .line 431
    .line 432
    sget-wide v20, Lf1/f;->m:J

    .line 433
    .line 434
    sget-object v22, Lf1/f;->n:Lk4/x;

    .line 435
    .line 436
    sget-wide v28, Lf1/f;->o:J

    .line 437
    .line 438
    sget-wide v25, Lf1/f;->p:J

    .line 439
    .line 440
    new-instance v9, Lg4/p0;

    .line 441
    .line 442
    const/16 v24, 0x0

    .line 443
    .line 444
    const v30, 0xfd7f78

    .line 445
    .line 446
    .line 447
    const/16 v23, 0x0

    .line 448
    .line 449
    move-wide/from16 v18, v7

    .line 450
    .line 451
    move-object/from16 v17, v9

    .line 452
    .line 453
    invoke-direct/range {v17 .. v30}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 454
    .line 455
    .line 456
    const/high16 v3, 0x3f800000    # 1.0f

    .line 457
    .line 458
    float-to-double v7, v3

    .line 459
    const-wide/16 v10, 0x0

    .line 460
    .line 461
    cmpl-double v7, v7, v10

    .line 462
    .line 463
    if-lez v7, :cond_18

    .line 464
    .line 465
    goto :goto_e

    .line 466
    :cond_18
    const-string v7, "invalid weight; must be greater than zero"

    .line 467
    .line 468
    invoke-static {v7}, Ll1/a;->a(Ljava/lang/String;)V

    .line 469
    .line 470
    .line 471
    :goto_e
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 472
    .line 473
    const/4 v7, 0x1

    .line 474
    invoke-direct {v8, v3, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 475
    .line 476
    .line 477
    and-int/lit8 v1, v1, 0xe

    .line 478
    .line 479
    const/high16 v3, 0x180000

    .line 480
    .line 481
    or-int v17, v1, v3

    .line 482
    .line 483
    const/16 v18, 0x3b8

    .line 484
    .line 485
    const/4 v10, 0x0

    .line 486
    const/4 v11, 0x0

    .line 487
    const/4 v12, 0x0

    .line 488
    const/4 v13, 0x1

    .line 489
    const/4 v14, 0x0

    .line 490
    const/4 v15, 0x0

    .line 491
    move-object/from16 v16, v0

    .line 492
    .line 493
    move v3, v7

    .line 494
    move-object/from16 v7, p0

    .line 495
    .line 496
    invoke-static/range {v7 .. v18}, Lt1/l0;->c(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILe3/t;Ll2/o;II)V

    .line 497
    .line 498
    .line 499
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 500
    .line 501
    .line 502
    goto :goto_f

    .line 503
    :cond_19
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 504
    .line 505
    .line 506
    :goto_f
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 507
    .line 508
    .line 509
    move-result-object v7

    .line 510
    if-eqz v7, :cond_1a

    .line 511
    .line 512
    new-instance v0, La71/c0;

    .line 513
    .line 514
    move-object/from16 v1, p0

    .line 515
    .line 516
    move-object/from16 v3, p2

    .line 517
    .line 518
    invoke-direct/range {v0 .. v6}, La71/c0;-><init>(Ljava/lang/String;Lf1/c;Lx2/s;Lay0/o;Lay0/a;I)V

    .line 519
    .line 520
    .line 521
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 522
    .line 523
    :cond_1a
    return-void
.end method
