.class public abstract Luz/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x54

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Luz/g0;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(ZLl2/o;I)V
    .locals 25

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    check-cast v2, Ll2/t;

    .line 8
    .line 9
    const v3, -0x56f904f4

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ll2/t;->h(Z)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const/4 v4, 0x2

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    const/4 v3, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v4

    .line 25
    :goto_0
    or-int/2addr v3, v1

    .line 26
    and-int/lit8 v5, v3, 0x3

    .line 27
    .line 28
    const/4 v6, 0x1

    .line 29
    const/4 v7, 0x0

    .line 30
    if-eq v5, v4, :cond_1

    .line 31
    .line 32
    move v4, v6

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v4, v7

    .line 35
    :goto_1
    and-int/2addr v3, v6

    .line 36
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_9

    .line 41
    .line 42
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 43
    .line 44
    sget-object v4, Lk1/j;->a:Lk1/c;

    .line 45
    .line 46
    const/16 v5, 0x30

    .line 47
    .line 48
    invoke-static {v4, v3, v2, v5}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    iget-wide v8, v2, Ll2/t;->T:J

    .line 53
    .line 54
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 59
    .line 60
    .line 61
    move-result-object v8

    .line 62
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 63
    .line 64
    invoke-static {v2, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 65
    .line 66
    .line 67
    move-result-object v10

    .line 68
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 69
    .line 70
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 74
    .line 75
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 76
    .line 77
    .line 78
    iget-boolean v12, v2, Ll2/t;->S:Z

    .line 79
    .line 80
    if-eqz v12, :cond_2

    .line 81
    .line 82
    invoke-virtual {v2, v11}, Ll2/t;->l(Lay0/a;)V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_2
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 87
    .line 88
    .line 89
    :goto_2
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 90
    .line 91
    invoke-static {v11, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 95
    .line 96
    invoke-static {v3, v8, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 100
    .line 101
    iget-boolean v8, v2, Ll2/t;->S:Z

    .line 102
    .line 103
    if-nez v8, :cond_3

    .line 104
    .line 105
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 110
    .line 111
    .line 112
    move-result-object v11

    .line 113
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v8

    .line 117
    if-nez v8, :cond_4

    .line 118
    .line 119
    :cond_3
    invoke-static {v4, v2, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 120
    .line 121
    .line 122
    :cond_4
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 123
    .line 124
    invoke-static {v3, v10, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 125
    .line 126
    .line 127
    sget-object v3, Li91/k1;->d:Li91/k1;

    .line 128
    .line 129
    const/4 v4, 0x0

    .line 130
    if-eqz v0, :cond_5

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_5
    move-object v3, v4

    .line 134
    :goto_3
    if-nez v3, :cond_6

    .line 135
    .line 136
    sget-object v3, Li91/k1;->h:Li91/k1;

    .line 137
    .line 138
    :cond_6
    const-string v8, "remoteprofile_active_indicator_icon"

    .line 139
    .line 140
    invoke-static {v9, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 141
    .line 142
    .line 143
    move-result-object v8

    .line 144
    invoke-static {v3, v8, v2, v5, v7}, Li91/j0;->E(Li91/k1;Lx2/s;Ll2/o;II)V

    .line 145
    .line 146
    .line 147
    const v3, 0x7f120f77

    .line 148
    .line 149
    .line 150
    invoke-static {v2, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 155
    .line 156
    invoke-virtual {v2, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    check-cast v5, Lj91/f;

    .line 161
    .line 162
    invoke-virtual {v5}, Lj91/f;->e()Lg4/p0;

    .line 163
    .line 164
    .line 165
    move-result-object v5

    .line 166
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 167
    .line 168
    invoke-virtual {v2, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v10

    .line 172
    check-cast v10, Lj91/e;

    .line 173
    .line 174
    invoke-virtual {v10}, Lj91/e;->s()J

    .line 175
    .line 176
    .line 177
    move-result-wide v10

    .line 178
    new-instance v12, Le3/s;

    .line 179
    .line 180
    invoke-direct {v12, v10, v11}, Le3/s;-><init>(J)V

    .line 181
    .line 182
    .line 183
    if-eqz v0, :cond_7

    .line 184
    .line 185
    move-object v4, v12

    .line 186
    :cond_7
    if-nez v4, :cond_8

    .line 187
    .line 188
    const v4, -0x362c590a

    .line 189
    .line 190
    .line 191
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v2, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    check-cast v4, Lj91/e;

    .line 199
    .line 200
    invoke-virtual {v4}, Lj91/e;->r()J

    .line 201
    .line 202
    .line 203
    move-result-wide v10

    .line 204
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 205
    .line 206
    .line 207
    :goto_4
    move-wide v7, v10

    .line 208
    goto :goto_5

    .line 209
    :cond_8
    const v8, -0x362c61c2

    .line 210
    .line 211
    .line 212
    invoke-virtual {v2, v8}, Ll2/t;->Y(I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    iget-wide v10, v4, Le3/s;->a:J

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :goto_5
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 222
    .line 223
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    check-cast v4, Lj91/c;

    .line 228
    .line 229
    iget v10, v4, Lj91/c;->c:F

    .line 230
    .line 231
    const/4 v13, 0x0

    .line 232
    const/16 v14, 0xe

    .line 233
    .line 234
    const/4 v11, 0x0

    .line 235
    const/4 v12, 0x0

    .line 236
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 237
    .line 238
    .line 239
    move-result-object v4

    .line 240
    const-string v9, "remoteprofile_active_indicator_text"

    .line 241
    .line 242
    invoke-static {v4, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 243
    .line 244
    .line 245
    move-result-object v4

    .line 246
    const/16 v22, 0x0

    .line 247
    .line 248
    const v23, 0xfff0

    .line 249
    .line 250
    .line 251
    move-object/from16 v20, v2

    .line 252
    .line 253
    move-object v2, v3

    .line 254
    move-object v3, v5

    .line 255
    move v9, v6

    .line 256
    move-wide v5, v7

    .line 257
    const-wide/16 v7, 0x0

    .line 258
    .line 259
    move v10, v9

    .line 260
    const/4 v9, 0x0

    .line 261
    move v12, v10

    .line 262
    const-wide/16 v10, 0x0

    .line 263
    .line 264
    move v13, v12

    .line 265
    const/4 v12, 0x0

    .line 266
    move v14, v13

    .line 267
    const/4 v13, 0x0

    .line 268
    move/from16 v16, v14

    .line 269
    .line 270
    const-wide/16 v14, 0x0

    .line 271
    .line 272
    move/from16 v17, v16

    .line 273
    .line 274
    const/16 v16, 0x0

    .line 275
    .line 276
    move/from16 v18, v17

    .line 277
    .line 278
    const/16 v17, 0x0

    .line 279
    .line 280
    move/from16 v19, v18

    .line 281
    .line 282
    const/16 v18, 0x0

    .line 283
    .line 284
    move/from16 v21, v19

    .line 285
    .line 286
    const/16 v19, 0x0

    .line 287
    .line 288
    move/from16 v24, v21

    .line 289
    .line 290
    const/16 v21, 0x0

    .line 291
    .line 292
    move/from16 v0, v24

    .line 293
    .line 294
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 295
    .line 296
    .line 297
    move-object/from16 v2, v20

    .line 298
    .line 299
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 300
    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_9
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 304
    .line 305
    .line 306
    :goto_6
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    if-eqz v0, :cond_a

    .line 311
    .line 312
    new-instance v2, Lal/m;

    .line 313
    .line 314
    const/16 v3, 0x9

    .line 315
    .line 316
    move/from16 v4, p0

    .line 317
    .line 318
    invoke-direct {v2, v1, v3, v4}, Lal/m;-><init>(IIZ)V

    .line 319
    .line 320
    .line 321
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 322
    .line 323
    :cond_a
    return-void
.end method

.method public static final b(Ltz/n2;Lay0/a;Ll2/o;I)V
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move/from16 v9, p3

    .line 6
    .line 7
    move-object/from16 v15, p2

    .line 8
    .line 9
    check-cast v15, Ll2/t;

    .line 10
    .line 11
    const v1, 0x5dab874c

    .line 12
    .line 13
    .line 14
    invoke-virtual {v15, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v15, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int/2addr v1, v9

    .line 27
    invoke-virtual {v15, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    const/16 v2, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v2, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v1, v2

    .line 39
    and-int/lit8 v2, v1, 0x13

    .line 40
    .line 41
    const/16 v4, 0x12

    .line 42
    .line 43
    const/4 v5, 0x1

    .line 44
    const/4 v6, 0x0

    .line 45
    if-eq v2, v4, :cond_2

    .line 46
    .line 47
    move v2, v5

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    move v2, v6

    .line 50
    :goto_2
    and-int/lit8 v4, v1, 0x1

    .line 51
    .line 52
    invoke-virtual {v15, v4, v2}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_b

    .line 57
    .line 58
    sget-object v2, Lx2/c;->n:Lx2/i;

    .line 59
    .line 60
    invoke-static {v15}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    iget v4, v4, Lj91/c;->c:F

    .line 65
    .line 66
    const/16 v20, 0x0

    .line 67
    .line 68
    const/16 v21, 0xd

    .line 69
    .line 70
    sget-object v22, Lx2/p;->b:Lx2/p;

    .line 71
    .line 72
    const/16 v17, 0x0

    .line 73
    .line 74
    const/16 v19, 0x0

    .line 75
    .line 76
    move/from16 v18, v4

    .line 77
    .line 78
    move-object/from16 v16, v22

    .line 79
    .line 80
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    sget-object v7, Lk1/j;->a:Lk1/c;

    .line 85
    .line 86
    const/16 v8, 0x30

    .line 87
    .line 88
    invoke-static {v7, v2, v15, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    iget-wide v7, v15, Ll2/t;->T:J

    .line 93
    .line 94
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 99
    .line 100
    .line 101
    move-result-object v8

    .line 102
    invoke-static {v15, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 107
    .line 108
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 112
    .line 113
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 114
    .line 115
    .line 116
    iget-boolean v11, v15, Ll2/t;->S:Z

    .line 117
    .line 118
    if-eqz v11, :cond_3

    .line 119
    .line 120
    invoke-virtual {v15, v10}, Ll2/t;->l(Lay0/a;)V

    .line 121
    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_3
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 125
    .line 126
    .line 127
    :goto_3
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 128
    .line 129
    invoke-static {v10, v2, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 133
    .line 134
    invoke-static {v2, v8, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 135
    .line 136
    .line 137
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 138
    .line 139
    iget-boolean v8, v15, Ll2/t;->S:Z

    .line 140
    .line 141
    if-nez v8, :cond_4

    .line 142
    .line 143
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v8

    .line 147
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 148
    .line 149
    .line 150
    move-result-object v10

    .line 151
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v8

    .line 155
    if-nez v8, :cond_5

    .line 156
    .line 157
    :cond_4
    invoke-static {v7, v15, v7, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 158
    .line 159
    .line 160
    :cond_5
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 161
    .line 162
    invoke-static {v2, v4, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 163
    .line 164
    .line 165
    const v2, 0x7f08034a

    .line 166
    .line 167
    .line 168
    invoke-static {v2, v6, v15}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 169
    .line 170
    .line 171
    move-result-object v10

    .line 172
    invoke-static {v15}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 177
    .line 178
    .line 179
    move-result-wide v7

    .line 180
    new-instance v2, Le3/s;

    .line 181
    .line 182
    invoke-direct {v2, v7, v8}, Le3/s;-><init>(J)V

    .line 183
    .line 184
    .line 185
    iget-boolean v4, v0, Ltz/n2;->l:Z

    .line 186
    .line 187
    const/4 v7, 0x0

    .line 188
    if-eqz v4, :cond_6

    .line 189
    .line 190
    goto :goto_4

    .line 191
    :cond_6
    move-object v2, v7

    .line 192
    :goto_4
    if-nez v2, :cond_7

    .line 193
    .line 194
    const v2, 0x54f12456

    .line 195
    .line 196
    .line 197
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 198
    .line 199
    .line 200
    invoke-static {v15}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    invoke-virtual {v2}, Lj91/e;->r()J

    .line 205
    .line 206
    .line 207
    move-result-wide v11

    .line 208
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 209
    .line 210
    .line 211
    :goto_5
    move-wide v13, v11

    .line 212
    goto :goto_6

    .line 213
    :cond_7
    const v4, 0x54f1198f

    .line 214
    .line 215
    .line 216
    invoke-virtual {v15, v4}, Ll2/t;->Y(I)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 220
    .line 221
    .line 222
    iget-wide v11, v2, Le3/s;->a:J

    .line 223
    .line 224
    goto :goto_5

    .line 225
    :goto_6
    const/16 v16, 0x30

    .line 226
    .line 227
    const/16 v17, 0x4

    .line 228
    .line 229
    const/4 v11, 0x0

    .line 230
    const/4 v12, 0x0

    .line 231
    invoke-static/range {v10 .. v17}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 232
    .line 233
    .line 234
    iget-boolean v2, v0, Ltz/n2;->k:Z

    .line 235
    .line 236
    if-eqz v2, :cond_8

    .line 237
    .line 238
    const v2, 0x7f120fa1

    .line 239
    .line 240
    .line 241
    goto :goto_7

    .line 242
    :cond_8
    const v2, 0x7f120fa0

    .line 243
    .line 244
    .line 245
    :goto_7
    invoke-static {v15, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v10

    .line 249
    invoke-static {v15}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 250
    .line 251
    .line 252
    move-result-object v2

    .line 253
    invoke-virtual {v2}, Lj91/f;->f()Lg4/p0;

    .line 254
    .line 255
    .line 256
    move-result-object v23

    .line 257
    invoke-static {v15}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 258
    .line 259
    .line 260
    move-result-object v2

    .line 261
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 262
    .line 263
    .line 264
    move-result-wide v11

    .line 265
    new-instance v2, Le3/s;

    .line 266
    .line 267
    invoke-direct {v2, v11, v12}, Le3/s;-><init>(J)V

    .line 268
    .line 269
    .line 270
    iget-boolean v4, v0, Ltz/n2;->l:Z

    .line 271
    .line 272
    if-eqz v4, :cond_9

    .line 273
    .line 274
    move-object v7, v2

    .line 275
    :cond_9
    if-nez v7, :cond_a

    .line 276
    .line 277
    const v2, 0x54f15c56

    .line 278
    .line 279
    .line 280
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 281
    .line 282
    .line 283
    invoke-static {v15}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 284
    .line 285
    .line 286
    move-result-object v2

    .line 287
    invoke-virtual {v2}, Lj91/e;->r()J

    .line 288
    .line 289
    .line 290
    move-result-wide v7

    .line 291
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 292
    .line 293
    .line 294
    :goto_8
    move-wide/from16 v24, v7

    .line 295
    .line 296
    goto :goto_9

    .line 297
    :cond_a
    const v2, 0x54f151cd

    .line 298
    .line 299
    .line 300
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 304
    .line 305
    .line 306
    iget-wide v7, v7, Le3/s;->a:J

    .line 307
    .line 308
    goto :goto_8

    .line 309
    :goto_9
    const/16 v36, 0x0

    .line 310
    .line 311
    const v37, 0xfffffe

    .line 312
    .line 313
    .line 314
    const-wide/16 v26, 0x0

    .line 315
    .line 316
    const/16 v28, 0x0

    .line 317
    .line 318
    const/16 v29, 0x0

    .line 319
    .line 320
    const-wide/16 v30, 0x0

    .line 321
    .line 322
    const/16 v32, 0x0

    .line 323
    .line 324
    const-wide/16 v33, 0x0

    .line 325
    .line 326
    const/16 v35, 0x0

    .line 327
    .line 328
    invoke-static/range {v23 .. v37}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 329
    .line 330
    .line 331
    move-result-object v11

    .line 332
    invoke-static {v15}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    iget v2, v2, Lj91/c;->b:F

    .line 337
    .line 338
    const/16 v26, 0x0

    .line 339
    .line 340
    const/16 v27, 0xe

    .line 341
    .line 342
    const/16 v24, 0x0

    .line 343
    .line 344
    const/16 v25, 0x0

    .line 345
    .line 346
    move/from16 v23, v2

    .line 347
    .line 348
    invoke-static/range {v22 .. v27}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 349
    .line 350
    .line 351
    move-result-object v12

    .line 352
    move-object/from16 v2, v22

    .line 353
    .line 354
    const/16 v30, 0x0

    .line 355
    .line 356
    const v31, 0xfff8

    .line 357
    .line 358
    .line 359
    const-wide/16 v13, 0x0

    .line 360
    .line 361
    move-object/from16 v28, v15

    .line 362
    .line 363
    const-wide/16 v15, 0x0

    .line 364
    .line 365
    const/16 v17, 0x0

    .line 366
    .line 367
    const-wide/16 v18, 0x0

    .line 368
    .line 369
    const/16 v20, 0x0

    .line 370
    .line 371
    const/16 v21, 0x0

    .line 372
    .line 373
    const-wide/16 v22, 0x0

    .line 374
    .line 375
    const/16 v24, 0x0

    .line 376
    .line 377
    const/16 v25, 0x0

    .line 378
    .line 379
    const/16 v26, 0x0

    .line 380
    .line 381
    const/16 v27, 0x0

    .line 382
    .line 383
    const/16 v29, 0x0

    .line 384
    .line 385
    invoke-static/range {v10 .. v31}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 386
    .line 387
    .line 388
    move-object/from16 v15, v28

    .line 389
    .line 390
    invoke-virtual {v15, v5}, Ll2/t;->q(Z)V

    .line 391
    .line 392
    .line 393
    const v4, 0x7f120f78

    .line 394
    .line 395
    .line 396
    invoke-static {v15, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object v5

    .line 400
    iget-boolean v8, v0, Ltz/n2;->l:Z

    .line 401
    .line 402
    invoke-static {v15}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 403
    .line 404
    .line 405
    move-result-object v6

    .line 406
    iget v6, v6, Lj91/c;->e:F

    .line 407
    .line 408
    const/16 v26, 0x0

    .line 409
    .line 410
    const/16 v27, 0xd

    .line 411
    .line 412
    const/16 v23, 0x0

    .line 413
    .line 414
    const/16 v25, 0x0

    .line 415
    .line 416
    move-object/from16 v22, v2

    .line 417
    .line 418
    move/from16 v24, v6

    .line 419
    .line 420
    invoke-static/range {v22 .. v27}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 421
    .line 422
    .line 423
    move-result-object v2

    .line 424
    invoke-static {v2, v4}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 425
    .line 426
    .line 427
    move-result-object v7

    .line 428
    const v2, 0x7f080465

    .line 429
    .line 430
    .line 431
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 432
    .line 433
    .line 434
    move-result-object v4

    .line 435
    and-int/lit8 v1, v1, 0x70

    .line 436
    .line 437
    const/4 v2, 0x0

    .line 438
    move-object v6, v15

    .line 439
    invoke-static/range {v1 .. v8}, Li91/j0;->h0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 440
    .line 441
    .line 442
    goto :goto_a

    .line 443
    :cond_b
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 444
    .line 445
    .line 446
    :goto_a
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    if-eqz v1, :cond_c

    .line 451
    .line 452
    new-instance v2, Luu/q0;

    .line 453
    .line 454
    const/16 v4, 0xa

    .line 455
    .line 456
    invoke-direct {v2, v9, v4, v0, v3}, Luu/q0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 457
    .line 458
    .line 459
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 460
    .line 461
    :cond_c
    return-void
.end method

.method public static final c(Lay0/a;Ll2/o;I)V
    .locals 31

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    move/from16 v8, p2

    .line 4
    .line 5
    move-object/from16 v5, p1

    .line 6
    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const v0, -0x2c37d38e

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v5, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v1, 0x2

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v1

    .line 25
    :goto_0
    or-int/2addr v0, v8

    .line 26
    and-int/lit8 v3, v0, 0x3

    .line 27
    .line 28
    if-eq v3, v1, :cond_1

    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/4 v1, 0x0

    .line 33
    :goto_1
    and-int/lit8 v3, v0, 0x1

    .line 34
    .line 35
    invoke-virtual {v5, v3, v1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    const-string v1, "remoteprofile_empty_screen_text"

    .line 42
    .line 43
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 44
    .line 45
    invoke-static {v3, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 46
    .line 47
    .line 48
    move-result-object v11

    .line 49
    const v1, 0x7f120f9a

    .line 50
    .line 51
    .line 52
    invoke-static {v5, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    sget-object v1, Lh2/ec;->a:Ll2/u2;

    .line 57
    .line 58
    invoke-virtual {v5, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Lh2/dc;

    .line 63
    .line 64
    iget-object v10, v1, Lh2/dc;->k:Lg4/p0;

    .line 65
    .line 66
    const/16 v29, 0x0

    .line 67
    .line 68
    const v30, 0xfff8

    .line 69
    .line 70
    .line 71
    const-wide/16 v12, 0x0

    .line 72
    .line 73
    const-wide/16 v14, 0x0

    .line 74
    .line 75
    const/16 v16, 0x0

    .line 76
    .line 77
    const-wide/16 v17, 0x0

    .line 78
    .line 79
    const/16 v19, 0x0

    .line 80
    .line 81
    const/16 v20, 0x0

    .line 82
    .line 83
    const-wide/16 v21, 0x0

    .line 84
    .line 85
    const/16 v23, 0x0

    .line 86
    .line 87
    const/16 v24, 0x0

    .line 88
    .line 89
    const/16 v25, 0x0

    .line 90
    .line 91
    const/16 v26, 0x0

    .line 92
    .line 93
    const/16 v28, 0x180

    .line 94
    .line 95
    move-object/from16 v27, v5

    .line 96
    .line 97
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 98
    .line 99
    .line 100
    const v1, 0x7f120f78

    .line 101
    .line 102
    .line 103
    invoke-static {v5, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 108
    .line 109
    invoke-virtual {v5, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    check-cast v6, Lj91/c;

    .line 114
    .line 115
    iget v11, v6, Lj91/c;->d:F

    .line 116
    .line 117
    const/4 v13, 0x0

    .line 118
    const/16 v14, 0xd

    .line 119
    .line 120
    const/4 v10, 0x0

    .line 121
    const/4 v12, 0x0

    .line 122
    move-object v9, v3

    .line 123
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    invoke-static {v3, v1}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    const v1, 0x7f080465

    .line 132
    .line 133
    .line 134
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v3

    .line 138
    shl-int/lit8 v0, v0, 0x3

    .line 139
    .line 140
    and-int/lit8 v0, v0, 0x70

    .line 141
    .line 142
    const/16 v1, 0x8

    .line 143
    .line 144
    const/4 v7, 0x0

    .line 145
    invoke-static/range {v0 .. v7}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_2
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 150
    .line 151
    .line 152
    :goto_2
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    if-eqz v0, :cond_3

    .line 157
    .line 158
    new-instance v1, Lt10/d;

    .line 159
    .line 160
    const/16 v3, 0xd

    .line 161
    .line 162
    invoke-direct {v1, v2, v8, v3}, Lt10/d;-><init>(Lay0/a;II)V

    .line 163
    .line 164
    .line 165
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 166
    .line 167
    :cond_3
    return-void
.end method

.method public static final d(Ltz/l2;Lay0/k;Ljava/lang/String;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move/from16 v8, p4

    .line 6
    .line 7
    move-object/from16 v9, p3

    .line 8
    .line 9
    check-cast v9, Ll2/t;

    .line 10
    .line 11
    const v0, 0x760745a8

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v2, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v2

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int/2addr v0, v8

    .line 28
    and-int/lit8 v3, v8, 0x30

    .line 29
    .line 30
    const/16 v4, 0x20

    .line 31
    .line 32
    if-nez v3, :cond_2

    .line 33
    .line 34
    invoke-virtual {v9, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_1

    .line 39
    .line 40
    move v3, v4

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v3, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v0, v3

    .line 45
    :cond_2
    and-int/lit16 v3, v8, 0x180

    .line 46
    .line 47
    if-nez v3, :cond_4

    .line 48
    .line 49
    move-object/from16 v3, p2

    .line 50
    .line 51
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_3

    .line 56
    .line 57
    const/16 v5, 0x100

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    const/16 v5, 0x80

    .line 61
    .line 62
    :goto_2
    or-int/2addr v0, v5

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    move-object/from16 v3, p2

    .line 65
    .line 66
    :goto_3
    and-int/lit16 v5, v0, 0x93

    .line 67
    .line 68
    const/16 v6, 0x92

    .line 69
    .line 70
    const/4 v10, 0x1

    .line 71
    const/4 v11, 0x0

    .line 72
    if-eq v5, v6, :cond_5

    .line 73
    .line 74
    move v5, v10

    .line 75
    goto :goto_4

    .line 76
    :cond_5
    move v5, v11

    .line 77
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 78
    .line 79
    invoke-virtual {v9, v6, v5}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-eqz v5, :cond_e

    .line 84
    .line 85
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 86
    .line 87
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    check-cast v6, Lj91/e;

    .line 92
    .line 93
    invoke-virtual {v6}, Lj91/e;->q()J

    .line 94
    .line 95
    .line 96
    move-result-wide v12

    .line 97
    new-instance v6, Le3/s;

    .line 98
    .line 99
    invoke-direct {v6, v12, v13}, Le3/s;-><init>(J)V

    .line 100
    .line 101
    .line 102
    iget-boolean v12, v1, Ltz/l2;->d:Z

    .line 103
    .line 104
    if-eqz v12, :cond_6

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_6
    const/4 v6, 0x0

    .line 108
    :goto_5
    if-nez v6, :cond_7

    .line 109
    .line 110
    const v6, 0x114c9b76

    .line 111
    .line 112
    .line 113
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    check-cast v6, Lj91/e;

    .line 121
    .line 122
    invoke-virtual {v6}, Lj91/e;->r()J

    .line 123
    .line 124
    .line 125
    move-result-wide v14

    .line 126
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    goto :goto_6

    .line 130
    :cond_7
    const v12, 0x114c910c

    .line 131
    .line 132
    .line 133
    invoke-virtual {v9, v12}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    iget-wide v14, v6, Le3/s;->a:J

    .line 140
    .line 141
    :goto_6
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v6

    .line 145
    check-cast v6, Lj91/e;

    .line 146
    .line 147
    move-wide/from16 v16, v14

    .line 148
    .line 149
    invoke-virtual {v6}, Lj91/e;->q()J

    .line 150
    .line 151
    .line 152
    move-result-wide v13

    .line 153
    new-instance v6, Le3/s;

    .line 154
    .line 155
    invoke-direct {v6, v13, v14}, Le3/s;-><init>(J)V

    .line 156
    .line 157
    .line 158
    iget-boolean v12, v1, Ltz/l2;->d:Z

    .line 159
    .line 160
    if-eqz v12, :cond_8

    .line 161
    .line 162
    move-object v13, v6

    .line 163
    goto :goto_7

    .line 164
    :cond_8
    const/4 v13, 0x0

    .line 165
    :goto_7
    if-nez v13, :cond_9

    .line 166
    .line 167
    const v6, 0x114cab36

    .line 168
    .line 169
    .line 170
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v5

    .line 177
    check-cast v5, Lj91/e;

    .line 178
    .line 179
    invoke-virtual {v5}, Lj91/e;->r()J

    .line 180
    .line 181
    .line 182
    move-result-wide v5

    .line 183
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    goto :goto_8

    .line 187
    :cond_9
    const v5, 0x114ca0cc

    .line 188
    .line 189
    .line 190
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 194
    .line 195
    .line 196
    iget-wide v5, v13, Le3/s;->a:J

    .line 197
    .line 198
    :goto_8
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 199
    .line 200
    const/high16 v13, 0x3f800000    # 1.0f

    .line 201
    .line 202
    invoke-static {v12, v13}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 203
    .line 204
    .line 205
    move-result-object v18

    .line 206
    iget-boolean v12, v1, Ltz/l2;->d:Z

    .line 207
    .line 208
    and-int/lit8 v13, v0, 0x70

    .line 209
    .line 210
    if-ne v13, v4, :cond_a

    .line 211
    .line 212
    move v4, v10

    .line 213
    goto :goto_9

    .line 214
    :cond_a
    move v4, v11

    .line 215
    :goto_9
    and-int/lit8 v0, v0, 0xe

    .line 216
    .line 217
    if-ne v0, v2, :cond_b

    .line 218
    .line 219
    goto :goto_a

    .line 220
    :cond_b
    move v10, v11

    .line 221
    :goto_a
    or-int v0, v4, v10

    .line 222
    .line 223
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    if-nez v0, :cond_c

    .line 228
    .line 229
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 230
    .line 231
    if-ne v2, v0, :cond_d

    .line 232
    .line 233
    :cond_c
    new-instance v2, Lt61/g;

    .line 234
    .line 235
    const/16 v0, 0x16

    .line 236
    .line 237
    invoke-direct {v2, v0, v7, v1}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {v9, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    :cond_d
    move-object/from16 v22, v2

    .line 244
    .line 245
    check-cast v22, Lay0/a;

    .line 246
    .line 247
    const/16 v23, 0xe

    .line 248
    .line 249
    const/16 v20, 0x0

    .line 250
    .line 251
    const/16 v21, 0x0

    .line 252
    .line 253
    move/from16 v19, v12

    .line 254
    .line 255
    invoke-static/range {v18 .. v23}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v10

    .line 259
    new-instance v0, Li40/c2;

    .line 260
    .line 261
    move-object v2, v3

    .line 262
    move-wide/from16 v3, v16

    .line 263
    .line 264
    invoke-direct/range {v0 .. v6}, Li40/c2;-><init>(Ltz/l2;Ljava/lang/String;JJ)V

    .line 265
    .line 266
    .line 267
    const v1, -0x27ff5223

    .line 268
    .line 269
    .line 270
    invoke-static {v1, v9, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 271
    .line 272
    .line 273
    move-result-object v3

    .line 274
    const/16 v5, 0xc00

    .line 275
    .line 276
    const/4 v6, 0x6

    .line 277
    const/4 v1, 0x0

    .line 278
    const/4 v2, 0x0

    .line 279
    move-object v4, v9

    .line 280
    move-object v0, v10

    .line 281
    invoke-static/range {v0 .. v6}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 282
    .line 283
    .line 284
    goto :goto_b

    .line 285
    :cond_e
    move-object v4, v9

    .line 286
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 287
    .line 288
    .line 289
    :goto_b
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 290
    .line 291
    .line 292
    move-result-object v6

    .line 293
    if-eqz v6, :cond_f

    .line 294
    .line 295
    new-instance v0, Luj/y;

    .line 296
    .line 297
    const/16 v5, 0x11

    .line 298
    .line 299
    move-object/from16 v1, p0

    .line 300
    .line 301
    move-object/from16 v3, p2

    .line 302
    .line 303
    move-object v2, v7

    .line 304
    move v4, v8

    .line 305
    invoke-direct/range {v0 .. v5}, Luj/y;-><init>(Ljava/lang/Object;Lay0/k;Ljava/lang/Object;II)V

    .line 306
    .line 307
    .line 308
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 309
    .line 310
    :cond_f
    return-void
.end method

.method public static final e(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v5, p0

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p0, 0x7d7915c5

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v5, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_a

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_9

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v9

    .line 41
    invoke-static {v5}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v11

    .line 45
    const-class v2, Ltz/p2;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v12, 0x0

    .line 60
    invoke-static/range {v6 .. v12}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v5, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v8, v1

    .line 73
    check-cast v8, Ltz/p2;

    .line 74
    .line 75
    iget-object v0, v8, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v5, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v0, p0

    .line 87
    check-cast v0, Ltz/n2;

    .line 88
    .line 89
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez p0, :cond_1

    .line 100
    .line 101
    if-ne v1, v2, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v6, Luz/b0;

    .line 104
    .line 105
    const/4 v12, 0x0

    .line 106
    const/16 v13, 0x11

    .line 107
    .line 108
    const/4 v7, 0x0

    .line 109
    const-class v9, Ltz/p2;

    .line 110
    .line 111
    const-string v10, "onRefresh"

    .line 112
    .line 113
    const-string v11, "onRefresh()V"

    .line 114
    .line 115
    invoke-direct/range {v6 .. v13}, Luz/b0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v6

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    if-nez p0, :cond_3

    .line 135
    .line 136
    if-ne v3, v2, :cond_4

    .line 137
    .line 138
    :cond_3
    new-instance v6, Luz/c0;

    .line 139
    .line 140
    const/4 v12, 0x0

    .line 141
    const/4 v13, 0x3

    .line 142
    const/4 v7, 0x1

    .line 143
    const-class v9, Ltz/p2;

    .line 144
    .line 145
    const-string v10, "onChargingProfile"

    .line 146
    .line 147
    const-string v11, "onChargingProfile(J)V"

    .line 148
    .line 149
    invoke-direct/range {v6 .. v13}, Luz/c0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    move-object v3, v6

    .line 156
    :cond_4
    check-cast v3, Lhy0/g;

    .line 157
    .line 158
    check-cast v3, Lay0/k;

    .line 159
    .line 160
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    if-nez p0, :cond_5

    .line 169
    .line 170
    if-ne v4, v2, :cond_6

    .line 171
    .line 172
    :cond_5
    new-instance v6, Luz/b0;

    .line 173
    .line 174
    const/4 v12, 0x0

    .line 175
    const/16 v13, 0x12

    .line 176
    .line 177
    const/4 v7, 0x0

    .line 178
    const-class v9, Ltz/p2;

    .line 179
    .line 180
    const-string v10, "onAddChargingProfile"

    .line 181
    .line 182
    const-string v11, "onAddChargingProfile()V"

    .line 183
    .line 184
    invoke-direct/range {v6 .. v13}, Luz/b0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    move-object v4, v6

    .line 191
    :cond_6
    check-cast v4, Lhy0/g;

    .line 192
    .line 193
    check-cast v4, Lay0/a;

    .line 194
    .line 195
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result p0

    .line 199
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v6

    .line 203
    if-nez p0, :cond_7

    .line 204
    .line 205
    if-ne v6, v2, :cond_8

    .line 206
    .line 207
    :cond_7
    new-instance v6, Luz/b0;

    .line 208
    .line 209
    const/4 v12, 0x0

    .line 210
    const/16 v13, 0x13

    .line 211
    .line 212
    const/4 v7, 0x0

    .line 213
    const-class v9, Ltz/p2;

    .line 214
    .line 215
    const-string v10, "onGoBack"

    .line 216
    .line 217
    const-string v11, "onGoBack()V"

    .line 218
    .line 219
    invoke-direct/range {v6 .. v13}, Luz/b0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    :cond_8
    check-cast v6, Lhy0/g;

    .line 226
    .line 227
    check-cast v6, Lay0/a;

    .line 228
    .line 229
    move-object v2, v3

    .line 230
    move-object v3, v4

    .line 231
    move-object v4, v6

    .line 232
    const/4 v6, 0x0

    .line 233
    const/4 v7, 0x0

    .line 234
    invoke-static/range {v0 .. v7}, Luz/g0;->f(Ltz/n2;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 235
    .line 236
    .line 237
    goto :goto_1

    .line 238
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 241
    .line 242
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    throw p0

    .line 246
    :cond_a
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 247
    .line 248
    .line 249
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 250
    .line 251
    .line 252
    move-result-object p0

    .line 253
    if-eqz p0, :cond_b

    .line 254
    .line 255
    new-instance v0, Luu/s1;

    .line 256
    .line 257
    const/16 v1, 0x1d

    .line 258
    .line 259
    invoke-direct {v0, p1, v1}, Luu/s1;-><init>(II)V

    .line 260
    .line 261
    .line 262
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 263
    .line 264
    :cond_b
    return-void
.end method

.method public static final f(Ltz/n2;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Ll2/o;II)V
    .locals 20

    .line 1
    move-object/from16 v12, p5

    .line 2
    .line 3
    check-cast v12, Ll2/t;

    .line 4
    .line 5
    const v0, -0x4690521f

    .line 6
    .line 7
    .line 8
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v2, p0

    .line 12
    .line 13
    invoke-virtual {v12, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p6, v0

    .line 23
    .line 24
    and-int/lit8 v1, p7, 0x2

    .line 25
    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    or-int/lit8 v0, v0, 0x30

    .line 29
    .line 30
    move-object/from16 v3, p1

    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_1
    move-object/from16 v3, p1

    .line 34
    .line 35
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-eqz v4, :cond_2

    .line 40
    .line 41
    const/16 v4, 0x20

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    const/16 v4, 0x10

    .line 45
    .line 46
    :goto_1
    or-int/2addr v0, v4

    .line 47
    :goto_2
    and-int/lit8 v4, p7, 0x4

    .line 48
    .line 49
    if-eqz v4, :cond_3

    .line 50
    .line 51
    or-int/lit16 v0, v0, 0x180

    .line 52
    .line 53
    move-object/from16 v5, p2

    .line 54
    .line 55
    goto :goto_4

    .line 56
    :cond_3
    move-object/from16 v5, p2

    .line 57
    .line 58
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    if-eqz v6, :cond_4

    .line 63
    .line 64
    const/16 v6, 0x100

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_4
    const/16 v6, 0x80

    .line 68
    .line 69
    :goto_3
    or-int/2addr v0, v6

    .line 70
    :goto_4
    and-int/lit8 v6, p7, 0x8

    .line 71
    .line 72
    if-eqz v6, :cond_5

    .line 73
    .line 74
    or-int/lit16 v0, v0, 0xc00

    .line 75
    .line 76
    move-object/from16 v7, p3

    .line 77
    .line 78
    goto :goto_6

    .line 79
    :cond_5
    move-object/from16 v7, p3

    .line 80
    .line 81
    invoke-virtual {v12, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v8

    .line 85
    if-eqz v8, :cond_6

    .line 86
    .line 87
    const/16 v8, 0x800

    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_6
    const/16 v8, 0x400

    .line 91
    .line 92
    :goto_5
    or-int/2addr v0, v8

    .line 93
    :goto_6
    and-int/lit8 v8, p7, 0x10

    .line 94
    .line 95
    if-eqz v8, :cond_7

    .line 96
    .line 97
    or-int/lit16 v0, v0, 0x6000

    .line 98
    .line 99
    move-object/from16 v9, p4

    .line 100
    .line 101
    goto :goto_8

    .line 102
    :cond_7
    move-object/from16 v9, p4

    .line 103
    .line 104
    invoke-virtual {v12, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v10

    .line 108
    if-eqz v10, :cond_8

    .line 109
    .line 110
    const/16 v10, 0x4000

    .line 111
    .line 112
    goto :goto_7

    .line 113
    :cond_8
    const/16 v10, 0x2000

    .line 114
    .line 115
    :goto_7
    or-int/2addr v0, v10

    .line 116
    :goto_8
    and-int/lit16 v10, v0, 0x2493

    .line 117
    .line 118
    const/16 v11, 0x2492

    .line 119
    .line 120
    const/4 v13, 0x1

    .line 121
    if-eq v10, v11, :cond_9

    .line 122
    .line 123
    move v10, v13

    .line 124
    goto :goto_9

    .line 125
    :cond_9
    const/4 v10, 0x0

    .line 126
    :goto_9
    and-int/2addr v0, v13

    .line 127
    invoke-virtual {v12, v0, v10}, Ll2/t;->O(IZ)Z

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    if-eqz v0, :cond_12

    .line 132
    .line 133
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 134
    .line 135
    if-eqz v1, :cond_b

    .line 136
    .line 137
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    if-ne v1, v0, :cond_a

    .line 142
    .line 143
    new-instance v1, Lu41/u;

    .line 144
    .line 145
    const/16 v3, 0x14

    .line 146
    .line 147
    invoke-direct {v1, v3}, Lu41/u;-><init>(I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :cond_a
    check-cast v1, Lay0/a;

    .line 154
    .line 155
    move-object v3, v1

    .line 156
    :cond_b
    if-eqz v4, :cond_d

    .line 157
    .line 158
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    if-ne v1, v0, :cond_c

    .line 163
    .line 164
    new-instance v1, Luu/r;

    .line 165
    .line 166
    const/16 v4, 0x11

    .line 167
    .line 168
    invoke-direct {v1, v4}, Luu/r;-><init>(I)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    :cond_c
    check-cast v1, Lay0/k;

    .line 175
    .line 176
    move/from16 v19, v6

    .line 177
    .line 178
    move-object v6, v1

    .line 179
    move/from16 v1, v19

    .line 180
    .line 181
    goto :goto_a

    .line 182
    :cond_d
    move v1, v6

    .line 183
    move-object v6, v5

    .line 184
    :goto_a
    if-eqz v1, :cond_f

    .line 185
    .line 186
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    if-ne v1, v0, :cond_e

    .line 191
    .line 192
    new-instance v1, Lu41/u;

    .line 193
    .line 194
    const/16 v4, 0x14

    .line 195
    .line 196
    invoke-direct {v1, v4}, Lu41/u;-><init>(I)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    :cond_e
    check-cast v1, Lay0/a;

    .line 203
    .line 204
    move-object v5, v1

    .line 205
    goto :goto_b

    .line 206
    :cond_f
    move-object v5, v7

    .line 207
    :goto_b
    if-eqz v8, :cond_11

    .line 208
    .line 209
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    if-ne v1, v0, :cond_10

    .line 214
    .line 215
    new-instance v1, Lu41/u;

    .line 216
    .line 217
    const/16 v0, 0x14

    .line 218
    .line 219
    invoke-direct {v1, v0}, Lu41/u;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v12, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    :cond_10
    move-object v0, v1

    .line 226
    check-cast v0, Lay0/a;

    .line 227
    .line 228
    move-object v15, v0

    .line 229
    goto :goto_c

    .line 230
    :cond_11
    move-object v15, v9

    .line 231
    :goto_c
    new-instance v0, Lt10/d;

    .line 232
    .line 233
    const/16 v1, 0xe

    .line 234
    .line 235
    invoke-direct {v0, v15, v1}, Lt10/d;-><init>(Lay0/a;I)V

    .line 236
    .line 237
    .line 238
    const v1, -0x1b04bb63

    .line 239
    .line 240
    .line 241
    invoke-static {v1, v12, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    new-instance v1, La71/u0;

    .line 246
    .line 247
    const/16 v2, 0x1d

    .line 248
    .line 249
    move-object/from16 v4, p0

    .line 250
    .line 251
    invoke-direct/range {v1 .. v6}, La71/u0;-><init>(ILay0/a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    move-object/from16 v16, v3

    .line 255
    .line 256
    move-object/from16 v18, v5

    .line 257
    .line 258
    move-object/from16 v17, v6

    .line 259
    .line 260
    const v2, 0x44d0a772

    .line 261
    .line 262
    .line 263
    invoke-static {v2, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 264
    .line 265
    .line 266
    move-result-object v11

    .line 267
    const v13, 0x30000030

    .line 268
    .line 269
    .line 270
    const/16 v14, 0x1fd

    .line 271
    .line 272
    move-object v1, v0

    .line 273
    const/4 v0, 0x0

    .line 274
    const/4 v2, 0x0

    .line 275
    const/4 v3, 0x0

    .line 276
    const/4 v4, 0x0

    .line 277
    const/4 v5, 0x0

    .line 278
    const-wide/16 v6, 0x0

    .line 279
    .line 280
    const-wide/16 v8, 0x0

    .line 281
    .line 282
    const/4 v10, 0x0

    .line 283
    invoke-static/range {v0 .. v14}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 284
    .line 285
    .line 286
    move-object v6, v15

    .line 287
    move-object/from16 v3, v16

    .line 288
    .line 289
    move-object/from16 v4, v17

    .line 290
    .line 291
    move-object/from16 v5, v18

    .line 292
    .line 293
    goto :goto_d

    .line 294
    :cond_12
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 295
    .line 296
    .line 297
    move-object v4, v5

    .line 298
    move-object v5, v7

    .line 299
    move-object v6, v9

    .line 300
    :goto_d
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    if-eqz v0, :cond_13

    .line 305
    .line 306
    new-instance v1, La71/c0;

    .line 307
    .line 308
    const/16 v9, 0x1b

    .line 309
    .line 310
    move-object/from16 v2, p0

    .line 311
    .line 312
    move/from16 v7, p6

    .line 313
    .line 314
    move/from16 v8, p7

    .line 315
    .line 316
    invoke-direct/range {v1 .. v9}, La71/c0;-><init>(Lql0/h;Lay0/a;Llx0/e;Lay0/a;Lay0/a;III)V

    .line 317
    .line 318
    .line 319
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 320
    .line 321
    :cond_13
    return-void
.end method

.method public static final g(Ltz/m2;Lx2/s;Ll2/o;I)V
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    check-cast v3, Ll2/t;

    .line 8
    .line 9
    const v4, 0x214293d3

    .line 10
    .line 11
    .line 12
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    const/4 v4, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v4, 0x2

    .line 24
    :goto_0
    or-int v4, p3, v4

    .line 25
    .line 26
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_1

    .line 31
    .line 32
    const/16 v5, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v5, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v4, v5

    .line 38
    and-int/lit8 v5, v4, 0x13

    .line 39
    .line 40
    const/16 v6, 0x12

    .line 41
    .line 42
    const/4 v7, 0x1

    .line 43
    if-eq v5, v6, :cond_2

    .line 44
    .line 45
    move v5, v7

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/4 v5, 0x0

    .line 48
    :goto_2
    and-int/2addr v4, v7

    .line 49
    invoke-virtual {v3, v4, v5}, Ll2/t;->O(IZ)Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-eqz v4, :cond_6

    .line 54
    .line 55
    sget-object v4, Lk1/j;->e:Lk1/f;

    .line 56
    .line 57
    sget-object v5, Lx2/c;->q:Lx2/h;

    .line 58
    .line 59
    const/16 v6, 0x36

    .line 60
    .line 61
    invoke-static {v4, v5, v3, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    iget-wide v5, v3, Ll2/t;->T:J

    .line 66
    .line 67
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    invoke-static {v3, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 80
    .line 81
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 85
    .line 86
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 87
    .line 88
    .line 89
    iget-boolean v10, v3, Ll2/t;->S:Z

    .line 90
    .line 91
    if-eqz v10, :cond_3

    .line 92
    .line 93
    invoke-virtual {v3, v9}, Ll2/t;->l(Lay0/a;)V

    .line 94
    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_3
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 98
    .line 99
    .line 100
    :goto_3
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 101
    .line 102
    invoke-static {v9, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 103
    .line 104
    .line 105
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 106
    .line 107
    invoke-static {v4, v6, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 108
    .line 109
    .line 110
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 111
    .line 112
    iget-boolean v6, v3, Ll2/t;->S:Z

    .line 113
    .line 114
    if-nez v6, :cond_4

    .line 115
    .line 116
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 121
    .line 122
    .line 123
    move-result-object v9

    .line 124
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v6

    .line 128
    if-nez v6, :cond_5

    .line 129
    .line 130
    :cond_4
    invoke-static {v5, v3, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 131
    .line 132
    .line 133
    :cond_5
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 134
    .line 135
    invoke-static {v4, v8, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 136
    .line 137
    .line 138
    iget-object v4, v0, Ltz/m2;->a:Ljava/lang/String;

    .line 139
    .line 140
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 141
    .line 142
    invoke-virtual {v3, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    check-cast v6, Lj91/f;

    .line 147
    .line 148
    invoke-virtual {v6}, Lj91/f;->l()Lg4/p0;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    const-string v8, "charging_profiles_warning_title"

    .line 153
    .line 154
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 155
    .line 156
    invoke-static {v9, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 157
    .line 158
    .line 159
    move-result-object v8

    .line 160
    new-instance v14, Lr4/k;

    .line 161
    .line 162
    const/4 v10, 0x3

    .line 163
    invoke-direct {v14, v10}, Lr4/k;-><init>(I)V

    .line 164
    .line 165
    .line 166
    const/16 v23, 0x0

    .line 167
    .line 168
    const v24, 0xfbf8

    .line 169
    .line 170
    .line 171
    move-object/from16 v21, v3

    .line 172
    .line 173
    move-object v3, v4

    .line 174
    move-object v4, v6

    .line 175
    move v11, v7

    .line 176
    const-wide/16 v6, 0x0

    .line 177
    .line 178
    move-object v12, v5

    .line 179
    move-object v5, v8

    .line 180
    move-object v13, v9

    .line 181
    const-wide/16 v8, 0x0

    .line 182
    .line 183
    move v15, v10

    .line 184
    const/4 v10, 0x0

    .line 185
    move/from16 v17, v11

    .line 186
    .line 187
    move-object/from16 v16, v12

    .line 188
    .line 189
    const-wide/16 v11, 0x0

    .line 190
    .line 191
    move-object/from16 v18, v13

    .line 192
    .line 193
    const/4 v13, 0x0

    .line 194
    move/from16 v20, v15

    .line 195
    .line 196
    move-object/from16 v19, v16

    .line 197
    .line 198
    const-wide/16 v15, 0x0

    .line 199
    .line 200
    move/from16 v22, v17

    .line 201
    .line 202
    const/16 v17, 0x0

    .line 203
    .line 204
    move-object/from16 v25, v18

    .line 205
    .line 206
    const/16 v18, 0x0

    .line 207
    .line 208
    move-object/from16 v26, v19

    .line 209
    .line 210
    const/16 v19, 0x0

    .line 211
    .line 212
    move/from16 v27, v20

    .line 213
    .line 214
    const/16 v20, 0x0

    .line 215
    .line 216
    move/from16 v28, v22

    .line 217
    .line 218
    const/16 v22, 0x180

    .line 219
    .line 220
    move-object/from16 v1, v26

    .line 221
    .line 222
    move/from16 v2, v27

    .line 223
    .line 224
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 225
    .line 226
    .line 227
    move-object/from16 v3, v21

    .line 228
    .line 229
    iget-object v4, v0, Ltz/m2;->b:Ljava/lang/String;

    .line 230
    .line 231
    invoke-virtual {v3, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    check-cast v1, Lj91/f;

    .line 236
    .line 237
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 242
    .line 243
    invoke-virtual {v3, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v5

    .line 247
    check-cast v5, Lj91/e;

    .line 248
    .line 249
    invoke-virtual {v5}, Lj91/e;->s()J

    .line 250
    .line 251
    .line 252
    move-result-wide v6

    .line 253
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 254
    .line 255
    invoke-virtual {v3, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v5

    .line 259
    check-cast v5, Lj91/c;

    .line 260
    .line 261
    iget v11, v5, Lj91/c;->c:F

    .line 262
    .line 263
    const/4 v13, 0x0

    .line 264
    const/16 v14, 0xd

    .line 265
    .line 266
    const/4 v10, 0x0

    .line 267
    const/4 v12, 0x0

    .line 268
    move-object/from16 v9, v25

    .line 269
    .line 270
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    const-string v8, "charging_profiles_warning_description"

    .line 275
    .line 276
    invoke-static {v5, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 277
    .line 278
    .line 279
    move-result-object v5

    .line 280
    new-instance v14, Lr4/k;

    .line 281
    .line 282
    invoke-direct {v14, v2}, Lr4/k;-><init>(I)V

    .line 283
    .line 284
    .line 285
    const v24, 0xfbf0

    .line 286
    .line 287
    .line 288
    const-wide/16 v8, 0x0

    .line 289
    .line 290
    const/4 v10, 0x0

    .line 291
    const-wide/16 v11, 0x0

    .line 292
    .line 293
    const/4 v13, 0x0

    .line 294
    const/16 v22, 0x0

    .line 295
    .line 296
    move-object v3, v4

    .line 297
    move-object v4, v1

    .line 298
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 299
    .line 300
    .line 301
    move-object/from16 v3, v21

    .line 302
    .line 303
    const/4 v11, 0x1

    .line 304
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    goto :goto_4

    .line 308
    :cond_6
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 309
    .line 310
    .line 311
    :goto_4
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    if-eqz v1, :cond_7

    .line 316
    .line 317
    new-instance v2, Luu/q0;

    .line 318
    .line 319
    const/16 v3, 0xb

    .line 320
    .line 321
    move-object/from16 v4, p1

    .line 322
    .line 323
    move/from16 v5, p3

    .line 324
    .line 325
    invoke-direct {v2, v5, v3, v0, v4}, Luu/q0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 329
    .line 330
    :cond_7
    return-void
.end method
