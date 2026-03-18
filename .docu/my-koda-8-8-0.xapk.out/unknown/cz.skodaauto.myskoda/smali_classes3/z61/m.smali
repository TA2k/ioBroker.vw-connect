.class public abstract Lz61/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "touch_diagnosis_info_text_1"

    .line 2
    .line 3
    const-string v1, "touch_diagnosis_info_text_2"

    .line 4
    .line 5
    const-string v2, "touch_diagnosis_info_text_0"

    .line 6
    .line 7
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lz61/m;->a:Ljava/util/List;

    .line 16
    .line 17
    return-void
.end method

.method public static final a(FILl2/o;Lx2/s;)V
    .locals 11

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0xf01ff04

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p1

    .line 19
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    and-int/lit8 v1, v0, 0x13

    .line 32
    .line 33
    const/16 v2, 0x12

    .line 34
    .line 35
    const/4 v3, 0x1

    .line 36
    const/4 v4, 0x0

    .line 37
    if-eq v1, v2, :cond_2

    .line 38
    .line 39
    move v1, v3

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    move v1, v4

    .line 42
    :goto_2
    and-int/2addr v0, v3

    .line 43
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    sget-object v0, Lh71/u;->a:Ll2/u2;

    .line 50
    .line 51
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Lh71/t;

    .line 56
    .line 57
    iget v1, v1, Lh71/t;->f:F

    .line 58
    .line 59
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    check-cast v2, Lh71/t;

    .line 64
    .line 65
    iget v2, v2, Lh71/t;->a:F

    .line 66
    .line 67
    sub-float v6, v1, v2

    .line 68
    .line 69
    new-instance v1, Lt4/f;

    .line 70
    .line 71
    invoke-direct {v1, p0}, Lt4/f;-><init>(F)V

    .line 72
    .line 73
    .line 74
    int-to-float v2, v4

    .line 75
    invoke-static {v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->j(FLt4/f;)Ljava/lang/Comparable;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Lt4/f;

    .line 80
    .line 81
    iget v7, v1, Lt4/f;->d:F

    .line 82
    .line 83
    const/4 v9, 0x0

    .line 84
    const/16 v10, 0xc

    .line 85
    .line 86
    const/4 v8, 0x0

    .line 87
    move-object v5, p3

    .line 88
    invoke-static/range {v5 .. v10}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 89
    .line 90
    .line 91
    move-result-object p3

    .line 92
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    check-cast v0, Lh71/t;

    .line 97
    .line 98
    iget v0, v0, Lh71/t;->a:F

    .line 99
    .line 100
    invoke-static {p3, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    sget-object v0, Lh71/m;->a:Ll2/u2;

    .line 105
    .line 106
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    check-cast v0, Lh71/l;

    .line 111
    .line 112
    iget-object v0, v0, Lh71/l;->e:Lh71/k;

    .line 113
    .line 114
    iget-wide v0, v0, Lh71/k;->i:J

    .line 115
    .line 116
    sget-object v2, Ls1/f;->a:Ls1/e;

    .line 117
    .line 118
    invoke-static {p3, v0, v1, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 119
    .line 120
    .line 121
    move-result-object p3

    .line 122
    invoke-static {p3, p2, v4}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_3
    move-object v5, p3

    .line 127
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 128
    .line 129
    .line 130
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 131
    .line 132
    .line 133
    move-result-object p2

    .line 134
    if-eqz p2, :cond_4

    .line 135
    .line 136
    new-instance p3, Lh2/x;

    .line 137
    .line 138
    const/4 v0, 0x3

    .line 139
    invoke-direct {p3, v5, p0, p1, v0}, Lh2/x;-><init>(Ljava/lang/Object;FII)V

    .line 140
    .line 141
    .line 142
    iput-object p3, p2, Ll2/u1;->d:Lay0/n;

    .line 143
    .line 144
    :cond_4
    return-void
.end method

.method public static final b(Lx2/s;Ll2/o;I)V
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v12, p1

    .line 4
    .line 5
    check-cast v12, Ll2/t;

    .line 6
    .line 7
    const v2, 0x60c92520

    .line 8
    .line 9
    .line 10
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v3

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v4, v2, 0x3

    .line 26
    .line 27
    const/4 v15, 0x1

    .line 28
    const/4 v5, 0x0

    .line 29
    if-eq v4, v3, :cond_1

    .line 30
    .line 31
    move v3, v15

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v3, v5

    .line 34
    :goto_1
    and-int/2addr v2, v15

    .line 35
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_9

    .line 40
    .line 41
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 42
    .line 43
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 44
    .line 45
    invoke-static {v2, v3, v12, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    iget-wide v6, v12, Ll2/t;->T:J

    .line 50
    .line 51
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 56
    .line 57
    .line 58
    move-result-object v6

    .line 59
    invoke-static {v12, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 64
    .line 65
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 69
    .line 70
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 71
    .line 72
    .line 73
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 74
    .line 75
    if-eqz v9, :cond_2

    .line 76
    .line 77
    invoke-virtual {v12, v8}, Ll2/t;->l(Lay0/a;)V

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_2
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 82
    .line 83
    .line 84
    :goto_2
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 85
    .line 86
    invoke-static {v9, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 87
    .line 88
    .line 89
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 90
    .line 91
    invoke-static {v2, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 95
    .line 96
    iget-boolean v10, v12, Ll2/t;->S:Z

    .line 97
    .line 98
    if-nez v10, :cond_3

    .line 99
    .line 100
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v10

    .line 104
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v11

    .line 108
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v10

    .line 112
    if-nez v10, :cond_4

    .line 113
    .line 114
    :cond_3
    invoke-static {v4, v12, v4, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 115
    .line 116
    .line 117
    :cond_4
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 118
    .line 119
    invoke-static {v4, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 123
    .line 124
    const/high16 v10, 0x3f800000    # 1.0f

    .line 125
    .line 126
    move-object v11, v4

    .line 127
    invoke-static {v7, v10}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    sget-object v13, Lj91/j;->a:Ll2/u2;

    .line 132
    .line 133
    invoke-virtual {v12, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v14

    .line 137
    check-cast v14, Lj91/f;

    .line 138
    .line 139
    invoke-virtual {v14}, Lj91/f;->h()Lg4/p0;

    .line 140
    .line 141
    .line 142
    move-result-object v16

    .line 143
    const/high16 v14, 0x42000000    # 32.0f

    .line 144
    .line 145
    move-object/from16 v31, v6

    .line 146
    .line 147
    const-wide v5, 0x100000000L

    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    invoke-static {v5, v6, v14}, Lgq/b;->e(JF)J

    .line 153
    .line 154
    .line 155
    move-result-wide v19

    .line 156
    const/high16 v14, 0x42200000    # 40.0f

    .line 157
    .line 158
    invoke-static {v5, v6, v14}, Lgq/b;->e(JF)J

    .line 159
    .line 160
    .line 161
    move-result-wide v26

    .line 162
    sget-object v21, Lk4/x;->k:Lk4/x;

    .line 163
    .line 164
    const/16 v29, 0x0

    .line 165
    .line 166
    const v30, 0xfdfff9

    .line 167
    .line 168
    .line 169
    const-wide/16 v17, 0x0

    .line 170
    .line 171
    const/16 v22, 0x0

    .line 172
    .line 173
    const-wide/16 v23, 0x0

    .line 174
    .line 175
    const/16 v25, 0x0

    .line 176
    .line 177
    const/16 v28, 0x0

    .line 178
    .line 179
    invoke-static/range {v16 .. v30}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    const-string v6, "touch_diagnosis_body_title"

    .line 184
    .line 185
    invoke-static {v6, v12}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    move-object v14, v13

    .line 190
    const/16 v13, 0x180

    .line 191
    .line 192
    move-object/from16 v16, v14

    .line 193
    .line 194
    const/16 v14, 0x1f8

    .line 195
    .line 196
    move-object/from16 v17, v3

    .line 197
    .line 198
    move-object v3, v5

    .line 199
    const/4 v5, 0x0

    .line 200
    move-object/from16 v18, v2

    .line 201
    .line 202
    move-object v2, v6

    .line 203
    const/4 v6, 0x0

    .line 204
    move-object/from16 v19, v7

    .line 205
    .line 206
    const/4 v7, 0x0

    .line 207
    move-object/from16 v20, v8

    .line 208
    .line 209
    const/4 v8, 0x0

    .line 210
    move-object/from16 v21, v9

    .line 211
    .line 212
    move/from16 v22, v10

    .line 213
    .line 214
    const-wide/16 v9, 0x0

    .line 215
    .line 216
    move-object/from16 v23, v11

    .line 217
    .line 218
    const/4 v11, 0x0

    .line 219
    move-object/from16 v1, v16

    .line 220
    .line 221
    move-object/from16 v32, v18

    .line 222
    .line 223
    move-object/from16 v0, v19

    .line 224
    .line 225
    move/from16 v15, v22

    .line 226
    .line 227
    move-object/from16 v34, v23

    .line 228
    .line 229
    move-object/from16 v33, v31

    .line 230
    .line 231
    invoke-static/range {v2 .. v14}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 232
    .line 233
    .line 234
    sget-object v2, Lh71/u;->a:Ll2/u2;

    .line 235
    .line 236
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    check-cast v3, Lh71/t;

    .line 241
    .line 242
    iget v3, v3, Lh71/t;->d:F

    .line 243
    .line 244
    invoke-static {v0, v3, v12, v0, v15}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 245
    .line 246
    .line 247
    move-result-object v4

    .line 248
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    check-cast v1, Lj91/f;

    .line 253
    .line 254
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    const-string v1, "touch_diagnosis_description"

    .line 259
    .line 260
    invoke-static {v1, v12}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v1

    .line 264
    move-object/from16 v35, v2

    .line 265
    .line 266
    move-object v2, v1

    .line 267
    move-object/from16 v1, v35

    .line 268
    .line 269
    invoke-static/range {v2 .. v14}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v2

    .line 276
    check-cast v2, Lh71/t;

    .line 277
    .line 278
    iget v2, v2, Lh71/t;->f:F

    .line 279
    .line 280
    invoke-static {v0, v2, v12, v0, v15}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    check-cast v1, Lh71/t;

    .line 289
    .line 290
    iget v1, v1, Lh71/t;->b:F

    .line 291
    .line 292
    invoke-static {v1}, Lk1/j;->g(F)Lk1/h;

    .line 293
    .line 294
    .line 295
    move-result-object v1

    .line 296
    move-object/from16 v3, v17

    .line 297
    .line 298
    const/4 v4, 0x0

    .line 299
    invoke-static {v1, v3, v12, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    iget-wide v5, v12, Ll2/t;->T:J

    .line 304
    .line 305
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 306
    .line 307
    .line 308
    move-result v3

    .line 309
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 310
    .line 311
    .line 312
    move-result-object v5

    .line 313
    invoke-static {v12, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 318
    .line 319
    .line 320
    iget-boolean v6, v12, Ll2/t;->S:Z

    .line 321
    .line 322
    if-eqz v6, :cond_5

    .line 323
    .line 324
    move-object/from16 v6, v20

    .line 325
    .line 326
    invoke-virtual {v12, v6}, Ll2/t;->l(Lay0/a;)V

    .line 327
    .line 328
    .line 329
    :goto_3
    move-object/from16 v6, v21

    .line 330
    .line 331
    goto :goto_4

    .line 332
    :cond_5
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 333
    .line 334
    .line 335
    goto :goto_3

    .line 336
    :goto_4
    invoke-static {v6, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 337
    .line 338
    .line 339
    move-object/from16 v1, v32

    .line 340
    .line 341
    invoke-static {v1, v5, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 342
    .line 343
    .line 344
    iget-boolean v1, v12, Ll2/t;->S:Z

    .line 345
    .line 346
    if-nez v1, :cond_6

    .line 347
    .line 348
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 353
    .line 354
    .line 355
    move-result-object v5

    .line 356
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    move-result v1

    .line 360
    if-nez v1, :cond_7

    .line 361
    .line 362
    :cond_6
    move-object/from16 v1, v33

    .line 363
    .line 364
    goto :goto_6

    .line 365
    :cond_7
    :goto_5
    move-object/from16 v11, v34

    .line 366
    .line 367
    goto :goto_7

    .line 368
    :goto_6
    invoke-static {v3, v12, v3, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 369
    .line 370
    .line 371
    goto :goto_5

    .line 372
    :goto_7
    invoke-static {v11, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 373
    .line 374
    .line 375
    const v1, 0x6f4658ce

    .line 376
    .line 377
    .line 378
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 379
    .line 380
    .line 381
    sget-object v1, Lz61/m;->a:Ljava/util/List;

    .line 382
    .line 383
    check-cast v1, Ljava/lang/Iterable;

    .line 384
    .line 385
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 386
    .line 387
    .line 388
    move-result-object v1

    .line 389
    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 390
    .line 391
    .line 392
    move-result v2

    .line 393
    if-eqz v2, :cond_8

    .line 394
    .line 395
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v2

    .line 399
    check-cast v2, Ljava/lang/String;

    .line 400
    .line 401
    invoke-static {v0, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 402
    .line 403
    .line 404
    move-result-object v3

    .line 405
    const/4 v5, 0x6

    .line 406
    invoke-static {v5, v2, v12, v3}, Lz61/m;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 407
    .line 408
    .line 409
    goto :goto_8

    .line 410
    :cond_8
    const/4 v2, 0x1

    .line 411
    invoke-static {v12, v4, v2, v2}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 412
    .line 413
    .line 414
    goto :goto_9

    .line 415
    :cond_9
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 416
    .line 417
    .line 418
    :goto_9
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    if-eqz v0, :cond_a

    .line 423
    .line 424
    new-instance v1, Luz/e;

    .line 425
    .line 426
    const/16 v2, 0xd

    .line 427
    .line 428
    move-object/from16 v3, p0

    .line 429
    .line 430
    move/from16 v4, p2

    .line 431
    .line 432
    invoke-direct {v1, v3, v4, v2}, Luz/e;-><init>(Lx2/s;II)V

    .line 433
    .line 434
    .line 435
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 436
    .line 437
    :cond_a
    return-void
.end method

.method public static final c(ILjava/lang/String;Ll2/o;Lx2/s;)V
    .locals 19

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v2, p3

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 7
    .line 8
    .line 9
    move-result-object v3

    .line 10
    move-object/from16 v14, p2

    .line 11
    .line 12
    check-cast v14, Ll2/t;

    .line 13
    .line 14
    const v4, -0x49d4f21b

    .line 15
    .line 16
    .line 17
    invoke-virtual {v14, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    const/16 v4, 0x20

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/16 v4, 0x10

    .line 30
    .line 31
    :goto_0
    or-int v4, p0, v4

    .line 32
    .line 33
    and-int/lit8 v5, v4, 0x13

    .line 34
    .line 35
    const/16 v6, 0x12

    .line 36
    .line 37
    const/4 v7, 0x1

    .line 38
    const/4 v8, 0x0

    .line 39
    if-eq v5, v6, :cond_1

    .line 40
    .line 41
    move v5, v7

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v5, v8

    .line 44
    :goto_1
    and-int/2addr v4, v7

    .line 45
    invoke-virtual {v14, v4, v5}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_d

    .line 50
    .line 51
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 56
    .line 57
    if-ne v4, v5, :cond_2

    .line 58
    .line 59
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    invoke-virtual {v14, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    check-cast v4, Ll2/b1;

    .line 67
    .line 68
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    if-ne v6, v5, :cond_3

    .line 73
    .line 74
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 75
    .line 76
    .line 77
    move-result-object v6

    .line 78
    invoke-virtual {v14, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_3
    check-cast v6, Ll2/b1;

    .line 82
    .line 83
    const v3, -0x2860bc75

    .line 84
    .line 85
    .line 86
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 87
    .line 88
    .line 89
    sget-object v3, Lw3/h1;->h:Ll2/u2;

    .line 90
    .line 91
    invoke-virtual {v14, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Lt4/c;

    .line 96
    .line 97
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v9

    .line 101
    check-cast v9, Ljava/lang/Number;

    .line 102
    .line 103
    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    .line 104
    .line 105
    .line 106
    move-result v9

    .line 107
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v10

    .line 111
    check-cast v10, Ljava/lang/Number;

    .line 112
    .line 113
    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v11

    .line 121
    check-cast v11, Ljava/lang/Number;

    .line 122
    .line 123
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 124
    .line 125
    .line 126
    move-result v11

    .line 127
    sub-float/2addr v10, v11

    .line 128
    const/high16 v11, 0x40000000    # 2.0f

    .line 129
    .line 130
    div-float/2addr v10, v11

    .line 131
    add-float/2addr v10, v9

    .line 132
    invoke-interface {v3, v10}, Lt4/c;->o0(F)F

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    sget-object v9, Lh71/u;->a:Ll2/u2;

    .line 137
    .line 138
    invoke-virtual {v14, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v10

    .line 142
    check-cast v10, Lh71/t;

    .line 143
    .line 144
    iget v10, v10, Lh71/t;->a:F

    .line 145
    .line 146
    div-float/2addr v10, v11

    .line 147
    sub-float/2addr v3, v10

    .line 148
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    sget-object v10, Lx2/c;->d:Lx2/j;

    .line 152
    .line 153
    invoke-static {v10, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 154
    .line 155
    .line 156
    move-result-object v10

    .line 157
    iget-wide v11, v14, Ll2/t;->T:J

    .line 158
    .line 159
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 160
    .line 161
    .line 162
    move-result v11

    .line 163
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 164
    .line 165
    .line 166
    move-result-object v12

    .line 167
    invoke-static {v14, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v13

    .line 171
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 172
    .line 173
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 177
    .line 178
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 179
    .line 180
    .line 181
    iget-boolean v7, v14, Ll2/t;->S:Z

    .line 182
    .line 183
    if-eqz v7, :cond_4

    .line 184
    .line 185
    invoke-virtual {v14, v15}, Ll2/t;->l(Lay0/a;)V

    .line 186
    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_4
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 190
    .line 191
    .line 192
    :goto_2
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 193
    .line 194
    invoke-static {v7, v10, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 195
    .line 196
    .line 197
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 198
    .line 199
    invoke-static {v10, v12, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 200
    .line 201
    .line 202
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 203
    .line 204
    iget-boolean v8, v14, Ll2/t;->S:Z

    .line 205
    .line 206
    if-nez v8, :cond_5

    .line 207
    .line 208
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v8

    .line 212
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v0

    .line 220
    if-nez v0, :cond_6

    .line 221
    .line 222
    :cond_5
    invoke-static {v11, v14, v11, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 223
    .line 224
    .line 225
    :cond_6
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 226
    .line 227
    invoke-static {v0, v13, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 228
    .line 229
    .line 230
    sget-object v8, Lk1/j;->a:Lk1/c;

    .line 231
    .line 232
    invoke-virtual {v14, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v8

    .line 236
    check-cast v8, Lh71/t;

    .line 237
    .line 238
    iget v8, v8, Lh71/t;->e:F

    .line 239
    .line 240
    invoke-static {v8}, Lk1/j;->g(F)Lk1/h;

    .line 241
    .line 242
    .line 243
    move-result-object v8

    .line 244
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 245
    .line 246
    const/4 v11, 0x0

    .line 247
    invoke-static {v8, v9, v14, v11}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 248
    .line 249
    .line 250
    move-result-object v8

    .line 251
    move-object v13, v4

    .line 252
    move-object v11, v5

    .line 253
    iget-wide v4, v14, Ll2/t;->T:J

    .line 254
    .line 255
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 256
    .line 257
    .line 258
    move-result v4

    .line 259
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 260
    .line 261
    .line 262
    move-result-object v5

    .line 263
    move-object/from16 v17, v11

    .line 264
    .line 265
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 266
    .line 267
    invoke-static {v14, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 268
    .line 269
    .line 270
    move-result-object v11

    .line 271
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 272
    .line 273
    .line 274
    move-object/from16 v18, v13

    .line 275
    .line 276
    iget-boolean v13, v14, Ll2/t;->S:Z

    .line 277
    .line 278
    if-eqz v13, :cond_7

    .line 279
    .line 280
    invoke-virtual {v14, v15}, Ll2/t;->l(Lay0/a;)V

    .line 281
    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_7
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 285
    .line 286
    .line 287
    :goto_3
    invoke-static {v7, v8, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 288
    .line 289
    .line 290
    invoke-static {v10, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 291
    .line 292
    .line 293
    iget-boolean v5, v14, Ll2/t;->S:Z

    .line 294
    .line 295
    if-nez v5, :cond_8

    .line 296
    .line 297
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v5

    .line 301
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 302
    .line 303
    .line 304
    move-result-object v7

    .line 305
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result v5

    .line 309
    if-nez v5, :cond_9

    .line 310
    .line 311
    :cond_8
    invoke-static {v4, v14, v4, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 312
    .line 313
    .line 314
    :cond_9
    invoke-static {v0, v11, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 315
    .line 316
    .line 317
    new-instance v0, Landroidx/compose/foundation/layout/VerticalAlignElement;

    .line 318
    .line 319
    invoke-direct {v0, v9}, Landroidx/compose/foundation/layout/VerticalAlignElement;-><init>(Lx2/i;)V

    .line 320
    .line 321
    .line 322
    const/4 v11, 0x0

    .line 323
    invoke-static {v3, v11, v14, v0}, Lz61/m;->a(FILl2/o;Lx2/s;)V

    .line 324
    .line 325
    .line 326
    const/high16 v0, 0x3f800000    # 1.0f

    .line 327
    .line 328
    float-to-double v3, v0

    .line 329
    const-wide/16 v7, 0x0

    .line 330
    .line 331
    cmpl-double v3, v3, v7

    .line 332
    .line 333
    if-lez v3, :cond_a

    .line 334
    .line 335
    goto :goto_4

    .line 336
    :cond_a
    const-string v3, "invalid weight; must be greater than zero"

    .line 337
    .line 338
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    :goto_4
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 342
    .line 343
    const v4, 0x7f7fffff    # Float.MAX_VALUE

    .line 344
    .line 345
    .line 346
    cmpl-float v5, v0, v4

    .line 347
    .line 348
    if-lez v5, :cond_b

    .line 349
    .line 350
    move v0, v4

    .line 351
    :cond_b
    const/4 v4, 0x1

    .line 352
    invoke-direct {v3, v0, v4}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 353
    .line 354
    .line 355
    new-instance v0, Landroidx/compose/foundation/layout/VerticalAlignElement;

    .line 356
    .line 357
    invoke-direct {v0, v9}, Landroidx/compose/foundation/layout/VerticalAlignElement;-><init>(Lx2/i;)V

    .line 358
    .line 359
    .line 360
    invoke-interface {v3, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 361
    .line 362
    .line 363
    move-result-object v0

    .line 364
    move v3, v4

    .line 365
    invoke-static {v1, v14}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v4

    .line 369
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 370
    .line 371
    invoke-virtual {v14, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v5

    .line 375
    check-cast v5, Lj91/f;

    .line 376
    .line 377
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 378
    .line 379
    .line 380
    move-result-object v5

    .line 381
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v7

    .line 385
    move-object/from16 v11, v17

    .line 386
    .line 387
    if-ne v7, v11, :cond_c

    .line 388
    .line 389
    new-instance v7, Li91/i4;

    .line 390
    .line 391
    const/4 v8, 0x4

    .line 392
    move-object/from16 v13, v18

    .line 393
    .line 394
    invoke-direct {v7, v13, v6, v8}, Li91/i4;-><init>(Ll2/b1;Ll2/b1;I)V

    .line 395
    .line 396
    .line 397
    invoke-virtual {v14, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 398
    .line 399
    .line 400
    :cond_c
    check-cast v7, Lay0/k;

    .line 401
    .line 402
    const/16 v15, 0xc00

    .line 403
    .line 404
    const/16 v16, 0x1f0

    .line 405
    .line 406
    const/4 v8, 0x0

    .line 407
    const/4 v9, 0x0

    .line 408
    const/4 v10, 0x0

    .line 409
    const-wide/16 v11, 0x0

    .line 410
    .line 411
    const/4 v13, 0x0

    .line 412
    move-object v6, v0

    .line 413
    invoke-static/range {v4 .. v16}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 414
    .line 415
    .line 416
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 420
    .line 421
    .line 422
    goto :goto_5

    .line 423
    :cond_d
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 424
    .line 425
    .line 426
    :goto_5
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    if-eqz v0, :cond_e

    .line 431
    .line 432
    new-instance v3, Ld00/j;

    .line 433
    .line 434
    const/16 v4, 0xc

    .line 435
    .line 436
    move/from16 v5, p0

    .line 437
    .line 438
    invoke-direct {v3, v2, v1, v5, v4}, Ld00/j;-><init>(Lx2/s;Ljava/lang/String;II)V

    .line 439
    .line 440
    .line 441
    iput-object v3, v0, Ll2/u1;->d:Lay0/n;

    .line 442
    .line 443
    :cond_e
    return-void
.end method

.method public static final d(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move/from16 v10, p3

    .line 6
    .line 7
    const-string v1, "modifier"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "viewModel"

    .line 13
    .line 14
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p2

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v1, 0x6c86d9c4

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    const/4 v1, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v1, 0x2

    .line 36
    :goto_0
    or-int/2addr v1, v10

    .line 37
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    const/16 v2, 0x20

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v2, 0x10

    .line 47
    .line 48
    :goto_1
    or-int v11, v1, v2

    .line 49
    .line 50
    and-int/lit8 v1, v11, 0x13

    .line 51
    .line 52
    const/16 v2, 0x12

    .line 53
    .line 54
    const/4 v4, 0x0

    .line 55
    if-eq v1, v2, :cond_2

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    move v1, v4

    .line 60
    :goto_2
    and-int/lit8 v2, v11, 0x1

    .line 61
    .line 62
    invoke-virtual {v9, v2, v1}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_b

    .line 67
    .line 68
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->isClosable()Lyy0/a2;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-static {v1, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->isUnlockActionEnabled()Lyy0/a2;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-static {v2, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 81
    .line 82
    .line 83
    move-result-object v12

    .line 84
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->isUnlockActionInProgress()Lyy0/a2;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-static {v2, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 89
    .line 90
    .line 91
    move-result-object v13

    .line 92
    invoke-interface {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;->getError()Lyy0/a2;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-static {v2, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 105
    .line 106
    invoke-static {v2, v9, v4}, La71/b;->m(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    check-cast v1, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result v14

    .line 119
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 128
    .line 129
    if-nez v1, :cond_3

    .line 130
    .line 131
    if-ne v2, v15, :cond_4

    .line 132
    .line 133
    :cond_3
    new-instance v1, Lz20/j;

    .line 134
    .line 135
    const/4 v7, 0x0

    .line 136
    const/16 v8, 0x11

    .line 137
    .line 138
    const/4 v2, 0x0

    .line 139
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 140
    .line 141
    const-string v5, "closeRPAModule"

    .line 142
    .line 143
    const-string v6, "closeRPAModule()V"

    .line 144
    .line 145
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    move-object v2, v1

    .line 152
    :cond_4
    move-object/from16 v16, v2

    .line 153
    .line 154
    check-cast v16, Lhy0/g;

    .line 155
    .line 156
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    check-cast v1, Ljava/lang/Boolean;

    .line 161
    .line 162
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 163
    .line 164
    .line 165
    move-result v12

    .line 166
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    check-cast v1, Ljava/lang/Boolean;

    .line 171
    .line 172
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 173
    .line 174
    .line 175
    move-result v13

    .line 176
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    if-nez v1, :cond_5

    .line 185
    .line 186
    if-ne v2, v15, :cond_6

    .line 187
    .line 188
    :cond_5
    new-instance v1, Lz20/j;

    .line 189
    .line 190
    const/4 v7, 0x0

    .line 191
    const/16 v8, 0x12

    .line 192
    .line 193
    const/4 v2, 0x0

    .line 194
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 195
    .line 196
    const-string v5, "startUnlock"

    .line 197
    .line 198
    const-string v6, "startUnlock()V"

    .line 199
    .line 200
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    move-object v2, v1

    .line 207
    :cond_6
    move-object/from16 v17, v2

    .line 208
    .line 209
    check-cast v17, Lhy0/g;

    .line 210
    .line 211
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v1

    .line 215
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    if-nez v1, :cond_7

    .line 220
    .line 221
    if-ne v2, v15, :cond_8

    .line 222
    .line 223
    :cond_7
    new-instance v1, Lz20/j;

    .line 224
    .line 225
    const/4 v7, 0x0

    .line 226
    const/16 v8, 0x13

    .line 227
    .line 228
    const/4 v2, 0x0

    .line 229
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 230
    .line 231
    const-string v5, "finishUnlock"

    .line 232
    .line 233
    const-string v6, "finishUnlock()V"

    .line 234
    .line 235
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    move-object v2, v1

    .line 242
    :cond_8
    move-object/from16 v18, v2

    .line 243
    .line 244
    check-cast v18, Lhy0/g;

    .line 245
    .line 246
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result v1

    .line 250
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v2

    .line 254
    if-nez v1, :cond_a

    .line 255
    .line 256
    if-ne v2, v15, :cond_9

    .line 257
    .line 258
    goto :goto_3

    .line 259
    :cond_9
    move-object v15, v3

    .line 260
    goto :goto_4

    .line 261
    :cond_a
    :goto_3
    new-instance v1, Lz20/j;

    .line 262
    .line 263
    const/4 v7, 0x0

    .line 264
    const/16 v8, 0x14

    .line 265
    .line 266
    const/4 v2, 0x0

    .line 267
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 268
    .line 269
    const-string v5, "cancelUnlock"

    .line 270
    .line 271
    const-string v6, "cancelUnlock()V"

    .line 272
    .line 273
    invoke-direct/range {v1 .. v8}, Lz20/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 274
    .line 275
    .line 276
    move-object v15, v3

    .line 277
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    move-object v2, v1

    .line 281
    :goto_4
    check-cast v2, Lhy0/g;

    .line 282
    .line 283
    move-object/from16 v4, v17

    .line 284
    .line 285
    check-cast v4, Lay0/a;

    .line 286
    .line 287
    move-object/from16 v5, v18

    .line 288
    .line 289
    check-cast v5, Lay0/a;

    .line 290
    .line 291
    move-object v6, v2

    .line 292
    check-cast v6, Lay0/a;

    .line 293
    .line 294
    move-object/from16 v7, v16

    .line 295
    .line 296
    check-cast v7, Lay0/a;

    .line 297
    .line 298
    and-int/lit8 v1, v11, 0xe

    .line 299
    .line 300
    move-object v8, v9

    .line 301
    move v2, v12

    .line 302
    move v3, v13

    .line 303
    move v9, v1

    .line 304
    move v1, v14

    .line 305
    invoke-static/range {v0 .. v9}, Lz61/m;->e(Lx2/s;ZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 306
    .line 307
    .line 308
    goto :goto_5

    .line 309
    :cond_b
    move-object v15, v3

    .line 310
    move-object v8, v9

    .line 311
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 312
    .line 313
    .line 314
    :goto_5
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 315
    .line 316
    .line 317
    move-result-object v1

    .line 318
    if-eqz v1, :cond_c

    .line 319
    .line 320
    new-instance v2, Ly61/b;

    .line 321
    .line 322
    invoke-direct {v2, v0, v15, v10}, Ly61/b;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;I)V

    .line 323
    .line 324
    .line 325
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 326
    .line 327
    :cond_c
    return-void
.end method

.method public static final e(Lx2/s;ZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 15

    .line 1
    move-object/from16 v11, p8

    .line 2
    .line 3
    check-cast v11, Ll2/t;

    .line 4
    .line 5
    const v0, 0x71d620a6

    .line 6
    .line 7
    .line 8
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v11, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x2

    .line 20
    :goto_0
    or-int v0, p9, v0

    .line 21
    .line 22
    move/from16 v2, p1

    .line 23
    .line 24
    invoke-virtual {v11, v2}, Ll2/t;->h(Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    const/16 v1, 0x20

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/16 v1, 0x10

    .line 34
    .line 35
    :goto_1
    or-int/2addr v0, v1

    .line 36
    move/from16 v4, p2

    .line 37
    .line 38
    invoke-virtual {v11, v4}, Ll2/t;->h(Z)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    const/16 v1, 0x100

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v1, 0x80

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v1

    .line 50
    move/from16 v5, p3

    .line 51
    .line 52
    invoke-virtual {v11, v5}, Ll2/t;->h(Z)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    const/16 v1, 0x800

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    const/16 v1, 0x400

    .line 62
    .line 63
    :goto_3
    or-int/2addr v0, v1

    .line 64
    move-object/from16 v6, p4

    .line 65
    .line 66
    invoke-virtual {v11, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_4

    .line 71
    .line 72
    const/16 v1, 0x4000

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_4
    const/16 v1, 0x2000

    .line 76
    .line 77
    :goto_4
    or-int/2addr v0, v1

    .line 78
    move-object/from16 v7, p5

    .line 79
    .line 80
    invoke-virtual {v11, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-eqz v1, :cond_5

    .line 85
    .line 86
    const/high16 v1, 0x20000

    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_5
    const/high16 v1, 0x10000

    .line 90
    .line 91
    :goto_5
    or-int/2addr v0, v1

    .line 92
    move-object/from16 v8, p6

    .line 93
    .line 94
    invoke-virtual {v11, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-eqz v1, :cond_6

    .line 99
    .line 100
    const/high16 v1, 0x100000

    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_6
    const/high16 v1, 0x80000

    .line 104
    .line 105
    :goto_6
    or-int/2addr v0, v1

    .line 106
    move-object/from16 v10, p7

    .line 107
    .line 108
    invoke-virtual {v11, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_7

    .line 113
    .line 114
    const/high16 v1, 0x800000

    .line 115
    .line 116
    goto :goto_7

    .line 117
    :cond_7
    const/high16 v1, 0x400000

    .line 118
    .line 119
    :goto_7
    or-int/2addr v0, v1

    .line 120
    const v1, 0x492493

    .line 121
    .line 122
    .line 123
    and-int/2addr v1, v0

    .line 124
    const v3, 0x492492

    .line 125
    .line 126
    .line 127
    if-eq v1, v3, :cond_8

    .line 128
    .line 129
    const/4 v1, 0x1

    .line 130
    goto :goto_8

    .line 131
    :cond_8
    const/4 v1, 0x0

    .line 132
    :goto_8
    and-int/lit8 v3, v0, 0x1

    .line 133
    .line 134
    invoke-virtual {v11, v3, v1}, Ll2/t;->O(IZ)Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    if-eqz v1, :cond_9

    .line 139
    .line 140
    const-string v1, "touch_diagnosis_top_bar_title"

    .line 141
    .line 142
    invoke-static {v1, v11}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    sget-object v3, Lh71/a;->d:Lh71/a;

    .line 147
    .line 148
    new-instance v3, Lz61/l;

    .line 149
    .line 150
    const/4 v9, 0x0

    .line 151
    invoke-direct/range {v3 .. v9}, Lz61/l;-><init>(ZZLay0/a;Lay0/a;Lay0/a;I)V

    .line 152
    .line 153
    .line 154
    const v4, 0x1de1f3b0

    .line 155
    .line 156
    .line 157
    invoke-static {v4, v11, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 158
    .line 159
    .line 160
    move-result-object v6

    .line 161
    and-int/lit8 v3, v0, 0xe

    .line 162
    .line 163
    const v4, 0x6030180

    .line 164
    .line 165
    .line 166
    or-int/2addr v3, v4

    .line 167
    shl-int/lit8 v4, v0, 0x6

    .line 168
    .line 169
    and-int/lit16 v4, v4, 0x1c00

    .line 170
    .line 171
    or-int v12, v3, v4

    .line 172
    .line 173
    shr-int/lit8 v0, v0, 0xf

    .line 174
    .line 175
    and-int/lit16 v13, v0, 0x380

    .line 176
    .line 177
    const/16 v14, 0xed0

    .line 178
    .line 179
    const/4 v3, 0x0

    .line 180
    const/4 v4, 0x1

    .line 181
    const/4 v5, 0x0

    .line 182
    const/4 v7, 0x0

    .line 183
    const/4 v8, 0x0

    .line 184
    const/4 v9, 0x0

    .line 185
    move-object v0, p0

    .line 186
    invoke-static/range {v0 .. v14}, Lc71/a;->b(Lx2/s;Ljava/lang/String;ZLjava/lang/String;ZZLay0/o;Lay0/o;Lk1/i;Lx2/d;Lay0/a;Ll2/o;III)V

    .line 187
    .line 188
    .line 189
    goto :goto_9

    .line 190
    :cond_9
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 191
    .line 192
    .line 193
    :goto_9
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    if-eqz v0, :cond_a

    .line 198
    .line 199
    new-instance v1, Lh2/s2;

    .line 200
    .line 201
    move-object v2, p0

    .line 202
    move/from16 v3, p1

    .line 203
    .line 204
    move/from16 v4, p2

    .line 205
    .line 206
    move/from16 v5, p3

    .line 207
    .line 208
    move-object/from16 v6, p4

    .line 209
    .line 210
    move-object/from16 v7, p5

    .line 211
    .line 212
    move-object/from16 v8, p6

    .line 213
    .line 214
    move-object/from16 v9, p7

    .line 215
    .line 216
    move/from16 v10, p9

    .line 217
    .line 218
    invoke-direct/range {v1 .. v10}, Lh2/s2;-><init>(Lx2/s;ZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;I)V

    .line 219
    .line 220
    .line 221
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 222
    .line 223
    :cond_a
    return-void
.end method
