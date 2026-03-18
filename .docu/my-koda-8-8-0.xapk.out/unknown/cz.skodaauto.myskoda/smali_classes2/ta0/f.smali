.class public abstract Lta0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0xf

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lta0/f;->a:F

    .line 5
    .line 6
    const/16 v0, 0x10

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Lta0/f;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lra0/c;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p1, 0x43bd6a56

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x6

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-nez p1, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    invoke-virtual {v5, p1}, Ll2/t;->e(I)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    const/4 p1, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move p1, v0

    .line 28
    :goto_0
    or-int/2addr p1, p2

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move p1, p2

    .line 31
    :goto_1
    and-int/lit8 v1, p1, 0x3

    .line 32
    .line 33
    const/4 v8, 0x1

    .line 34
    const/4 v9, 0x0

    .line 35
    if-eq v1, v0, :cond_2

    .line 36
    .line 37
    move v0, v8

    .line 38
    goto :goto_2

    .line 39
    :cond_2
    move v0, v9

    .line 40
    :goto_2
    and-int/2addr p1, v8

    .line 41
    invoke-virtual {v5, p1, v0}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eqz p1, :cond_8

    .line 46
    .line 47
    sget-object p1, Lx2/c;->n:Lx2/i;

    .line 48
    .line 49
    sget-object v0, Lk1/j;->a:Lk1/c;

    .line 50
    .line 51
    const/16 v1, 0x30

    .line 52
    .line 53
    invoke-static {v0, p1, v5, v1}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iget-wide v0, v5, Ll2/t;->T:J

    .line 58
    .line 59
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 68
    .line 69
    invoke-static {v5, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 79
    .line 80
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 81
    .line 82
    .line 83
    iget-boolean v4, v5, Ll2/t;->S:Z

    .line 84
    .line 85
    if-eqz v4, :cond_3

    .line 86
    .line 87
    invoke-virtual {v5, v3}, Ll2/t;->l(Lay0/a;)V

    .line 88
    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_3
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 92
    .line 93
    .line 94
    :goto_3
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 95
    .line 96
    invoke-static {v3, p1, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object p1, Lv3/j;->f:Lv3/h;

    .line 100
    .line 101
    invoke-static {p1, v1, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 102
    .line 103
    .line 104
    sget-object p1, Lv3/j;->j:Lv3/h;

    .line 105
    .line 106
    iget-boolean v1, v5, Ll2/t;->S:Z

    .line 107
    .line 108
    if-nez v1, :cond_4

    .line 109
    .line 110
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-nez v1, :cond_5

    .line 123
    .line 124
    :cond_4
    invoke-static {v0, v5, v0, p1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 125
    .line 126
    .line 127
    :cond_5
    sget-object p1, Lv3/j;->d:Lv3/h;

    .line 128
    .line 129
    invoke-static {p1, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    invoke-static {p0, v5}, Lkp/t9;->c(Lra0/c;Ll2/o;)Lta0/d;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    instance-of v0, p1, Lta0/b;

    .line 137
    .line 138
    if-eqz v0, :cond_6

    .line 139
    .line 140
    const v0, 0x3f5ad146

    .line 141
    .line 142
    .line 143
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    check-cast p1, Lta0/b;

    .line 147
    .line 148
    iget v0, p1, Lta0/b;->a:I

    .line 149
    .line 150
    invoke-static {v0, v9, v5}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    const/16 v1, 0x10

    .line 155
    .line 156
    int-to-float v1, v1

    .line 157
    invoke-static {v10, v1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-static {p0}, Lkp/t9;->b(Lra0/c;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    const-string v3, "icon_"

    .line 166
    .line 167
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    iget-wide v3, p1, Lta0/b;->b:J

    .line 176
    .line 177
    const/16 v6, 0x30

    .line 178
    .line 179
    const/4 v7, 0x0

    .line 180
    const/4 v1, 0x0

    .line 181
    invoke-static/range {v0 .. v7}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    goto :goto_4

    .line 188
    :cond_6
    instance-of v0, p1, Lta0/c;

    .line 189
    .line 190
    if-eqz v0, :cond_7

    .line 191
    .line 192
    const v0, 0x3f615f07

    .line 193
    .line 194
    .line 195
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 196
    .line 197
    .line 198
    check-cast p1, Lta0/c;

    .line 199
    .line 200
    iget-object p1, p1, Lta0/c;->a:Li91/k1;

    .line 201
    .line 202
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    new-instance v1, Ljava/lang/StringBuilder;

    .line 207
    .line 208
    const-string v2, "indicator_"

    .line 209
    .line 210
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    invoke-static {v10, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-static {p1, v0, v5, v9, v9}, Li91/j0;->E(Li91/k1;Lx2/s;Ll2/o;II)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 228
    .line 229
    .line 230
    :goto_4
    sget-object p1, Lj91/a;->a:Ll2/u2;

    .line 231
    .line 232
    invoke-virtual {v5, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    check-cast v0, Lj91/c;

    .line 237
    .line 238
    iget v0, v0, Lj91/c;->b:F

    .line 239
    .line 240
    invoke-static {v10, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    invoke-static {v5, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 245
    .line 246
    .line 247
    invoke-static {p0}, Lkp/t9;->a(Lra0/c;)I

    .line 248
    .line 249
    .line 250
    move-result v0

    .line 251
    invoke-static {v5, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    invoke-static {p0}, Lkp/t9;->b(Lra0/c;)Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    invoke-static {v0, v1, v5, v9}, Lta0/f;->b(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v5, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object p1

    .line 266
    check-cast p1, Lj91/c;

    .line 267
    .line 268
    iget p1, p1, Lj91/c;->b:F

    .line 269
    .line 270
    invoke-static {v10, p1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 271
    .line 272
    .line 273
    move-result-object p1

    .line 274
    invoke-static {v5, p1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 275
    .line 276
    .line 277
    sget p1, Lta0/f;->a:F

    .line 278
    .line 279
    invoke-static {v10, p1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    invoke-static {v0, p1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 284
    .line 285
    .line 286
    move-result-object v2

    .line 287
    sget-object p1, Lj91/h;->a:Ll2/u2;

    .line 288
    .line 289
    invoke-virtual {v5, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object p1

    .line 293
    check-cast p1, Lj91/e;

    .line 294
    .line 295
    invoke-virtual {p1}, Lj91/e;->q()J

    .line 296
    .line 297
    .line 298
    move-result-wide v3

    .line 299
    const p1, 0x7f080349

    .line 300
    .line 301
    .line 302
    invoke-static {p1, v9, v5}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    const/16 v6, 0x1b0

    .line 307
    .line 308
    const/4 v7, 0x0

    .line 309
    const/4 v1, 0x0

    .line 310
    invoke-static/range {v0 .. v7}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 311
    .line 312
    .line 313
    invoke-virtual {v5, v8}, Ll2/t;->q(Z)V

    .line 314
    .line 315
    .line 316
    goto :goto_5

    .line 317
    :cond_7
    const p0, 0x6523ee73

    .line 318
    .line 319
    .line 320
    invoke-static {p0, v5, v9}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 321
    .line 322
    .line 323
    move-result-object p0

    .line 324
    throw p0

    .line 325
    :cond_8
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 326
    .line 327
    .line 328
    :goto_5
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 329
    .line 330
    .line 331
    move-result-object p1

    .line 332
    if-eqz p1, :cond_9

    .line 333
    .line 334
    new-instance v0, Ld90/h;

    .line 335
    .line 336
    const/16 v1, 0xf

    .line 337
    .line 338
    invoke-direct {v0, p0, p2, v1}, Ld90/h;-><init>(Ljava/lang/Object;II)V

    .line 339
    .line 340
    .line 341
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 342
    .line 343
    :cond_9
    return-void
.end method

.method public static final b(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    check-cast v2, Ll2/t;

    .line 8
    .line 9
    const v3, 0x453a9684

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    const/4 v3, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v3, 0x2

    .line 24
    :goto_0
    or-int v3, p3, v3

    .line 25
    .line 26
    invoke-virtual {v2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    const/16 v4, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v4, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v3, v4

    .line 38
    and-int/lit8 v4, v3, 0x13

    .line 39
    .line 40
    const/16 v5, 0x12

    .line 41
    .line 42
    if-eq v4, v5, :cond_2

    .line 43
    .line 44
    const/4 v4, 0x1

    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/4 v4, 0x0

    .line 47
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 48
    .line 49
    invoke-virtual {v2, v5, v4}, Ll2/t;->O(IZ)Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-eqz v4, :cond_3

    .line 54
    .line 55
    const-string v4, "vehicle_connection_statuses_title_"

    .line 56
    .line 57
    invoke-virtual {v4, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 62
    .line 63
    invoke-static {v5, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 68
    .line 69
    invoke-virtual {v2, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Lj91/f;

    .line 74
    .line 75
    invoke-virtual {v5}, Lj91/f;->e()Lg4/p0;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 80
    .line 81
    invoke-virtual {v2, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    check-cast v6, Lj91/e;

    .line 86
    .line 87
    invoke-virtual {v6}, Lj91/e;->s()J

    .line 88
    .line 89
    .line 90
    move-result-wide v6

    .line 91
    and-int/lit8 v19, v3, 0xe

    .line 92
    .line 93
    const/16 v20, 0x0

    .line 94
    .line 95
    const v21, 0xfff0

    .line 96
    .line 97
    .line 98
    move-object/from16 v18, v2

    .line 99
    .line 100
    move-object v2, v4

    .line 101
    move-object v1, v5

    .line 102
    move-wide v3, v6

    .line 103
    const-wide/16 v5, 0x0

    .line 104
    .line 105
    const/4 v7, 0x0

    .line 106
    const-wide/16 v8, 0x0

    .line 107
    .line 108
    const/4 v10, 0x0

    .line 109
    const/4 v11, 0x0

    .line 110
    const-wide/16 v12, 0x0

    .line 111
    .line 112
    const/4 v14, 0x0

    .line 113
    const/4 v15, 0x0

    .line 114
    const/16 v16, 0x0

    .line 115
    .line 116
    const/16 v17, 0x0

    .line 117
    .line 118
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 119
    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_3
    move-object/from16 v18, v2

    .line 123
    .line 124
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 125
    .line 126
    .line 127
    :goto_3
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    if-eqz v1, :cond_4

    .line 132
    .line 133
    new-instance v2, Lbk/c;

    .line 134
    .line 135
    const/16 v3, 0xc

    .line 136
    .line 137
    move-object/from16 v4, p1

    .line 138
    .line 139
    move/from16 v5, p3

    .line 140
    .line 141
    invoke-direct {v2, v0, v4, v5, v3}, Lbk/c;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 142
    .line 143
    .line 144
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 145
    .line 146
    :cond_4
    return-void
.end method

.method public static final c(Lra0/c;Ljava/time/OffsetDateTime;Lx2/s;ZLay0/a;Ll2/o;II)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v3, p3

    .line 4
    .line 5
    const-string v0, "vehicleState"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v0, p5

    .line 11
    .line 12
    check-cast v0, Ll2/t;

    .line 13
    .line 14
    const v2, 0x4051f991

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-virtual {v0, v2}, Ll2/t;->e(I)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    const/4 v4, 0x2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    const/4 v2, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v2, v4

    .line 34
    :goto_0
    or-int v2, p6, v2

    .line 35
    .line 36
    move-object/from16 v8, p1

    .line 37
    .line 38
    invoke-virtual {v0, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    if-eqz v5, :cond_1

    .line 43
    .line 44
    const/16 v5, 0x20

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/16 v5, 0x10

    .line 48
    .line 49
    :goto_1
    or-int/2addr v2, v5

    .line 50
    and-int/lit8 v5, p7, 0x4

    .line 51
    .line 52
    if-eqz v5, :cond_2

    .line 53
    .line 54
    or-int/lit16 v2, v2, 0x180

    .line 55
    .line 56
    move-object/from16 v6, p2

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_2
    move-object/from16 v6, p2

    .line 60
    .line 61
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v7

    .line 65
    if-eqz v7, :cond_3

    .line 66
    .line 67
    const/16 v7, 0x100

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    const/16 v7, 0x80

    .line 71
    .line 72
    :goto_2
    or-int/2addr v2, v7

    .line 73
    :goto_3
    invoke-virtual {v0, v3}, Ll2/t;->h(Z)Z

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    if-eqz v7, :cond_4

    .line 78
    .line 79
    const/16 v7, 0x800

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_4
    const/16 v7, 0x400

    .line 83
    .line 84
    :goto_4
    or-int/2addr v2, v7

    .line 85
    move-object/from16 v7, p4

    .line 86
    .line 87
    invoke-virtual {v0, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v9

    .line 91
    if-eqz v9, :cond_5

    .line 92
    .line 93
    const/16 v9, 0x4000

    .line 94
    .line 95
    goto :goto_5

    .line 96
    :cond_5
    const/16 v9, 0x2000

    .line 97
    .line 98
    :goto_5
    or-int/2addr v9, v2

    .line 99
    and-int/lit16 v2, v9, 0x2493

    .line 100
    .line 101
    const/16 v10, 0x2492

    .line 102
    .line 103
    const/4 v11, 0x1

    .line 104
    const/4 v12, 0x0

    .line 105
    if-eq v2, v10, :cond_6

    .line 106
    .line 107
    move v2, v11

    .line 108
    goto :goto_6

    .line 109
    :cond_6
    move v2, v12

    .line 110
    :goto_6
    and-int/lit8 v10, v9, 0x1

    .line 111
    .line 112
    invoke-virtual {v0, v10, v2}, Ll2/t;->O(IZ)Z

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    if-eqz v2, :cond_e

    .line 117
    .line 118
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 119
    .line 120
    if-eqz v5, :cond_7

    .line 121
    .line 122
    move-object v13, v10

    .line 123
    goto :goto_7

    .line 124
    :cond_7
    move-object v13, v6

    .line 125
    :goto_7
    const v2, 0x73b9f895

    .line 126
    .line 127
    .line 128
    invoke-virtual {v0, v2}, Ll2/t;->Y(I)V

    .line 129
    .line 130
    .line 131
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 132
    .line 133
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    check-cast v2, Lt4/c;

    .line 138
    .line 139
    sget-object v14, Lj91/a;->a:Ll2/u2;

    .line 140
    .line 141
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    check-cast v5, Lj91/c;

    .line 146
    .line 147
    iget v5, v5, Lj91/c;->b:F

    .line 148
    .line 149
    invoke-interface {v2, v5}, Lt4/c;->w0(F)F

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    neg-float v2, v2

    .line 154
    invoke-virtual {v0, v12}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    const/high16 v5, 0x3f800000    # 1.0f

    .line 158
    .line 159
    invoke-static {v13, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 160
    .line 161
    .line 162
    move-result-object v5

    .line 163
    const-string v6, "vehicle_connection_statuses_container"

    .line 164
    .line 165
    invoke-static {v5, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v6

    .line 173
    check-cast v6, Lj91/c;

    .line 174
    .line 175
    iget v6, v6, Lj91/c;->j:F

    .line 176
    .line 177
    const/4 v15, 0x0

    .line 178
    invoke-static {v5, v6, v15, v4}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    sget v5, Lta0/f;->b:F

    .line 183
    .line 184
    invoke-static {v4, v15, v5, v11}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object v4

    .line 188
    sget-object v5, Lk1/r0;->d:Lk1/r0;

    .line 189
    .line 190
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    invoke-virtual {v0, v2}, Ll2/t;->d(F)Z

    .line 195
    .line 196
    .line 197
    move-result v5

    .line 198
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v6

    .line 202
    if-nez v5, :cond_8

    .line 203
    .line 204
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 205
    .line 206
    if-ne v6, v5, :cond_9

    .line 207
    .line 208
    :cond_8
    new-instance v6, Lta0/e;

    .line 209
    .line 210
    invoke-direct {v6, v2}, Lta0/e;-><init>(F)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v0, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    :cond_9
    check-cast v6, Lay0/k;

    .line 217
    .line 218
    invoke-static {v4, v6}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 219
    .line 220
    .line 221
    move-result-object v2

    .line 222
    const/4 v5, 0x0

    .line 223
    const/16 v7, 0xe

    .line 224
    .line 225
    const/4 v4, 0x0

    .line 226
    move-object/from16 v6, p4

    .line 227
    .line 228
    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 233
    .line 234
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 235
    .line 236
    invoke-static {v3, v4, v0, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    iget-wide v4, v0, Ll2/t;->T:J

    .line 241
    .line 242
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 243
    .line 244
    .line 245
    move-result v4

    .line 246
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 247
    .line 248
    .line 249
    move-result-object v5

    .line 250
    invoke-static {v0, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 251
    .line 252
    .line 253
    move-result-object v2

    .line 254
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 255
    .line 256
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 257
    .line 258
    .line 259
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 260
    .line 261
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 262
    .line 263
    .line 264
    iget-boolean v7, v0, Ll2/t;->S:Z

    .line 265
    .line 266
    if-eqz v7, :cond_a

    .line 267
    .line 268
    invoke-virtual {v0, v6}, Ll2/t;->l(Lay0/a;)V

    .line 269
    .line 270
    .line 271
    goto :goto_8

    .line 272
    :cond_a
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 273
    .line 274
    .line 275
    :goto_8
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 276
    .line 277
    invoke-static {v6, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 278
    .line 279
    .line 280
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 281
    .line 282
    invoke-static {v3, v5, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 283
    .line 284
    .line 285
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 286
    .line 287
    iget-boolean v5, v0, Ll2/t;->S:Z

    .line 288
    .line 289
    if-nez v5, :cond_b

    .line 290
    .line 291
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v5

    .line 295
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 296
    .line 297
    .line 298
    move-result-object v6

    .line 299
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 300
    .line 301
    .line 302
    move-result v5

    .line 303
    if-nez v5, :cond_c

    .line 304
    .line 305
    :cond_b
    invoke-static {v4, v0, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 306
    .line 307
    .line 308
    :cond_c
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 309
    .line 310
    invoke-static {v3, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 311
    .line 312
    .line 313
    if-eqz p3, :cond_d

    .line 314
    .line 315
    const v2, -0x2355cfc8

    .line 316
    .line 317
    .line 318
    invoke-virtual {v0, v2}, Ll2/t;->Y(I)V

    .line 319
    .line 320
    .line 321
    shr-int/lit8 v2, v9, 0x3

    .line 322
    .line 323
    and-int/lit8 v6, v2, 0xe

    .line 324
    .line 325
    const/4 v7, 0x6

    .line 326
    const/4 v3, 0x0

    .line 327
    const/4 v4, 0x0

    .line 328
    move-object v5, v0

    .line 329
    move-object v2, v8

    .line 330
    invoke-static/range {v2 .. v7}, Llp/bc;->a(Ljava/time/OffsetDateTime;Lx2/s;ZLl2/o;II)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v5, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    check-cast v0, Lj91/c;

    .line 338
    .line 339
    iget v0, v0, Lj91/c;->b:F

    .line 340
    .line 341
    invoke-static {v10, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    invoke-static {v5, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 346
    .line 347
    .line 348
    and-int/lit8 v0, v9, 0xe

    .line 349
    .line 350
    invoke-static {v1, v5, v0}, Lta0/f;->a(Lra0/c;Ll2/o;I)V

    .line 351
    .line 352
    .line 353
    :goto_9
    invoke-virtual {v5, v12}, Ll2/t;->q(Z)V

    .line 354
    .line 355
    .line 356
    goto :goto_a

    .line 357
    :cond_d
    move-object v5, v0

    .line 358
    const v0, -0x237b1845

    .line 359
    .line 360
    .line 361
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 362
    .line 363
    .line 364
    goto :goto_9

    .line 365
    :goto_a
    invoke-virtual {v5, v11}, Ll2/t;->q(Z)V

    .line 366
    .line 367
    .line 368
    move-object v3, v13

    .line 369
    goto :goto_b

    .line 370
    :cond_e
    move-object v5, v0

    .line 371
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 372
    .line 373
    .line 374
    move-object v3, v6

    .line 375
    :goto_b
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 376
    .line 377
    .line 378
    move-result-object v8

    .line 379
    if-eqz v8, :cond_f

    .line 380
    .line 381
    new-instance v0, Ld80/k;

    .line 382
    .line 383
    move-object/from16 v2, p1

    .line 384
    .line 385
    move/from16 v4, p3

    .line 386
    .line 387
    move-object/from16 v5, p4

    .line 388
    .line 389
    move/from16 v6, p6

    .line 390
    .line 391
    move/from16 v7, p7

    .line 392
    .line 393
    invoke-direct/range {v0 .. v7}, Ld80/k;-><init>(Lra0/c;Ljava/time/OffsetDateTime;Lx2/s;ZLay0/a;II)V

    .line 394
    .line 395
    .line 396
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 397
    .line 398
    :cond_f
    return-void
.end method
