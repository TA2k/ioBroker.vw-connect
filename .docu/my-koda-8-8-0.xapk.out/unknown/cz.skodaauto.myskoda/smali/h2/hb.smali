.class public final Lh2/hb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/hb;

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh2/hb;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/hb;->a:Lh2/hb;

    .line 7
    .line 8
    const/16 v0, 0x38

    .line 9
    .line 10
    int-to-float v0, v0

    .line 11
    sput v0, Lh2/hb;->b:F

    .line 12
    .line 13
    const/16 v0, 0x118

    .line 14
    .line 15
    int-to-float v0, v0

    .line 16
    sput v0, Lh2/hb;->c:F

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    int-to-float v0, v0

    .line 20
    sput v0, Lh2/hb;->d:F

    .line 21
    .line 22
    const/4 v0, 0x2

    .line 23
    int-to-float v0, v0

    .line 24
    sput v0, Lh2/hb;->e:F

    .line 25
    .line 26
    return-void
.end method

.method public static c(JJJJJJJJJJJJJJJJJJJJJLl2/t;)Lh2/eb;
    .locals 87

    move-object/from16 v0, p42

    .line 1
    sget-wide v20, Le3/s;->i:J

    .line 2
    sget-object v1, Lh2/g1;->a:Ll2/u2;

    .line 3
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v1

    .line 4
    check-cast v1, Lh2/f1;

    .line 5
    sget-object v2, Le2/e1;->a:Ll2/e0;

    .line 6
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Le2/d1;

    .line 7
    invoke-static {v1, v0}, Lh2/hb;->f(Lh2/f1;Le2/d1;)Lh2/eb;

    move-result-object v1

    const/16 v22, 0x0

    move-wide/from16 v29, v20

    move-wide/from16 v37, v20

    move-wide/from16 v45, v20

    move-wide/from16 v47, v20

    move-wide/from16 v49, v20

    move-wide/from16 v51, v20

    move-wide/from16 v53, v20

    move-wide/from16 v61, v20

    move-wide/from16 v63, v20

    move-wide/from16 v65, v20

    move-wide/from16 v67, v20

    move-wide/from16 v69, v20

    move-wide/from16 v71, v20

    move-wide/from16 v73, v20

    move-wide/from16 v75, v20

    move-wide/from16 v77, v20

    move-wide/from16 v79, v20

    move-wide/from16 v81, v20

    move-wide/from16 v83, v20

    move-wide/from16 v85, v20

    move-wide/from16 v2, p0

    move-wide/from16 v4, p2

    move-wide/from16 v6, p4

    move-wide/from16 v8, p6

    move-wide/from16 v10, p8

    move-wide/from16 v12, p10

    move-wide/from16 v14, p12

    move-wide/from16 v16, p14

    move-wide/from16 v18, p16

    move-wide/from16 v23, p18

    move-wide/from16 v25, p20

    move-wide/from16 v27, p22

    move-wide/from16 v31, p24

    move-wide/from16 v33, p26

    move-wide/from16 v35, p28

    move-wide/from16 v39, p30

    move-wide/from16 v41, p32

    move-wide/from16 v43, p34

    move-wide/from16 v55, p36

    move-wide/from16 v57, p38

    move-wide/from16 v59, p40

    .line 8
    invoke-virtual/range {v1 .. v86}, Lh2/eb;->a(JJJJJJJJJJLe2/d1;JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ)Lh2/eb;

    move-result-object v0

    return-object v0
.end method

.method public static d(Lh2/hb;)Lk1/a1;
    .locals 2

    .line 1
    sget p0, Li2/h1;->a:F

    .line 2
    .line 3
    sget v0, Lh2/mb;->a:F

    .line 4
    .line 5
    new-instance v1, Lk1/a1;

    .line 6
    .line 7
    invoke-direct {v1, p0, v0, p0, v0}, Lk1/a1;-><init>(FFFF)V

    .line 8
    .line 9
    .line 10
    return-object v1
.end method

.method public static e(Lh2/hb;)Lk1/a1;
    .locals 1

    .line 1
    sget p0, Li2/h1;->a:F

    .line 2
    .line 3
    new-instance v0, Lk1/a1;

    .line 4
    .line 5
    invoke-direct {v0, p0, p0, p0, p0}, Lk1/a1;-><init>(FFFF)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public static f(Lh2/f1;Le2/d1;)Lh2/eb;
    .locals 89

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lh2/f1;->g0:Lh2/eb;

    .line 4
    .line 5
    if-eqz v1, :cond_1

    .line 6
    .line 7
    iget-object v2, v1, Lh2/eb;->k:Le2/d1;

    .line 8
    .line 9
    move-object/from16 v3, p1

    .line 10
    .line 11
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    return-object v1

    .line 18
    :cond_0
    const-wide/16 v53, 0x0

    .line 19
    .line 20
    const/16 v55, -0x401

    .line 21
    .line 22
    const-wide/16 v2, 0x0

    .line 23
    .line 24
    const-wide/16 v4, 0x0

    .line 25
    .line 26
    const-wide/16 v6, 0x0

    .line 27
    .line 28
    const-wide/16 v8, 0x0

    .line 29
    .line 30
    const-wide/16 v10, 0x0

    .line 31
    .line 32
    const-wide/16 v12, 0x0

    .line 33
    .line 34
    const-wide/16 v14, 0x0

    .line 35
    .line 36
    const-wide/16 v16, 0x0

    .line 37
    .line 38
    const-wide/16 v18, 0x0

    .line 39
    .line 40
    const-wide/16 v21, 0x0

    .line 41
    .line 42
    const-wide/16 v23, 0x0

    .line 43
    .line 44
    const-wide/16 v25, 0x0

    .line 45
    .line 46
    const-wide/16 v27, 0x0

    .line 47
    .line 48
    const-wide/16 v29, 0x0

    .line 49
    .line 50
    const-wide/16 v31, 0x0

    .line 51
    .line 52
    const-wide/16 v33, 0x0

    .line 53
    .line 54
    const-wide/16 v35, 0x0

    .line 55
    .line 56
    const-wide/16 v37, 0x0

    .line 57
    .line 58
    const-wide/16 v39, 0x0

    .line 59
    .line 60
    const-wide/16 v41, 0x0

    .line 61
    .line 62
    const-wide/16 v43, 0x0

    .line 63
    .line 64
    const-wide/16 v45, 0x0

    .line 65
    .line 66
    const-wide/16 v47, 0x0

    .line 67
    .line 68
    const-wide/16 v49, 0x0

    .line 69
    .line 70
    const-wide/16 v51, 0x0

    .line 71
    .line 72
    move-object/from16 v20, p1

    .line 73
    .line 74
    invoke-static/range {v1 .. v55}, Lh2/eb;->b(Lh2/eb;JJJJJJJJJLe2/d1;JJJJJJJJJJJJJJJJJI)Lh2/eb;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    iput-object v1, v0, Lh2/f1;->g0:Lh2/eb;

    .line 79
    .line 80
    return-object v1

    .line 81
    :cond_1
    new-instance v3, Lh2/eb;

    .line 82
    .line 83
    sget-object v1, Lk2/s;->y:Lk2/l;

    .line 84
    .line 85
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 86
    .line 87
    .line 88
    move-result-wide v4

    .line 89
    sget-object v1, Lk2/s;->D:Lk2/l;

    .line 90
    .line 91
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 92
    .line 93
    .line 94
    move-result-wide v6

    .line 95
    sget-object v1, Lk2/s;->g:Lk2/l;

    .line 96
    .line 97
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 98
    .line 99
    .line 100
    move-result-wide v8

    .line 101
    sget v2, Lk2/s;->h:F

    .line 102
    .line 103
    invoke-static {v8, v9, v2}, Le3/s;->b(JF)J

    .line 104
    .line 105
    .line 106
    move-result-wide v8

    .line 107
    sget-object v10, Lk2/s;->s:Lk2/l;

    .line 108
    .line 109
    invoke-static {v0, v10}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 110
    .line 111
    .line 112
    move-result-wide v10

    .line 113
    sget-object v12, Lk2/s;->c:Lk2/l;

    .line 114
    .line 115
    invoke-static {v0, v12}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 116
    .line 117
    .line 118
    move-result-wide v13

    .line 119
    move-wide/from16 v16, v13

    .line 120
    .line 121
    invoke-static {v0, v12}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 122
    .line 123
    .line 124
    move-result-wide v14

    .line 125
    move-wide/from16 v18, v16

    .line 126
    .line 127
    invoke-static {v0, v12}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 128
    .line 129
    .line 130
    move-result-wide v16

    .line 131
    invoke-static {v0, v12}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 132
    .line 133
    .line 134
    move-result-wide v12

    .line 135
    move-object/from16 v20, v3

    .line 136
    .line 137
    sget-object v3, Lk2/s;->b:Lk2/l;

    .line 138
    .line 139
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 140
    .line 141
    .line 142
    move-result-wide v21

    .line 143
    sget-object v3, Lk2/s;->r:Lk2/l;

    .line 144
    .line 145
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 146
    .line 147
    .line 148
    move-result-wide v23

    .line 149
    sget-object v3, Lk2/s;->x:Lk2/l;

    .line 150
    .line 151
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 152
    .line 153
    .line 154
    move-result-wide v25

    .line 155
    sget-object v3, Lk2/s;->a:Lk2/l;

    .line 156
    .line 157
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 158
    .line 159
    .line 160
    move-result-wide v27

    .line 161
    sget-object v3, Lk2/s;->e:Lk2/l;

    .line 162
    .line 163
    move-wide/from16 v29, v4

    .line 164
    .line 165
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 166
    .line 167
    .line 168
    move-result-wide v3

    .line 169
    sget v5, Lk2/s;->f:F

    .line 170
    .line 171
    invoke-static {v3, v4, v5}, Le3/s;->b(JF)J

    .line 172
    .line 173
    .line 174
    move-result-wide v3

    .line 175
    sget-object v5, Lk2/s;->q:Lk2/l;

    .line 176
    .line 177
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 178
    .line 179
    .line 180
    move-result-wide v31

    .line 181
    sget-object v5, Lk2/s;->A:Lk2/l;

    .line 182
    .line 183
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 184
    .line 185
    .line 186
    move-result-wide v33

    .line 187
    sget-object v5, Lk2/s;->I:Lk2/l;

    .line 188
    .line 189
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 190
    .line 191
    .line 192
    move-result-wide v35

    .line 193
    sget-object v5, Lk2/s;->k:Lk2/l;

    .line 194
    .line 195
    move-wide/from16 v37, v3

    .line 196
    .line 197
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 198
    .line 199
    .line 200
    move-result-wide v3

    .line 201
    sget v5, Lk2/s;->l:F

    .line 202
    .line 203
    invoke-static {v3, v4, v5}, Le3/s;->b(JF)J

    .line 204
    .line 205
    .line 206
    move-result-wide v3

    .line 207
    sget-object v5, Lk2/s;->u:Lk2/l;

    .line 208
    .line 209
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 210
    .line 211
    .line 212
    move-result-wide v39

    .line 213
    sget-object v5, Lk2/s;->C:Lk2/l;

    .line 214
    .line 215
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 216
    .line 217
    .line 218
    move-result-wide v41

    .line 219
    sget-object v5, Lk2/s;->K:Lk2/l;

    .line 220
    .line 221
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 222
    .line 223
    .line 224
    move-result-wide v43

    .line 225
    sget-object v5, Lk2/s;->o:Lk2/l;

    .line 226
    .line 227
    move-wide/from16 v45, v3

    .line 228
    .line 229
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 230
    .line 231
    .line 232
    move-result-wide v3

    .line 233
    sget v5, Lk2/s;->p:F

    .line 234
    .line 235
    invoke-static {v3, v4, v5}, Le3/s;->b(JF)J

    .line 236
    .line 237
    .line 238
    move-result-wide v3

    .line 239
    sget-object v5, Lk2/s;->w:Lk2/l;

    .line 240
    .line 241
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 242
    .line 243
    .line 244
    move-result-wide v47

    .line 245
    sget-object v5, Lk2/s;->z:Lk2/l;

    .line 246
    .line 247
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 248
    .line 249
    .line 250
    move-result-wide v49

    .line 251
    sget-object v5, Lk2/s;->H:Lk2/l;

    .line 252
    .line 253
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 254
    .line 255
    .line 256
    move-result-wide v51

    .line 257
    sget-object v5, Lk2/s;->i:Lk2/l;

    .line 258
    .line 259
    move-wide/from16 v53, v3

    .line 260
    .line 261
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 262
    .line 263
    .line 264
    move-result-wide v3

    .line 265
    sget v5, Lk2/s;->j:F

    .line 266
    .line 267
    invoke-static {v3, v4, v5}, Le3/s;->b(JF)J

    .line 268
    .line 269
    .line 270
    move-result-wide v3

    .line 271
    sget-object v5, Lk2/s;->t:Lk2/l;

    .line 272
    .line 273
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 274
    .line 275
    .line 276
    move-result-wide v55

    .line 277
    sget-object v5, Lk2/s;->E:Lk2/l;

    .line 278
    .line 279
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 280
    .line 281
    .line 282
    move-result-wide v57

    .line 283
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 284
    .line 285
    .line 286
    move-result-wide v59

    .line 287
    move-wide/from16 v61, v3

    .line 288
    .line 289
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 290
    .line 291
    .line 292
    move-result-wide v3

    .line 293
    invoke-static {v3, v4, v2}, Le3/s;->b(JF)J

    .line 294
    .line 295
    .line 296
    move-result-wide v3

    .line 297
    invoke-static {v0, v5}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 298
    .line 299
    .line 300
    move-result-wide v63

    .line 301
    sget-object v1, Lk2/s;->B:Lk2/l;

    .line 302
    .line 303
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 304
    .line 305
    .line 306
    move-result-wide v65

    .line 307
    sget-object v1, Lk2/s;->J:Lk2/l;

    .line 308
    .line 309
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 310
    .line 311
    .line 312
    move-result-wide v67

    .line 313
    sget-object v1, Lk2/s;->m:Lk2/l;

    .line 314
    .line 315
    move-wide/from16 v69, v3

    .line 316
    .line 317
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 318
    .line 319
    .line 320
    move-result-wide v3

    .line 321
    sget v1, Lk2/s;->n:F

    .line 322
    .line 323
    invoke-static {v3, v4, v1}, Le3/s;->b(JF)J

    .line 324
    .line 325
    .line 326
    move-result-wide v3

    .line 327
    sget-object v1, Lk2/s;->v:Lk2/l;

    .line 328
    .line 329
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 330
    .line 331
    .line 332
    move-result-wide v71

    .line 333
    sget-object v1, Lk2/s;->F:Lk2/l;

    .line 334
    .line 335
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 336
    .line 337
    .line 338
    move-result-wide v73

    .line 339
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 340
    .line 341
    .line 342
    move-result-wide v75

    .line 343
    move-wide/from16 v77, v3

    .line 344
    .line 345
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 346
    .line 347
    .line 348
    move-result-wide v3

    .line 349
    invoke-static {v3, v4, v2}, Le3/s;->b(JF)J

    .line 350
    .line 351
    .line 352
    move-result-wide v3

    .line 353
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 354
    .line 355
    .line 356
    move-result-wide v79

    .line 357
    sget-object v1, Lk2/s;->G:Lk2/l;

    .line 358
    .line 359
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 360
    .line 361
    .line 362
    move-result-wide v81

    .line 363
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 364
    .line 365
    .line 366
    move-result-wide v83

    .line 367
    move-wide/from16 v85, v3

    .line 368
    .line 369
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 370
    .line 371
    .line 372
    move-result-wide v3

    .line 373
    invoke-static {v3, v4, v2}, Le3/s;->b(JF)J

    .line 374
    .line 375
    .line 376
    move-result-wide v2

    .line 377
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 378
    .line 379
    .line 380
    move-result-wide v87

    .line 381
    move-wide/from16 v4, v18

    .line 382
    .line 383
    move-wide/from16 v18, v12

    .line 384
    .line 385
    move-wide v12, v4

    .line 386
    move-wide/from16 v4, v29

    .line 387
    .line 388
    move-wide/from16 v29, v37

    .line 389
    .line 390
    move-wide/from16 v37, v45

    .line 391
    .line 392
    move-wide/from16 v45, v53

    .line 393
    .line 394
    move-wide/from16 v53, v61

    .line 395
    .line 396
    move-wide/from16 v61, v69

    .line 397
    .line 398
    move-wide/from16 v69, v77

    .line 399
    .line 400
    move-wide/from16 v77, v85

    .line 401
    .line 402
    move-wide/from16 v85, v2

    .line 403
    .line 404
    move-object/from16 v3, v20

    .line 405
    .line 406
    move-wide/from16 v20, v21

    .line 407
    .line 408
    move-wide/from16 v22, v23

    .line 409
    .line 410
    move-object/from16 v24, p1

    .line 411
    .line 412
    invoke-direct/range {v3 .. v88}, Lh2/eb;-><init>(JJJJJJJJJJLe2/d1;JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ)V

    .line 413
    .line 414
    .line 415
    iput-object v3, v0, Lh2/f1;->g0:Lh2/eb;

    .line 416
    .line 417
    return-object v3
.end method

.method public static g(Lx2/s;ZZLi1/l;Lh2/eb;)Lx2/s;
    .locals 6

    .line 1
    new-instance v0, Landroidx/compose/material3/IndicatorLineElement;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    move v1, p1

    .line 5
    move v2, p2

    .line 6
    move-object v3, p3

    .line 7
    move-object v4, p4

    .line 8
    invoke-direct/range {v0 .. v5}, Landroidx/compose/material3/IndicatorLineElement;-><init>(ZZLi1/l;Lh2/eb;Le3/n0;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static h()Lk1/a1;
    .locals 4

    .line 1
    sget v0, Li2/h1;->a:F

    .line 2
    .line 3
    sget v1, Li2/h1;->b:F

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    int-to-float v2, v2

    .line 7
    new-instance v3, Lk1/a1;

    .line 8
    .line 9
    invoke-direct {v3, v0, v1, v0, v2}, Lk1/a1;-><init>(FFFF)V

    .line 10
    .line 11
    .line 12
    return-object v3
.end method


# virtual methods
.method public final a(ZZLi1/l;Lh2/eb;Le3/n0;Ll2/o;I)V
    .locals 21

    .line 1
    move/from16 v1, p1

    .line 2
    .line 3
    move/from16 v2, p2

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    move-object/from16 v4, p4

    .line 8
    .line 9
    move-object/from16 v5, p5

    .line 10
    .line 11
    move-object/from16 v10, p6

    .line 12
    .line 13
    check-cast v10, Ll2/t;

    .line 14
    .line 15
    const v0, -0x30cbc77a    # -3.0236032E9f

    .line 16
    .line 17
    .line 18
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v10, v1}, Ll2/t;->h(Z)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int v0, p7, v0

    .line 31
    .line 32
    invoke-virtual {v10, v2}, Ll2/t;->h(Z)Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    if-eqz v6, :cond_1

    .line 37
    .line 38
    const/16 v6, 0x20

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v6, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v0, v6

    .line 44
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    if-eqz v6, :cond_2

    .line 49
    .line 50
    const/16 v6, 0x100

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v6, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v6

    .line 56
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    if-eqz v6, :cond_3

    .line 61
    .line 62
    const/16 v6, 0x4000

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v6, 0x2000

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v6

    .line 68
    invoke-virtual {v10, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_4

    .line 73
    .line 74
    const/high16 v6, 0x20000

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    const/high16 v6, 0x10000

    .line 78
    .line 79
    :goto_4
    or-int/2addr v0, v6

    .line 80
    const v6, 0x2492493

    .line 81
    .line 82
    .line 83
    and-int/2addr v6, v0

    .line 84
    const v7, 0x2492492

    .line 85
    .line 86
    .line 87
    const/4 v13, 0x0

    .line 88
    if-eq v6, v7, :cond_5

    .line 89
    .line 90
    const/4 v6, 0x1

    .line 91
    goto :goto_5

    .line 92
    :cond_5
    move v6, v13

    .line 93
    :goto_5
    and-int/lit8 v7, v0, 0x1

    .line 94
    .line 95
    invoke-virtual {v10, v7, v6}, Ll2/t;->O(IZ)Z

    .line 96
    .line 97
    .line 98
    move-result v6

    .line 99
    if-eqz v6, :cond_b

    .line 100
    .line 101
    invoke-virtual {v10}, Ll2/t;->T()V

    .line 102
    .line 103
    .line 104
    and-int/lit8 v6, p7, 0x1

    .line 105
    .line 106
    if-eqz v6, :cond_7

    .line 107
    .line 108
    invoke-virtual {v10}, Ll2/t;->y()Z

    .line 109
    .line 110
    .line 111
    move-result v6

    .line 112
    if-eqz v6, :cond_6

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_6
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :cond_7
    :goto_6
    invoke-virtual {v10}, Ll2/t;->r()V

    .line 119
    .line 120
    .line 121
    shr-int/lit8 v0, v0, 0x6

    .line 122
    .line 123
    and-int/lit8 v0, v0, 0xe

    .line 124
    .line 125
    invoke-static {v3, v10, v0}, Llp/n1;->b(Li1/l;Ll2/o;I)Ll2/b1;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    check-cast v0, Ljava/lang/Boolean;

    .line 134
    .line 135
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    if-nez v1, :cond_8

    .line 140
    .line 141
    iget-wide v6, v4, Lh2/eb;->g:J

    .line 142
    .line 143
    goto :goto_7

    .line 144
    :cond_8
    if-eqz v2, :cond_9

    .line 145
    .line 146
    iget-wide v6, v4, Lh2/eb;->h:J

    .line 147
    .line 148
    goto :goto_7

    .line 149
    :cond_9
    if-eqz v0, :cond_a

    .line 150
    .line 151
    iget-wide v6, v4, Lh2/eb;->e:J

    .line 152
    .line 153
    goto :goto_7

    .line 154
    :cond_a
    iget-wide v6, v4, Lh2/eb;->f:J

    .line 155
    .line 156
    :goto_7
    sget-object v0, Lk2/w;->g:Lk2/w;

    .line 157
    .line 158
    invoke-static {v0, v10}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    const/4 v11, 0x0

    .line 163
    const/16 v12, 0xc

    .line 164
    .line 165
    const/4 v9, 0x0

    .line 166
    invoke-static/range {v6 .. v12}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 167
    .line 168
    .line 169
    move-result-object v18

    .line 170
    new-instance v14, La90/r;

    .line 171
    .line 172
    const/4 v15, 0x0

    .line 173
    const/16 v16, 0xe

    .line 174
    .line 175
    const-class v17, Ll2/t2;

    .line 176
    .line 177
    const-string v19, "value"

    .line 178
    .line 179
    const-string v20, "getValue()Ljava/lang/Object;"

    .line 180
    .line 181
    invoke-direct/range {v14 .. v20}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    new-instance v0, Lh2/gb;

    .line 185
    .line 186
    invoke-direct {v0, v14}, Lh2/gb;-><init>(La90/r;)V

    .line 187
    .line 188
    .line 189
    sget v6, Li2/h1;->a:F

    .line 190
    .line 191
    new-instance v6, Let/g;

    .line 192
    .line 193
    const/16 v7, 0x1c

    .line 194
    .line 195
    invoke-direct {v6, v7, v5, v0}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 199
    .line 200
    invoke-static {v0, v6}, Landroidx/compose/ui/draw/a;->b(Lx2/s;Lay0/k;)Lx2/s;

    .line 201
    .line 202
    .line 203
    move-result-object v6

    .line 204
    new-instance v0, Landroidx/compose/material3/IndicatorLineElement;

    .line 205
    .line 206
    invoke-direct/range {v0 .. v5}, Landroidx/compose/material3/IndicatorLineElement;-><init>(ZZLi1/l;Lh2/eb;Le3/n0;)V

    .line 207
    .line 208
    .line 209
    invoke-interface {v6, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    invoke-static {v0, v10, v13}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 214
    .line 215
    .line 216
    goto :goto_8

    .line 217
    :cond_b
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 218
    .line 219
    .line 220
    :goto_8
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 221
    .line 222
    .line 223
    move-result-object v8

    .line 224
    if-eqz v8, :cond_c

    .line 225
    .line 226
    new-instance v0, Ldk/a;

    .line 227
    .line 228
    move-object/from16 v1, p0

    .line 229
    .line 230
    move/from16 v2, p1

    .line 231
    .line 232
    move/from16 v3, p2

    .line 233
    .line 234
    move-object/from16 v4, p3

    .line 235
    .line 236
    move-object/from16 v5, p4

    .line 237
    .line 238
    move-object/from16 v6, p5

    .line 239
    .line 240
    move/from16 v7, p7

    .line 241
    .line 242
    invoke-direct/range {v0 .. v7}, Ldk/a;-><init>(Lh2/hb;ZZLi1/l;Lh2/eb;Le3/n0;I)V

    .line 243
    .line 244
    .line 245
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 246
    .line 247
    :cond_c
    return-void
.end method

.method public final b(Ljava/lang/String;Lay0/n;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Le3/n0;Lh2/eb;Lk1/z0;Lay0/n;Ll2/o;III)V
    .locals 34

    move-object/from16 v2, p1

    move-object/from16 v6, p5

    move/from16 v15, p15

    move/from16 v0, p17

    .line 1
    move-object/from16 v1, p14

    check-cast v1, Ll2/t;

    const v3, 0x6bb456c1

    invoke-virtual {v1, v3}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v3, v15, 0x6

    if-nez v3, :cond_1

    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v15

    goto :goto_1

    :cond_1
    move v3, v15

    :goto_1
    and-int/lit8 v7, v15, 0x30

    if-nez v7, :cond_3

    move-object/from16 v7, p2

    invoke-virtual {v1, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    const/16 v10, 0x20

    goto :goto_2

    :cond_2
    const/16 v10, 0x10

    :goto_2
    or-int/2addr v3, v10

    goto :goto_3

    :cond_3
    move-object/from16 v7, p2

    :goto_3
    and-int/lit16 v10, v15, 0x180

    if-nez v10, :cond_5

    move/from16 v10, p3

    invoke-virtual {v1, v10}, Ll2/t;->h(Z)Z

    move-result v13

    if-eqz v13, :cond_4

    const/16 v13, 0x100

    goto :goto_4

    :cond_4
    const/16 v13, 0x80

    :goto_4
    or-int/2addr v3, v13

    goto :goto_5

    :cond_5
    move/from16 v10, p3

    :goto_5
    and-int/lit16 v13, v15, 0xc00

    const/16 v16, 0x800

    if-nez v13, :cond_7

    move/from16 v13, p4

    invoke-virtual {v1, v13}, Ll2/t;->h(Z)Z

    move-result v17

    if-eqz v17, :cond_6

    move/from16 v17, v16

    goto :goto_6

    :cond_6
    const/16 v17, 0x400

    :goto_6
    or-int v3, v3, v17

    goto :goto_7

    :cond_7
    move/from16 v13, p4

    :goto_7
    and-int/lit16 v4, v15, 0x6000

    const/16 v17, 0x2000

    if-nez v4, :cond_9

    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_8

    const/16 v4, 0x4000

    goto :goto_8

    :cond_8
    move/from16 v4, v17

    :goto_8
    or-int/2addr v3, v4

    :cond_9
    const/high16 v4, 0x30000

    and-int/2addr v4, v15

    const/high16 v19, 0x20000

    const/high16 v20, 0x10000

    if-nez v4, :cond_b

    move-object/from16 v4, p6

    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_a

    move/from16 v21, v19

    goto :goto_9

    :cond_a
    move/from16 v21, v20

    :goto_9
    or-int v3, v3, v21

    goto :goto_a

    :cond_b
    move-object/from16 v4, p6

    :goto_a
    and-int/lit8 v21, v0, 0x40

    const/high16 v22, 0x80000

    const/high16 v23, 0x100000

    const/high16 v24, 0x180000

    if-eqz v21, :cond_c

    or-int v3, v3, v24

    move/from16 v9, p7

    goto :goto_c

    :cond_c
    and-int v24, v15, v24

    move/from16 v9, p7

    if-nez v24, :cond_e

    invoke-virtual {v1, v9}, Ll2/t;->h(Z)Z

    move-result v25

    if-eqz v25, :cond_d

    move/from16 v25, v23

    goto :goto_b

    :cond_d
    move/from16 v25, v22

    :goto_b
    or-int v3, v3, v25

    :cond_e
    :goto_c
    and-int/lit16 v11, v0, 0x80

    const/high16 v26, 0xc00000

    if-eqz v11, :cond_f

    or-int v3, v3, v26

    move-object/from16 v12, p8

    goto :goto_e

    :cond_f
    and-int v27, v15, v26

    move-object/from16 v12, p8

    if-nez v27, :cond_11

    invoke-virtual {v1, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v28

    if-eqz v28, :cond_10

    const/high16 v28, 0x800000

    goto :goto_d

    :cond_10
    const/high16 v28, 0x400000

    :goto_d
    or-int v3, v3, v28

    :cond_11
    :goto_e
    const/high16 v28, 0x6000000

    and-int v28, v15, v28

    move-object/from16 v14, p9

    if-nez v28, :cond_13

    invoke-virtual {v1, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_12

    const/high16 v29, 0x4000000

    goto :goto_f

    :cond_12
    const/high16 v29, 0x2000000

    :goto_f
    or-int v3, v3, v29

    :cond_13
    const/high16 v29, 0x30000000

    and-int v29, v15, v29

    const/4 v8, 0x0

    if-nez v29, :cond_15

    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_14

    const/high16 v29, 0x20000000

    goto :goto_10

    :cond_14
    const/high16 v29, 0x10000000

    :goto_10
    or-int v3, v3, v29

    :cond_15
    and-int/lit8 v29, p16, 0x6

    if-nez v29, :cond_17

    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_16

    const/16 v29, 0x4

    goto :goto_11

    :cond_16
    const/16 v29, 0x2

    :goto_11
    or-int v29, p16, v29

    goto :goto_12

    :cond_17
    move/from16 v29, p16

    :goto_12
    and-int/lit16 v5, v0, 0x800

    if-eqz v5, :cond_18

    or-int/lit8 v5, v29, 0x30

    goto :goto_14

    :cond_18
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_19

    const/16 v18, 0x20

    goto :goto_13

    :cond_19
    const/16 v18, 0x10

    :goto_13
    or-int v5, v29, v18

    :goto_14
    and-int/lit16 v8, v0, 0x1000

    if-eqz v8, :cond_1a

    or-int/lit16 v5, v5, 0x180

    goto :goto_16

    :cond_1a
    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_1b

    const/16 v25, 0x100

    goto :goto_15

    :cond_1b
    const/16 v25, 0x80

    :goto_15
    or-int v5, v5, v25

    :goto_16
    and-int/lit16 v8, v0, 0x2000

    if-eqz v8, :cond_1c

    or-int/lit16 v5, v5, 0xc00

    const/4 v8, 0x0

    goto :goto_18

    :cond_1c
    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_1d

    goto :goto_17

    :cond_1d
    const/16 v16, 0x400

    :goto_17
    or-int v5, v5, v16

    :goto_18
    and-int/lit16 v8, v0, 0x4000

    if-nez v8, :cond_1e

    move-object/from16 v8, p10

    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_1f

    const/16 v17, 0x4000

    goto :goto_19

    :cond_1e
    move-object/from16 v8, p10

    :cond_1f
    :goto_19
    or-int v5, v5, v17

    move-object/from16 v4, p11

    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_20

    goto :goto_1a

    :cond_20
    move/from16 v19, v20

    :goto_1a
    or-int v5, v5, v19

    and-int v16, v0, v20

    move-object/from16 v4, p12

    if-nez v16, :cond_21

    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_21

    move/from16 v22, v23

    :cond_21
    or-int v5, v5, v22

    or-int v5, v5, v26

    const v16, 0x12492493

    and-int v4, v3, v16

    move/from16 v16, v5

    const v5, 0x12492492

    const/4 v7, 0x0

    const/16 v23, 0x1

    if-ne v4, v5, :cond_23

    const v4, 0x2492493

    and-int v4, v16, v4

    const v5, 0x2492492

    if-eq v4, v5, :cond_22

    goto :goto_1b

    :cond_22
    move v4, v7

    goto :goto_1c

    :cond_23
    :goto_1b
    move/from16 v4, v23

    :goto_1c
    and-int/lit8 v5, v3, 0x1

    invoke-virtual {v1, v5, v4}, Ll2/t;->O(IZ)Z

    move-result v4

    if-eqz v4, :cond_32

    invoke-virtual {v1}, Ll2/t;->T()V

    and-int/lit8 v4, v15, 0x1

    const v5, -0x380001

    const v17, -0xe001

    if-eqz v4, :cond_27

    invoke-virtual {v1}, Ll2/t;->y()Z

    move-result v4

    if-eqz v4, :cond_24

    goto :goto_1d

    .line 2
    :cond_24
    invoke-virtual {v1}, Ll2/t;->R()V

    and-int/lit16 v4, v0, 0x4000

    if-eqz v4, :cond_25

    and-int v4, v16, v17

    move/from16 v16, v4

    :cond_25
    and-int v4, v0, v20

    if-eqz v4, :cond_26

    and-int v16, v16, v5

    :cond_26
    move-object/from16 v27, p12

    move-object/from16 v29, p13

    move/from16 v25, v9

    goto :goto_22

    :cond_27
    :goto_1d
    if-eqz v21, :cond_28

    move/from16 v18, v7

    goto :goto_1e

    :cond_28
    move/from16 v18, v9

    :goto_1e
    if-eqz v11, :cond_29

    const/4 v12, 0x0

    :cond_29
    and-int/lit16 v4, v0, 0x4000

    if-eqz v4, :cond_2a

    .line 3
    sget-object v4, Lk2/s;->d:Lk2/f0;

    .line 4
    invoke-static {v4, v1}, Lh2/i8;->b(Lk2/f0;Ll2/o;)Le3/n0;

    move-result-object v4

    and-int v8, v16, v17

    move-object/from16 v21, v4

    move/from16 v16, v8

    goto :goto_1f

    :cond_2a
    move-object/from16 v21, v8

    :goto_1f
    and-int v4, v0, v20

    if-eqz v4, :cond_2c

    if-nez v12, :cond_2b

    .line 5
    invoke-static/range {p0 .. p0}, Lh2/hb;->e(Lh2/hb;)Lk1/a1;

    move-result-object v4

    goto :goto_20

    .line 6
    :cond_2b
    invoke-static/range {p0 .. p0}, Lh2/hb;->d(Lh2/hb;)Lk1/a1;

    move-result-object v4

    :goto_20
    and-int v5, v16, v5

    goto :goto_21

    :cond_2c
    move-object/from16 v4, p12

    move/from16 v5, v16

    .line 7
    :goto_21
    new-instance v16, Lh2/z6;

    const/16 v22, 0x1

    move-object/from16 v19, p6

    move-object/from16 v20, p11

    move/from16 v17, v10

    invoke-direct/range {v16 .. v22}, Lh2/z6;-><init>(ZZLi1/l;Lh2/eb;Le3/n0;I)V

    move-object/from16 v8, v16

    const v9, 0x18e8c5b6

    invoke-static {v9, v1, v8}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v8

    move-object/from16 v27, v4

    move/from16 v16, v5

    move-object/from16 v29, v8

    move/from16 v25, v18

    move-object/from16 v8, v21

    .line 8
    :goto_22
    invoke-virtual {v1}, Ll2/t;->r()V

    and-int/lit8 v4, v3, 0xe

    const/4 v5, 0x4

    if-ne v4, v5, :cond_2d

    move/from16 v4, v23

    goto :goto_23

    :cond_2d
    move v4, v7

    :goto_23
    const v5, 0xe000

    and-int v9, v3, v5

    const/16 v10, 0x4000

    if-ne v9, v10, :cond_2e

    goto :goto_24

    :cond_2e
    move/from16 v23, v7

    :goto_24
    or-int v4, v4, v23

    .line 9
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v9

    if-nez v4, :cond_2f

    .line 10
    sget-object v4, Ll2/n;->a:Ll2/x0;

    if-ne v9, v4, :cond_30

    .line 11
    :cond_2f
    new-instance v4, Lg4/g;

    invoke-direct {v4, v2}, Lg4/g;-><init>(Ljava/lang/String;)V

    invoke-interface {v6, v4}, Ll4/d0;->b(Lg4/g;)Ll4/b0;

    move-result-object v9

    .line 12
    invoke-virtual {v1, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 13
    :cond_30
    check-cast v9, Ll4/b0;

    .line 14
    iget-object v4, v9, Ll4/b0;->a:Lg4/g;

    .line 15
    iget-object v4, v4, Lg4/g;->e:Ljava/lang/String;

    move/from16 v9, v16

    .line 16
    sget-object v16, Li2/i1;->d:Li2/i1;

    .line 17
    new-instance v19, Lh2/nb;

    invoke-direct/range {v19 .. v19}, Lh2/nb;-><init>()V

    if-nez v12, :cond_31

    const v10, -0x50a724b7

    .line 18
    invoke-virtual {v1, v10}, Ll2/t;->Y(I)V

    .line 19
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    const/16 v20, 0x0

    goto :goto_25

    :cond_31
    const v10, -0x50a724b6

    .line 20
    invoke-virtual {v1, v10}, Ll2/t;->Y(I)V

    new-instance v10, Lh2/u6;

    const/4 v11, 0x2

    invoke-direct {v10, v11, v12}, Lh2/u6;-><init>(ILay0/n;)V

    const v11, 0x422a2601

    invoke-static {v11, v1, v10}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    move-result-object v10

    .line 21
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    move-object/from16 v20, v10

    :goto_25
    shl-int/lit8 v7, v3, 0x3

    and-int/lit16 v7, v7, 0x380

    or-int/lit8 v7, v7, 0x6

    shr-int/lit8 v10, v3, 0x9

    const/high16 v11, 0x70000

    and-int v17, v10, v11

    or-int v7, v7, v17

    const/high16 v17, 0x380000

    and-int v18, v10, v17

    or-int v7, v7, v18

    shl-int/lit8 v18, v9, 0x15

    const/high16 v21, 0x1c00000

    and-int v21, v18, v21

    or-int v7, v7, v21

    const/high16 v21, 0xe000000

    and-int v21, v18, v21

    or-int v7, v7, v21

    const/high16 v21, 0x70000000

    and-int v18, v18, v21

    or-int v31, v7, v18

    shr-int/lit8 v7, v9, 0x9

    and-int/lit8 v7, v7, 0xe

    shr-int/lit8 v18, v3, 0x6

    and-int/lit8 v18, v18, 0x70

    or-int v7, v7, v18

    move/from16 p7, v5

    and-int/lit16 v5, v3, 0x380

    or-int/2addr v5, v7

    and-int/lit16 v7, v10, 0x1c00

    or-int/2addr v5, v7

    shr-int/lit8 v3, v3, 0x3

    and-int v3, v3, p7

    or-int/2addr v3, v5

    shr-int/lit8 v5, v9, 0x3

    and-int/2addr v5, v11

    or-int/2addr v3, v5

    shl-int/lit8 v5, v9, 0x3

    and-int v5, v5, v17

    or-int/2addr v3, v5

    or-int v32, v3, v26

    const/16 v22, 0x0

    move-object/from16 v18, p2

    move/from16 v24, p3

    move-object/from16 v26, p6

    move-object/from16 v28, p11

    move-object/from16 v30, v1

    move-object/from16 v17, v4

    move/from16 v23, v13

    move-object/from16 v21, v14

    .line 22
    invoke-static/range {v16 .. v32}, Li2/h1;->a(Li2/i1;Ljava/lang/CharSequence;Lay0/n;Lh2/nb;Lay0/o;Lay0/n;Lay0/n;ZZZLi1/l;Lk1/z0;Lh2/eb;Lay0/n;Ll2/o;II)V

    move-object v11, v8

    move/from16 v8, v25

    move-object/from16 v13, v27

    move-object/from16 v14, v29

    :goto_26
    move-object v9, v12

    goto :goto_27

    :cond_32
    move-object/from16 v30, v1

    .line 23
    invoke-virtual/range {v30 .. v30}, Ll2/t;->R()V

    move-object/from16 v13, p12

    move-object/from16 v14, p13

    move-object v11, v8

    move v8, v9

    goto :goto_26

    .line 24
    :goto_27
    invoke-virtual/range {v30 .. v30}, Ll2/t;->s()Ll2/u1;

    move-result-object v1

    if-eqz v1, :cond_33

    new-instance v0, Lh2/fb;

    move-object/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v7, p6

    move-object/from16 v10, p9

    move-object/from16 v12, p11

    move/from16 v16, p16

    move/from16 v17, p17

    move-object/from16 v33, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v17}, Lh2/fb;-><init>(Lh2/hb;Ljava/lang/String;Lay0/n;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Le3/n0;Lh2/eb;Lk1/z0;Lay0/n;III)V

    move-object v1, v0

    move-object/from16 v0, v33

    .line 25
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    :cond_33
    return-void
.end method
