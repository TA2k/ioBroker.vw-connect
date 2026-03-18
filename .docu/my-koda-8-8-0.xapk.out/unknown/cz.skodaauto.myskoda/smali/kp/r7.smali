.class public abstract Lkp/r7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;IZLay0/a;Lay0/a;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v12, p1

    .line 4
    .line 5
    move/from16 v1, p2

    .line 6
    .line 7
    move-object/from16 v13, p3

    .line 8
    .line 9
    move-object/from16 v14, p4

    .line 10
    .line 11
    const-string v2, "modifier"

    .line 12
    .line 13
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v2, "onTouchDown"

    .line 17
    .line 18
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v2, "onTouchUp"

    .line 22
    .line 23
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    move-object/from16 v10, p5

    .line 27
    .line 28
    check-cast v10, Ll2/t;

    .line 29
    .line 30
    const v2, -0x2a41dbc9

    .line 31
    .line 32
    .line 33
    invoke-virtual {v10, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v10, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_0

    .line 41
    .line 42
    const/4 v2, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v2, 0x2

    .line 45
    :goto_0
    or-int v2, p6, v2

    .line 46
    .line 47
    invoke-virtual {v10, v12}, Ll2/t;->e(I)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_1

    .line 52
    .line 53
    const/16 v3, 0x20

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/16 v3, 0x10

    .line 57
    .line 58
    :goto_1
    or-int/2addr v2, v3

    .line 59
    invoke-virtual {v10, v1}, Ll2/t;->h(Z)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_2

    .line 64
    .line 65
    const/16 v3, 0x100

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_2
    const/16 v3, 0x80

    .line 69
    .line 70
    :goto_2
    or-int/2addr v2, v3

    .line 71
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    if-eqz v3, :cond_3

    .line 76
    .line 77
    const/16 v3, 0x800

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    const/16 v3, 0x400

    .line 81
    .line 82
    :goto_3
    or-int/2addr v2, v3

    .line 83
    invoke-virtual {v10, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    if-eqz v3, :cond_4

    .line 88
    .line 89
    const/16 v3, 0x4000

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_4
    const/16 v3, 0x2000

    .line 93
    .line 94
    :goto_4
    or-int/2addr v2, v3

    .line 95
    and-int/lit16 v3, v2, 0x2493

    .line 96
    .line 97
    const/16 v4, 0x2492

    .line 98
    .line 99
    const/16 v16, 0x1

    .line 100
    .line 101
    if-eq v3, v4, :cond_5

    .line 102
    .line 103
    move/from16 v3, v16

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_5
    const/4 v3, 0x0

    .line 107
    :goto_5
    and-int/lit8 v4, v2, 0x1

    .line 108
    .line 109
    invoke-virtual {v10, v4, v3}, Ll2/t;->O(IZ)Z

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-eqz v3, :cond_11

    .line 114
    .line 115
    sget-object v3, Lh71/m;->a:Ll2/u2;

    .line 116
    .line 117
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    check-cast v3, Lh71/l;

    .line 122
    .line 123
    iget-object v3, v3, Lh71/l;->c:Lh71/f;

    .line 124
    .line 125
    iget-object v3, v3, Lh71/f;->g:Lh71/w;

    .line 126
    .line 127
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 132
    .line 133
    if-ne v4, v5, :cond_6

    .line 134
    .line 135
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :cond_6
    check-cast v4, Ll2/b1;

    .line 145
    .line 146
    iget-object v6, v3, Lh71/w;->c:Lh71/d;

    .line 147
    .line 148
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    check-cast v7, Ljava/lang/Boolean;

    .line 153
    .line 154
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 155
    .line 156
    .line 157
    move-result v7

    .line 158
    shr-int/lit8 v17, v2, 0x3

    .line 159
    .line 160
    and-int/lit8 v18, v17, 0x70

    .line 161
    .line 162
    invoke-virtual {v6, v7, v1}, Lh71/d;->a(ZZ)J

    .line 163
    .line 164
    .line 165
    move-result-wide v6

    .line 166
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v8

    .line 170
    if-ne v8, v5, :cond_7

    .line 171
    .line 172
    new-instance v8, Lf31/n;

    .line 173
    .line 174
    const/4 v15, 0x3

    .line 175
    invoke-direct {v8, v15}, Lf31/n;-><init>(I)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v10, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    :cond_7
    check-cast v8, Lay0/k;

    .line 182
    .line 183
    move-object v15, v4

    .line 184
    move-wide/from16 v20, v6

    .line 185
    .line 186
    move-object v6, v3

    .line 187
    move-wide/from16 v3, v20

    .line 188
    .line 189
    const/16 v7, 0x30

    .line 190
    .line 191
    move-object/from16 v19, v5

    .line 192
    .line 193
    move-object v5, v8

    .line 194
    const/4 v8, 0x0

    .line 195
    move-object v11, v10

    .line 196
    move-object v10, v6

    .line 197
    move-object v6, v11

    .line 198
    move-object/from16 v11, v19

    .line 199
    .line 200
    invoke-static/range {v3 .. v8}, Lkp/f0;->c(JLay0/k;Ll2/o;II)Le71/b;

    .line 201
    .line 202
    .line 203
    move-result-object v5

    .line 204
    invoke-interface {v15}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v7

    .line 208
    check-cast v7, Ljava/lang/Boolean;

    .line 209
    .line 210
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 211
    .line 212
    .line 213
    move-result v7

    .line 214
    new-instance v8, Le71/g;

    .line 215
    .line 216
    and-int/lit8 v9, v17, 0xe

    .line 217
    .line 218
    invoke-static {v12, v9, v6}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 219
    .line 220
    .line 221
    move-result-object v9

    .line 222
    invoke-direct {v8, v5, v9, v3, v4}, Le71/g;-><init>(Le71/b;Li3/c;J)V

    .line 223
    .line 224
    .line 225
    iget-object v3, v10, Lh71/w;->d:Lh71/x;

    .line 226
    .line 227
    and-int/lit16 v4, v2, 0x1c00

    .line 228
    .line 229
    const/16 v5, 0x800

    .line 230
    .line 231
    if-ne v4, v5, :cond_8

    .line 232
    .line 233
    move/from16 v4, v16

    .line 234
    .line 235
    goto :goto_6

    .line 236
    :cond_8
    const/4 v4, 0x0

    .line 237
    :goto_6
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v5

    .line 241
    if-nez v4, :cond_9

    .line 242
    .line 243
    if-ne v5, v11, :cond_a

    .line 244
    .line 245
    :cond_9
    new-instance v5, Lb71/h;

    .line 246
    .line 247
    const/4 v4, 0x4

    .line 248
    invoke-direct {v5, v4, v13, v15}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v6, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    :cond_a
    check-cast v5, Lay0/a;

    .line 255
    .line 256
    const v4, 0xe000

    .line 257
    .line 258
    .line 259
    and-int/2addr v4, v2

    .line 260
    const/16 v9, 0x4000

    .line 261
    .line 262
    if-ne v4, v9, :cond_b

    .line 263
    .line 264
    move/from16 v9, v16

    .line 265
    .line 266
    goto :goto_7

    .line 267
    :cond_b
    const/4 v9, 0x0

    .line 268
    :goto_7
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v10

    .line 272
    if-nez v9, :cond_c

    .line 273
    .line 274
    if-ne v10, v11, :cond_d

    .line 275
    .line 276
    :cond_c
    new-instance v10, Lb71/h;

    .line 277
    .line 278
    const/4 v9, 0x5

    .line 279
    invoke-direct {v10, v9, v14, v15}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v6, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    :cond_d
    check-cast v10, Lay0/a;

    .line 286
    .line 287
    const/16 v9, 0x4000

    .line 288
    .line 289
    if-ne v4, v9, :cond_e

    .line 290
    .line 291
    goto :goto_8

    .line 292
    :cond_e
    const/16 v16, 0x0

    .line 293
    .line 294
    :goto_8
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v4

    .line 298
    if-nez v16, :cond_f

    .line 299
    .line 300
    if-ne v4, v11, :cond_10

    .line 301
    .line 302
    :cond_f
    new-instance v4, Lb71/h;

    .line 303
    .line 304
    const/4 v9, 0x6

    .line 305
    invoke-direct {v4, v9, v14, v15}, Lb71/h;-><init>(ILay0/a;Ll2/b1;)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v6, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    :cond_10
    move-object v9, v4

    .line 312
    check-cast v9, Lay0/a;

    .line 313
    .line 314
    const/high16 v4, 0x1b0000

    .line 315
    .line 316
    and-int/lit8 v2, v2, 0xe

    .line 317
    .line 318
    or-int/2addr v2, v4

    .line 319
    or-int v11, v2, v18

    .line 320
    .line 321
    move v4, v7

    .line 322
    move-object v7, v5

    .line 323
    const/4 v5, 0x0

    .line 324
    move-object v2, v8

    .line 325
    move-object v8, v10

    .line 326
    move-object v10, v6

    .line 327
    const v6, 0x3edc28f6    # 0.43f

    .line 328
    .line 329
    .line 330
    invoke-static/range {v0 .. v11}, Lkp/j0;->a(Lx2/s;ZLe71/g;Lh71/x;ZLjava/lang/Float;FLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 331
    .line 332
    .line 333
    goto :goto_9

    .line 334
    :cond_11
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 335
    .line 336
    .line 337
    :goto_9
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 338
    .line 339
    .line 340
    move-result-object v7

    .line 341
    if-eqz v7, :cond_12

    .line 342
    .line 343
    new-instance v0, Lf71/b;

    .line 344
    .line 345
    move-object/from16 v1, p0

    .line 346
    .line 347
    move/from16 v3, p2

    .line 348
    .line 349
    move/from16 v6, p6

    .line 350
    .line 351
    move v2, v12

    .line 352
    move-object v4, v13

    .line 353
    move-object v5, v14

    .line 354
    invoke-direct/range {v0 .. v6}, Lf71/b;-><init>(Lx2/s;IZLay0/a;Lay0/a;I)V

    .line 355
    .line 356
    .line 357
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 358
    .line 359
    :cond_12
    return-void
.end method

.method public static final b(Ljava/time/LocalDate;ZZZ)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "format(...)"

    .line 7
    .line 8
    if-eqz p1, :cond_3

    .line 9
    .line 10
    if-eqz p2, :cond_1

    .line 11
    .line 12
    if-eqz p3, :cond_0

    .line 13
    .line 14
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    sget-object p3, Ljava/time/format/TextStyle;->FULL_STANDALONE:Ljava/time/format/TextStyle;

    .line 23
    .line 24
    invoke-virtual {p2, p3, p1}, Ljava/time/Month;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    new-instance p2, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string p1, " "

    .line 41
    .line 42
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_0
    const/4 p1, 0x0

    .line 54
    invoke-static {p0, p1}, Ljp/e1;->c(Ljava/time/LocalDate;Z)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_1
    if-eqz p3, :cond_2

    .line 60
    .line 61
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    sget-object p2, Ljava/time/format/TextStyle;->FULL_STANDALONE:Ljava/time/format/TextStyle;

    .line 70
    .line 71
    invoke-virtual {p0, p2, p1}, Ljava/time/Month;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    const-string p1, "getDisplayName(...)"

    .line 76
    .line 77
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_2
    const-string p1, "MMM"

    .line 82
    .line 83
    invoke-static {p1}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-virtual {p1, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_3
    if-eqz p2, :cond_4

    .line 96
    .line 97
    invoke-static {p0}, Lu7/b;->d(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :cond_4
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    sget-object p2, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 107
    .line 108
    sget-object p3, Ljava/time/chrono/IsoChronology;->INSTANCE:Ljava/time/chrono/IsoChronology;

    .line 109
    .line 110
    const/4 v1, 0x0

    .line 111
    invoke-static {p2, v1, p3, p1}, Ljava/time/format/DateTimeFormatterBuilder;->getLocalizedDateTimePattern(Ljava/time/format/FormatStyle;Ljava/time/format/FormatStyle;Ljava/time/chrono/Chronology;Ljava/util/Locale;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    const-string p3, "((\' de \')|[^dM]*)y[^dM]*"

    .line 119
    .line 120
    invoke-static {p3}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 121
    .line 122
    .line 123
    move-result-object p3

    .line 124
    const-string v1, "compile(...)"

    .line 125
    .line 126
    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const-string v1, ""

    .line 130
    .line 131
    invoke-virtual {p3, p2}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    invoke-virtual {p2, v1}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p2

    .line 139
    const-string p3, "replaceAll(...)"

    .line 140
    .line 141
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    new-instance p3, Ljava/time/format/DateTimeFormatterBuilder;

    .line 145
    .line 146
    invoke-direct {p3}, Ljava/time/format/DateTimeFormatterBuilder;-><init>()V

    .line 147
    .line 148
    .line 149
    invoke-virtual {p3, p2}, Ljava/time/format/DateTimeFormatterBuilder;->appendPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatterBuilder;

    .line 150
    .line 151
    .line 152
    move-result-object p2

    .line 153
    invoke-virtual {p2, p1}, Ljava/time/format/DateTimeFormatterBuilder;->toFormatter(Ljava/util/Locale;)Ljava/time/format/DateTimeFormatter;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-virtual {p1, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    return-object p0
.end method
