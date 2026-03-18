.class public final synthetic Lh2/f9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lgy0/e;

.field public final synthetic f:Lh2/u7;


# direct methods
.method public synthetic constructor <init>(Lgy0/e;Lh2/u7;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/f9;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/f9;->e:Lgy0/e;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/f9;->f:Lh2/u7;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lh2/f9;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    iget-object v3, p0, Lh2/f9;->f:Lh2/u7;

    .line 6
    .line 7
    iget-object p0, p0, Lh2/f9;->e:Lgy0/e;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    iget-object v0, v3, Lh2/u7;->e:Ll2/f1;

    .line 13
    .line 14
    iget-object v4, v3, Lh2/u7;->d:Ll2/f1;

    .line 15
    .line 16
    check-cast p1, Ljava/lang/Float;

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    iget v5, p0, Lgy0/e;->d:F

    .line 23
    .line 24
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 25
    .line 26
    .line 27
    move-result-object v6

    .line 28
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    iget p0, p0, Lgy0/e;->e:F

    .line 33
    .line 34
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 35
    .line 36
    .line 37
    move-result-object v7

    .line 38
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    invoke-static {p1, v6, v7}, Lkp/r9;->d(FFF)F

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    invoke-virtual {v3}, Lh2/u7;->d()I

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    if-lez v6, :cond_2

    .line 51
    .line 52
    invoke-virtual {v3}, Lh2/u7;->d()I

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    add-int/2addr v6, v1

    .line 57
    if-ltz v6, :cond_2

    .line 58
    .line 59
    move v8, p1

    .line 60
    move v9, v8

    .line 61
    move v7, v2

    .line 62
    :goto_0
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    .line 67
    .line 68
    .line 69
    move-result v10

    .line 70
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 71
    .line 72
    .line 73
    move-result-object v11

    .line 74
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 75
    .line 76
    .line 77
    move-result v11

    .line 78
    int-to-float v12, v7

    .line 79
    invoke-virtual {v3}, Lh2/u7;->d()I

    .line 80
    .line 81
    .line 82
    move-result v13

    .line 83
    add-int/2addr v13, v1

    .line 84
    int-to-float v13, v13

    .line 85
    div-float/2addr v12, v13

    .line 86
    invoke-static {v10, v11, v12}, Llp/wa;->b(FFF)F

    .line 87
    .line 88
    .line 89
    move-result v10

    .line 90
    sub-float v11, v10, p1

    .line 91
    .line 92
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    .line 93
    .line 94
    .line 95
    move-result v12

    .line 96
    cmpg-float v12, v12, v8

    .line 97
    .line 98
    if-gtz v12, :cond_0

    .line 99
    .line 100
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    move v9, v10

    .line 105
    :cond_0
    if-eq v7, v6, :cond_1

    .line 106
    .line 107
    add-int/lit8 v7, v7, 0x1

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_1
    move p1, v9

    .line 111
    :cond_2
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    cmpg-float p0, p1, p0

    .line 116
    .line 117
    if-nez p0, :cond_3

    .line 118
    .line 119
    move v1, v2

    .line 120
    goto :goto_2

    .line 121
    :cond_3
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    invoke-static {p1, p0}, Lh2/q9;->g(FF)J

    .line 126
    .line 127
    .line 128
    move-result-wide p0

    .line 129
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    invoke-static {v2, v0}, Lh2/q9;->g(FF)J

    .line 138
    .line 139
    .line 140
    move-result-wide v4

    .line 141
    sget v0, Lh2/r9;->c:I

    .line 142
    .line 143
    cmp-long v0, p0, v4

    .line 144
    .line 145
    if-nez v0, :cond_4

    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_4
    iget-object v0, v3, Lh2/u7;->f:Lay0/k;

    .line 149
    .line 150
    if-eqz v0, :cond_5

    .line 151
    .line 152
    new-instance v2, Lh2/r9;

    .line 153
    .line 154
    invoke-direct {v2, p0, p1}, Lh2/r9;-><init>(J)V

    .line 155
    .line 156
    .line 157
    invoke-interface {v0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_5
    invoke-static {p0, p1}, Lh2/r9;->b(J)F

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    invoke-virtual {v3, v0}, Lh2/u7;->h(F)V

    .line 166
    .line 167
    .line 168
    invoke-static {p0, p1}, Lh2/r9;->a(J)F

    .line 169
    .line 170
    .line 171
    move-result p0

    .line 172
    invoke-virtual {v3, p0}, Lh2/u7;->g(F)V

    .line 173
    .line 174
    .line 175
    :goto_1
    iget-object p0, v3, Lh2/u7;->b:Lay0/a;

    .line 176
    .line 177
    if-eqz p0, :cond_6

    .line 178
    .line 179
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    :cond_6
    :goto_2
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    return-object p0

    .line 187
    :pswitch_0
    iget-object v0, v3, Lh2/u7;->d:Ll2/f1;

    .line 188
    .line 189
    iget-object v4, v3, Lh2/u7;->e:Ll2/f1;

    .line 190
    .line 191
    check-cast p1, Ljava/lang/Float;

    .line 192
    .line 193
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 194
    .line 195
    .line 196
    move-result p1

    .line 197
    iget v5, p0, Lgy0/e;->d:F

    .line 198
    .line 199
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 200
    .line 201
    .line 202
    move-result-object v6

    .line 203
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    iget p0, p0, Lgy0/e;->e:F

    .line 208
    .line 209
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 210
    .line 211
    .line 212
    move-result-object v7

    .line 213
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 214
    .line 215
    .line 216
    move-result v7

    .line 217
    invoke-static {p1, v6, v7}, Lkp/r9;->d(FFF)F

    .line 218
    .line 219
    .line 220
    move-result p1

    .line 221
    invoke-virtual {v3}, Lh2/u7;->c()I

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    if-lez v6, :cond_9

    .line 226
    .line 227
    invoke-virtual {v3}, Lh2/u7;->c()I

    .line 228
    .line 229
    .line 230
    move-result v6

    .line 231
    add-int/2addr v6, v1

    .line 232
    if-ltz v6, :cond_9

    .line 233
    .line 234
    move v8, p1

    .line 235
    move v9, v8

    .line 236
    move v7, v2

    .line 237
    :goto_3
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 238
    .line 239
    .line 240
    move-result-object v10

    .line 241
    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    .line 242
    .line 243
    .line 244
    move-result v10

    .line 245
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 246
    .line 247
    .line 248
    move-result-object v11

    .line 249
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 250
    .line 251
    .line 252
    move-result v11

    .line 253
    int-to-float v12, v7

    .line 254
    invoke-virtual {v3}, Lh2/u7;->c()I

    .line 255
    .line 256
    .line 257
    move-result v13

    .line 258
    add-int/2addr v13, v1

    .line 259
    int-to-float v13, v13

    .line 260
    div-float/2addr v12, v13

    .line 261
    invoke-static {v10, v11, v12}, Llp/wa;->b(FFF)F

    .line 262
    .line 263
    .line 264
    move-result v10

    .line 265
    sub-float v11, v10, p1

    .line 266
    .line 267
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    .line 268
    .line 269
    .line 270
    move-result v12

    .line 271
    cmpg-float v12, v12, v8

    .line 272
    .line 273
    if-gtz v12, :cond_7

    .line 274
    .line 275
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    .line 276
    .line 277
    .line 278
    move-result v8

    .line 279
    move v9, v10

    .line 280
    :cond_7
    if-eq v7, v6, :cond_8

    .line 281
    .line 282
    add-int/lit8 v7, v7, 0x1

    .line 283
    .line 284
    goto :goto_3

    .line 285
    :cond_8
    move p1, v9

    .line 286
    :cond_9
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 287
    .line 288
    .line 289
    move-result p0

    .line 290
    cmpg-float p0, p1, p0

    .line 291
    .line 292
    if-nez p0, :cond_a

    .line 293
    .line 294
    move v1, v2

    .line 295
    goto :goto_5

    .line 296
    :cond_a
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 297
    .line 298
    .line 299
    move-result p0

    .line 300
    invoke-static {p0, p1}, Lh2/q9;->g(FF)J

    .line 301
    .line 302
    .line 303
    move-result-wide p0

    .line 304
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 305
    .line 306
    .line 307
    move-result v0

    .line 308
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 309
    .line 310
    .line 311
    move-result v2

    .line 312
    invoke-static {v0, v2}, Lh2/q9;->g(FF)J

    .line 313
    .line 314
    .line 315
    move-result-wide v4

    .line 316
    sget v0, Lh2/r9;->c:I

    .line 317
    .line 318
    cmp-long v0, p0, v4

    .line 319
    .line 320
    if-nez v0, :cond_b

    .line 321
    .line 322
    goto :goto_4

    .line 323
    :cond_b
    iget-object v0, v3, Lh2/u7;->f:Lay0/k;

    .line 324
    .line 325
    if-eqz v0, :cond_c

    .line 326
    .line 327
    new-instance v2, Lh2/r9;

    .line 328
    .line 329
    invoke-direct {v2, p0, p1}, Lh2/r9;-><init>(J)V

    .line 330
    .line 331
    .line 332
    invoke-interface {v0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    goto :goto_4

    .line 336
    :cond_c
    invoke-static {p0, p1}, Lh2/r9;->b(J)F

    .line 337
    .line 338
    .line 339
    move-result v0

    .line 340
    invoke-virtual {v3, v0}, Lh2/u7;->h(F)V

    .line 341
    .line 342
    .line 343
    invoke-static {p0, p1}, Lh2/r9;->a(J)F

    .line 344
    .line 345
    .line 346
    move-result p0

    .line 347
    invoke-virtual {v3, p0}, Lh2/u7;->g(F)V

    .line 348
    .line 349
    .line 350
    :goto_4
    iget-object p0, v3, Lh2/u7;->b:Lay0/a;

    .line 351
    .line 352
    if-eqz p0, :cond_d

    .line 353
    .line 354
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    :cond_d
    :goto_5
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 358
    .line 359
    .line 360
    move-result-object p0

    .line 361
    return-object p0

    .line 362
    nop

    .line 363
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
