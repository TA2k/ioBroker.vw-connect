.class public final Lf5/i;
.super Lf5/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final apply()V
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    iget-object v2, p0, Le5/h;->m0:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    iget-object v5, p0, Le5/h;->k0:Lz4/q;

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    invoke-virtual {v5, v4}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {v4}, Le5/b;->h()V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    const/4 v3, 0x0

    .line 37
    move-object v4, v3

    .line 38
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    const/16 v7, 0xc

    .line 43
    .line 44
    if-eqz v6, :cond_7

    .line 45
    .line 46
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    invoke-virtual {v5, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 51
    .line 52
    .line 53
    move-result-object v8

    .line 54
    const/16 v9, 0xa

    .line 55
    .line 56
    if-nez v4, :cond_3

    .line 57
    .line 58
    iget-object v4, p0, Le5/b;->R:Ljava/lang/Object;

    .line 59
    .line 60
    if-eqz v4, :cond_1

    .line 61
    .line 62
    invoke-virtual {v8, v4}, Le5/b;->p(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget v4, p0, Le5/b;->n:I

    .line 66
    .line 67
    invoke-virtual {v8, v4}, Le5/b;->k(I)Le5/b;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    iget v10, p0, Le5/b;->t:I

    .line 72
    .line 73
    invoke-virtual {v4, v10}, Le5/b;->m(I)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_1
    iget-object v4, p0, Le5/b;->S:Ljava/lang/Object;

    .line 78
    .line 79
    if-eqz v4, :cond_2

    .line 80
    .line 81
    iput v9, v8, Le5/b;->j0:I

    .line 82
    .line 83
    iput-object v4, v8, Le5/b;->S:Ljava/lang/Object;

    .line 84
    .line 85
    iget v4, p0, Le5/b;->n:I

    .line 86
    .line 87
    invoke-virtual {v8, v4}, Le5/b;->k(I)Le5/b;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    iget v10, p0, Le5/b;->t:I

    .line 92
    .line 93
    invoke-virtual {v4, v10}, Le5/b;->m(I)V

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_2
    iget-object v4, v8, Le5/b;->a:Ljava/lang/Object;

    .line 98
    .line 99
    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-virtual {v8, v1}, Le5/b;->p(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p0, v4}, Lf5/c;->w(Ljava/lang/String;)F

    .line 107
    .line 108
    .line 109
    move-result v10

    .line 110
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    invoke-virtual {v8, v10}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    invoke-virtual {p0, v4}, Lf5/c;->v(Ljava/lang/String;)F

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    invoke-virtual {v10, v4}, Le5/b;->n(Ljava/lang/Float;)V

    .line 127
    .line 128
    .line 129
    :goto_2
    move-object v4, v8

    .line 130
    :cond_3
    if-eqz v3, :cond_4

    .line 131
    .line 132
    iget-object v10, v3, Le5/b;->a:Ljava/lang/Object;

    .line 133
    .line 134
    invoke-virtual {v10}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v10

    .line 138
    iget-object v11, v8, Le5/b;->a:Ljava/lang/Object;

    .line 139
    .line 140
    invoke-virtual {v11}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v11

    .line 144
    iget-object v12, v8, Le5/b;->a:Ljava/lang/Object;

    .line 145
    .line 146
    iput v7, v3, Le5/b;->j0:I

    .line 147
    .line 148
    iput-object v12, v3, Le5/b;->U:Ljava/lang/Object;

    .line 149
    .line 150
    invoke-virtual {p0, v10}, Lf5/c;->u(Ljava/lang/String;)F

    .line 151
    .line 152
    .line 153
    move-result v7

    .line 154
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    invoke-virtual {v3, v7}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    invoke-virtual {p0, v10}, Lf5/c;->t(Ljava/lang/String;)F

    .line 163
    .line 164
    .line 165
    move-result v10

    .line 166
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 167
    .line 168
    .line 169
    move-result-object v10

    .line 170
    invoke-virtual {v7, v10}, Le5/b;->n(Ljava/lang/Float;)V

    .line 171
    .line 172
    .line 173
    iget-object v3, v3, Le5/b;->a:Ljava/lang/Object;

    .line 174
    .line 175
    iput v9, v8, Le5/b;->j0:I

    .line 176
    .line 177
    iput-object v3, v8, Le5/b;->S:Ljava/lang/Object;

    .line 178
    .line 179
    invoke-virtual {p0, v11}, Lf5/c;->w(Ljava/lang/String;)F

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    invoke-virtual {v8, v3}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 188
    .line 189
    .line 190
    move-result-object v3

    .line 191
    invoke-virtual {p0, v11}, Lf5/c;->v(Ljava/lang/String;)F

    .line 192
    .line 193
    .line 194
    move-result v7

    .line 195
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    invoke-virtual {v3, v7}, Le5/b;->n(Ljava/lang/Float;)V

    .line 200
    .line 201
    .line 202
    :cond_4
    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    iget-object v6, p0, Lf5/c;->o0:Ljava/util/HashMap;

    .line 207
    .line 208
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v7

    .line 212
    const/high16 v9, -0x40800000    # -1.0f

    .line 213
    .line 214
    if-eqz v7, :cond_5

    .line 215
    .line 216
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v3

    .line 220
    check-cast v3, Ljava/lang/Float;

    .line 221
    .line 222
    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    goto :goto_3

    .line 227
    :cond_5
    move v3, v9

    .line 228
    :goto_3
    cmpl-float v6, v3, v9

    .line 229
    .line 230
    if-eqz v6, :cond_6

    .line 231
    .line 232
    iput v3, v8, Le5/b;->g:F

    .line 233
    .line 234
    :cond_6
    move-object v3, v8

    .line 235
    goto/16 :goto_1

    .line 236
    .line 237
    :cond_7
    if-eqz v3, :cond_a

    .line 238
    .line 239
    iget-object v2, p0, Le5/b;->U:Ljava/lang/Object;

    .line 240
    .line 241
    if-eqz v2, :cond_8

    .line 242
    .line 243
    iput v7, v3, Le5/b;->j0:I

    .line 244
    .line 245
    iput-object v2, v3, Le5/b;->U:Ljava/lang/Object;

    .line 246
    .line 247
    iget v1, p0, Le5/b;->o:I

    .line 248
    .line 249
    invoke-virtual {v3, v1}, Le5/b;->k(I)Le5/b;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    iget v2, p0, Le5/b;->u:I

    .line 254
    .line 255
    invoke-virtual {v1, v2}, Le5/b;->m(I)V

    .line 256
    .line 257
    .line 258
    goto :goto_4

    .line 259
    :cond_8
    iget-object v2, p0, Le5/b;->V:Ljava/lang/Object;

    .line 260
    .line 261
    if-eqz v2, :cond_9

    .line 262
    .line 263
    invoke-virtual {v3, v2}, Le5/b;->e(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    iget v1, p0, Le5/b;->o:I

    .line 267
    .line 268
    invoke-virtual {v3, v1}, Le5/b;->k(I)Le5/b;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    iget v2, p0, Le5/b;->u:I

    .line 273
    .line 274
    invoke-virtual {v1, v2}, Le5/b;->m(I)V

    .line 275
    .line 276
    .line 277
    goto :goto_4

    .line 278
    :cond_9
    iget-object v2, v3, Le5/b;->a:Ljava/lang/Object;

    .line 279
    .line 280
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    invoke-virtual {v3, v1}, Le5/b;->e(Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {p0, v2}, Lf5/c;->u(Ljava/lang/String;)F

    .line 288
    .line 289
    .line 290
    move-result v1

    .line 291
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    invoke-virtual {v3, v1}, Le5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 296
    .line 297
    .line 298
    move-result-object v1

    .line 299
    invoke-virtual {p0, v2}, Lf5/c;->t(Ljava/lang/String;)F

    .line 300
    .line 301
    .line 302
    move-result v2

    .line 303
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 304
    .line 305
    .line 306
    move-result-object v2

    .line 307
    invoke-virtual {v1, v2}, Le5/b;->n(Ljava/lang/Float;)V

    .line 308
    .line 309
    .line 310
    :cond_a
    :goto_4
    if-nez v4, :cond_b

    .line 311
    .line 312
    goto :goto_5

    .line 313
    :cond_b
    iget v1, p0, Lf5/c;->n0:F

    .line 314
    .line 315
    const/high16 v2, 0x3f000000    # 0.5f

    .line 316
    .line 317
    cmpl-float v2, v1, v2

    .line 318
    .line 319
    if-eqz v2, :cond_c

    .line 320
    .line 321
    iput v1, v4, Le5/b;->i:F

    .line 322
    .line 323
    :cond_c
    iget-object p0, p0, Lf5/c;->t0:Le5/j;

    .line 324
    .line 325
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 326
    .line 327
    .line 328
    move-result p0

    .line 329
    if-eqz p0, :cond_f

    .line 330
    .line 331
    const/4 v0, 0x1

    .line 332
    if-eq p0, v0, :cond_e

    .line 333
    .line 334
    const/4 v0, 0x2

    .line 335
    if-eq p0, v0, :cond_d

    .line 336
    .line 337
    :goto_5
    return-void

    .line 338
    :cond_d
    iput v0, v4, Le5/b;->e:I

    .line 339
    .line 340
    return-void

    .line 341
    :cond_e
    iput v0, v4, Le5/b;->e:I

    .line 342
    .line 343
    return-void

    .line 344
    :cond_f
    iput v0, v4, Le5/b;->e:I

    .line 345
    .line 346
    return-void
.end method
