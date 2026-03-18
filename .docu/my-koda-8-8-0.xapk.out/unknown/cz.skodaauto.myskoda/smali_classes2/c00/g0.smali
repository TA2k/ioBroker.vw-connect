.class public final Lc00/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/i0;


# direct methods
.method public synthetic constructor <init>(Lc00/i0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc00/g0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/g0;->e:Lc00/i0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lc00/g0;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lne0/t;

    .line 13
    .line 14
    instance-of v3, v2, Lne0/c;

    .line 15
    .line 16
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    iget-object v0, v0, Lc00/g0;->e:Lc00/i0;

    .line 19
    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    iget-object v0, v0, Lc00/i0;->m:Ljn0/c;

    .line 23
    .line 24
    check-cast v2, Lne0/c;

    .line 25
    .line 26
    invoke-virtual {v0, v2, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    if-ne v0, v1, :cond_1

    .line 33
    .line 34
    move-object v4, v0

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    instance-of v1, v2, Lne0/e;

    .line 37
    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lc00/d0;

    .line 45
    .line 46
    iget-object v2, v0, Lc00/i0;->j:Lij0/a;

    .line 47
    .line 48
    sget-object v3, Lcn0/a;->e:Lcn0/a;

    .line 49
    .line 50
    invoke-static {v1, v2, v3}, Ljp/dc;->c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    :goto_0
    return-object v4

    .line 58
    :cond_2
    new-instance v0, La8/r0;

    .line 59
    .line 60
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 61
    .line 62
    .line 63
    throw v0

    .line 64
    :pswitch_0
    move-object/from16 v2, p1

    .line 65
    .line 66
    check-cast v2, Lne0/t;

    .line 67
    .line 68
    instance-of v3, v2, Lne0/e;

    .line 69
    .line 70
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    iget-object v0, v0, Lc00/g0;->e:Lc00/i0;

    .line 73
    .line 74
    if-eqz v3, :cond_3

    .line 75
    .line 76
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    check-cast v1, Lc00/d0;

    .line 81
    .line 82
    iget-object v2, v0, Lc00/i0;->j:Lij0/a;

    .line 83
    .line 84
    sget-object v3, Lcn0/a;->f:Lcn0/a;

    .line 85
    .line 86
    invoke-static {v1, v2, v3}, Ljp/dc;->c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    instance-of v3, v2, Lne0/c;

    .line 95
    .line 96
    if-eqz v3, :cond_5

    .line 97
    .line 98
    iget-object v0, v0, Lc00/i0;->m:Ljn0/c;

    .line 99
    .line 100
    check-cast v2, Lne0/c;

    .line 101
    .line 102
    invoke-virtual {v0, v2, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    if-ne v0, v1, :cond_4

    .line 109
    .line 110
    move-object v4, v0

    .line 111
    :cond_4
    :goto_1
    return-object v4

    .line 112
    :cond_5
    new-instance v0, La8/r0;

    .line 113
    .line 114
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 115
    .line 116
    .line 117
    throw v0

    .line 118
    :pswitch_1
    move-object/from16 v2, p1

    .line 119
    .line 120
    check-cast v2, Lne0/t;

    .line 121
    .line 122
    instance-of v3, v2, Lne0/c;

    .line 123
    .line 124
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    iget-object v0, v0, Lc00/g0;->e:Lc00/i0;

    .line 127
    .line 128
    if-eqz v3, :cond_6

    .line 129
    .line 130
    iget-object v0, v0, Lc00/i0;->m:Ljn0/c;

    .line 131
    .line 132
    check-cast v2, Lne0/c;

    .line 133
    .line 134
    invoke-virtual {v0, v2, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 139
    .line 140
    if-ne v0, v1, :cond_7

    .line 141
    .line 142
    move-object v4, v0

    .line 143
    goto :goto_2

    .line 144
    :cond_6
    instance-of v1, v2, Lne0/e;

    .line 145
    .line 146
    if-eqz v1, :cond_8

    .line 147
    .line 148
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    check-cast v1, Lc00/d0;

    .line 153
    .line 154
    iget-object v2, v0, Lc00/i0;->j:Lij0/a;

    .line 155
    .line 156
    sget-object v3, Lcn0/a;->d:Lcn0/a;

    .line 157
    .line 158
    invoke-static {v1, v2, v3}, Ljp/dc;->c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 163
    .line 164
    .line 165
    :cond_7
    :goto_2
    return-object v4

    .line 166
    :cond_8
    new-instance v0, La8/r0;

    .line 167
    .line 168
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 169
    .line 170
    .line 171
    throw v0

    .line 172
    :pswitch_2
    move-object/from16 v2, p1

    .line 173
    .line 174
    check-cast v2, Lne0/t;

    .line 175
    .line 176
    instance-of v3, v2, Lne0/c;

    .line 177
    .line 178
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    iget-object v0, v0, Lc00/g0;->e:Lc00/i0;

    .line 181
    .line 182
    if-eqz v3, :cond_9

    .line 183
    .line 184
    iget-object v0, v0, Lc00/i0;->m:Ljn0/c;

    .line 185
    .line 186
    check-cast v2, Lne0/c;

    .line 187
    .line 188
    invoke-virtual {v0, v2, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 193
    .line 194
    if-ne v0, v1, :cond_a

    .line 195
    .line 196
    move-object v4, v0

    .line 197
    goto :goto_3

    .line 198
    :cond_9
    instance-of v1, v2, Lne0/e;

    .line 199
    .line 200
    if-eqz v1, :cond_b

    .line 201
    .line 202
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    check-cast v1, Lc00/d0;

    .line 207
    .line 208
    iget-object v2, v0, Lc00/i0;->j:Lij0/a;

    .line 209
    .line 210
    sget-object v3, Lcn0/a;->h:Lcn0/a;

    .line 211
    .line 212
    invoke-static {v1, v2, v3}, Ljp/dc;->c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 217
    .line 218
    .line 219
    :cond_a
    :goto_3
    return-object v4

    .line 220
    :cond_b
    new-instance v0, La8/r0;

    .line 221
    .line 222
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 223
    .line 224
    .line 225
    throw v0

    .line 226
    :pswitch_3
    move-object/from16 v1, p1

    .line 227
    .line 228
    check-cast v1, Lne0/s;

    .line 229
    .line 230
    iget-object v0, v0, Lc00/g0;->e:Lc00/i0;

    .line 231
    .line 232
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    move-object v3, v2

    .line 237
    check-cast v3, Lc00/d0;

    .line 238
    .line 239
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 240
    .line 241
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result v6

    .line 245
    const/16 v24, 0x0

    .line 246
    .line 247
    const v25, 0x3ffffb

    .line 248
    .line 249
    .line 250
    const/4 v4, 0x0

    .line 251
    const/4 v5, 0x0

    .line 252
    const/4 v7, 0x0

    .line 253
    const/4 v8, 0x0

    .line 254
    const/4 v9, 0x0

    .line 255
    const/4 v10, 0x0

    .line 256
    const/4 v11, 0x0

    .line 257
    const/4 v12, 0x0

    .line 258
    const/4 v13, 0x0

    .line 259
    const/4 v14, 0x0

    .line 260
    const/4 v15, 0x0

    .line 261
    const/16 v16, 0x0

    .line 262
    .line 263
    const/16 v17, 0x0

    .line 264
    .line 265
    const/16 v18, 0x0

    .line 266
    .line 267
    const/16 v19, 0x0

    .line 268
    .line 269
    const/16 v20, 0x0

    .line 270
    .line 271
    const/16 v21, 0x0

    .line 272
    .line 273
    const/16 v22, 0x0

    .line 274
    .line 275
    const/16 v23, 0x0

    .line 276
    .line 277
    invoke-static/range {v3 .. v25}, Lc00/d0;->a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;

    .line 278
    .line 279
    .line 280
    move-result-object v1

    .line 281
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 282
    .line 283
    .line 284
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    return-object v0

    .line 287
    :pswitch_4
    move-object/from16 v2, p1

    .line 288
    .line 289
    check-cast v2, Lne0/t;

    .line 290
    .line 291
    instance-of v3, v2, Lne0/e;

    .line 292
    .line 293
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 294
    .line 295
    iget-object v0, v0, Lc00/g0;->e:Lc00/i0;

    .line 296
    .line 297
    if-eqz v3, :cond_c

    .line 298
    .line 299
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    check-cast v1, Lc00/d0;

    .line 304
    .line 305
    iget-object v2, v0, Lc00/i0;->j:Lij0/a;

    .line 306
    .line 307
    sget-object v3, Lcn0/a;->g:Lcn0/a;

    .line 308
    .line 309
    invoke-static {v1, v2, v3}, Ljp/dc;->c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;

    .line 310
    .line 311
    .line 312
    move-result-object v1

    .line 313
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 314
    .line 315
    .line 316
    goto :goto_4

    .line 317
    :cond_c
    instance-of v3, v2, Lne0/c;

    .line 318
    .line 319
    if-eqz v3, :cond_e

    .line 320
    .line 321
    iget-object v0, v0, Lc00/i0;->m:Ljn0/c;

    .line 322
    .line 323
    check-cast v2, Lne0/c;

    .line 324
    .line 325
    invoke-virtual {v0, v2, v1}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 330
    .line 331
    if-ne v0, v1, :cond_d

    .line 332
    .line 333
    move-object v4, v0

    .line 334
    :cond_d
    :goto_4
    return-object v4

    .line 335
    :cond_e
    new-instance v0, La8/r0;

    .line 336
    .line 337
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 338
    .line 339
    .line 340
    throw v0

    .line 341
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
