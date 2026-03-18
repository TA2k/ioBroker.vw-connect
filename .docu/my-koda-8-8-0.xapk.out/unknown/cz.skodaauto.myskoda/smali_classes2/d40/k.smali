.class public final Ld40/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Ld40/k;->d:I

    iput-object p2, p0, Ld40/k;->g:Ljava/lang/Object;

    iput-object p3, p0, Ld40/k;->h:Ljava/lang/Object;

    iput-object p4, p0, Ld40/k;->i:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p6, p0, Ld40/k;->d:I

    iput-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    iput-object p2, p0, Ld40/k;->g:Ljava/lang/Object;

    iput-object p3, p0, Ld40/k;->h:Ljava/lang/Object;

    iput-object p4, p0, Ld40/k;->i:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 3
    iput p6, p0, Ld40/k;->d:I

    iput-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    iput-object p2, p0, Ld40/k;->g:Ljava/lang/Object;

    iput-object p3, p0, Ld40/k;->i:Ljava/lang/Object;

    iput-object p4, p0, Ld40/k;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lxy/g;Laz/i;Ljava/lang/String;Lqp0/r;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/16 v0, 0xb

    iput v0, p0, Ld40/k;->d:I

    .line 4
    iput-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    iput-object p2, p0, Ld40/k;->h:Ljava/lang/Object;

    iput-object p3, p0, Ld40/k;->g:Ljava/lang/Object;

    iput-object p4, p0, Ld40/k;->i:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget v0, p0, Ld40/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Ld40/k;

    .line 7
    .line 8
    iget-object v0, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Lyk0/q;

    .line 12
    .line 13
    iget-object v0, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v0

    .line 16
    check-cast v3, Lxj0/f;

    .line 17
    .line 18
    iget-object v0, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lxj0/f;

    .line 22
    .line 23
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v5, p0

    .line 26
    check-cast v5, Ljava/util/List;

    .line 27
    .line 28
    const/16 v7, 0xc

    .line 29
    .line 30
    move-object v6, p1

    .line 31
    invoke-direct/range {v1 .. v7}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    return-object v1

    .line 35
    :pswitch_0
    move-object v7, p1

    .line 36
    new-instance v2, Ld40/k;

    .line 37
    .line 38
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v3, p1

    .line 41
    check-cast v3, Lxy/g;

    .line 42
    .line 43
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 44
    .line 45
    move-object v4, p1

    .line 46
    check-cast v4, Laz/i;

    .line 47
    .line 48
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v5, p1

    .line 51
    check-cast v5, Ljava/lang/String;

    .line 52
    .line 53
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v6, p0

    .line 56
    check-cast v6, Lqp0/r;

    .line 57
    .line 58
    invoke-direct/range {v2 .. v7}, Ld40/k;-><init>(Lxy/g;Laz/i;Ljava/lang/String;Lqp0/r;Lkotlin/coroutines/Continuation;)V

    .line 59
    .line 60
    .line 61
    return-object v2

    .line 62
    :pswitch_1
    move-object v7, p1

    .line 63
    new-instance v2, Ld40/k;

    .line 64
    .line 65
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v3, p1

    .line 68
    check-cast v3, Lwo0/e;

    .line 69
    .line 70
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 71
    .line 72
    move-object v4, p1

    .line 73
    check-cast v4, Ljava/lang/String;

    .line 74
    .line 75
    iget-object p1, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v5, p1

    .line 78
    check-cast v5, Ljava/util/ArrayList;

    .line 79
    .line 80
    iget-object p0, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v6, p0

    .line 83
    check-cast v6, Ljava/lang/String;

    .line 84
    .line 85
    const/16 v8, 0xa

    .line 86
    .line 87
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 88
    .line 89
    .line 90
    return-object v2

    .line 91
    :pswitch_2
    move-object v7, p1

    .line 92
    new-instance v2, Ld40/k;

    .line 93
    .line 94
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 95
    .line 96
    move-object v3, p1

    .line 97
    check-cast v3, Lnp0/c;

    .line 98
    .line 99
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 100
    .line 101
    move-object v4, p1

    .line 102
    check-cast v4, Ljava/lang/String;

    .line 103
    .line 104
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 105
    .line 106
    move-object v5, p1

    .line 107
    check-cast v5, Ljava/util/List;

    .line 108
    .line 109
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 110
    .line 111
    move-object v6, p0

    .line 112
    check-cast v6, Lqp0/s;

    .line 113
    .line 114
    const/16 v8, 0x9

    .line 115
    .line 116
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 117
    .line 118
    .line 119
    return-object v2

    .line 120
    :pswitch_3
    move-object v7, p1

    .line 121
    new-instance v2, Ld40/k;

    .line 122
    .line 123
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 124
    .line 125
    move-object v4, p1

    .line 126
    check-cast v4, Lm6/w;

    .line 127
    .line 128
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 129
    .line 130
    move-object v5, p1

    .line 131
    check-cast v5, Lpx0/g;

    .line 132
    .line 133
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 134
    .line 135
    move-object v6, p0

    .line 136
    check-cast v6, Lay0/n;

    .line 137
    .line 138
    const/16 v3, 0x8

    .line 139
    .line 140
    invoke-direct/range {v2 .. v7}, Ld40/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 141
    .line 142
    .line 143
    return-object v2

    .line 144
    :pswitch_4
    move-object v7, p1

    .line 145
    new-instance v2, Ld40/k;

    .line 146
    .line 147
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 148
    .line 149
    move-object v4, p1

    .line 150
    check-cast v4, Lkotlin/jvm/internal/f0;

    .line 151
    .line 152
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 153
    .line 154
    move-object v5, p1

    .line 155
    check-cast v5, Lm6/w;

    .line 156
    .line 157
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 158
    .line 159
    move-object v6, p0

    .line 160
    check-cast v6, Lkotlin/jvm/internal/d0;

    .line 161
    .line 162
    const/4 v3, 0x7

    .line 163
    invoke-direct/range {v2 .. v7}, Ld40/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 164
    .line 165
    .line 166
    return-object v2

    .line 167
    :pswitch_5
    move-object v7, p1

    .line 168
    new-instance v2, Ld40/k;

    .line 169
    .line 170
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 171
    .line 172
    move-object v3, p1

    .line 173
    check-cast v3, Ljz/m;

    .line 174
    .line 175
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 176
    .line 177
    move-object v4, p1

    .line 178
    check-cast v4, Ljava/lang/String;

    .line 179
    .line 180
    iget-object p1, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 181
    .line 182
    move-object v5, p1

    .line 183
    check-cast v5, Lmz/b;

    .line 184
    .line 185
    iget-object p0, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 186
    .line 187
    move-object v6, p0

    .line 188
    check-cast v6, Ljava/lang/String;

    .line 189
    .line 190
    const/4 v8, 0x6

    .line 191
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 192
    .line 193
    .line 194
    return-object v2

    .line 195
    :pswitch_6
    move-object v7, p1

    .line 196
    new-instance v2, Ld40/k;

    .line 197
    .line 198
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 199
    .line 200
    move-object v3, p1

    .line 201
    check-cast v3, Ljz/m;

    .line 202
    .line 203
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 204
    .line 205
    move-object v4, p1

    .line 206
    check-cast v4, Ljava/lang/String;

    .line 207
    .line 208
    iget-object p1, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 209
    .line 210
    move-object v5, p1

    .line 211
    check-cast v5, Ljava/util/List;

    .line 212
    .line 213
    iget-object p0, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 214
    .line 215
    move-object v6, p0

    .line 216
    check-cast v6, Ljava/lang/String;

    .line 217
    .line 218
    const/4 v8, 0x5

    .line 219
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 220
    .line 221
    .line 222
    return-object v2

    .line 223
    :pswitch_7
    move-object v7, p1

    .line 224
    new-instance v2, Ld40/k;

    .line 225
    .line 226
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 227
    .line 228
    move-object v3, p1

    .line 229
    check-cast v3, Lis0/d;

    .line 230
    .line 231
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 232
    .line 233
    move-object v4, p1

    .line 234
    check-cast v4, Ljava/lang/String;

    .line 235
    .line 236
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 237
    .line 238
    move-object v5, p1

    .line 239
    check-cast v5, Ljava/lang/String;

    .line 240
    .line 241
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 242
    .line 243
    move-object v6, p0

    .line 244
    check-cast v6, Ljava/lang/String;

    .line 245
    .line 246
    const/4 v8, 0x4

    .line 247
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 248
    .line 249
    .line 250
    return-object v2

    .line 251
    :pswitch_8
    move-object v7, p1

    .line 252
    new-instance v2, Ld40/k;

    .line 253
    .line 254
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 255
    .line 256
    move-object v3, p1

    .line 257
    check-cast v3, Li70/r;

    .line 258
    .line 259
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 260
    .line 261
    move-object v4, p1

    .line 262
    check-cast v4, Ljava/lang/String;

    .line 263
    .line 264
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 265
    .line 266
    move-object v5, p1

    .line 267
    check-cast v5, Ljava/lang/String;

    .line 268
    .line 269
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 270
    .line 271
    move-object v6, p0

    .line 272
    check-cast v6, Ll70/d;

    .line 273
    .line 274
    const/4 v8, 0x3

    .line 275
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 276
    .line 277
    .line 278
    return-object v2

    .line 279
    :pswitch_9
    move-object v7, p1

    .line 280
    new-instance v2, Ld40/k;

    .line 281
    .line 282
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 283
    .line 284
    move-object v3, p1

    .line 285
    check-cast v3, Ld40/n;

    .line 286
    .line 287
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 288
    .line 289
    move-object v4, p1

    .line 290
    check-cast v4, Ljava/lang/String;

    .line 291
    .line 292
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 293
    .line 294
    move-object v5, p1

    .line 295
    check-cast v5, Ljava/lang/String;

    .line 296
    .line 297
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 298
    .line 299
    move-object v6, p0

    .line 300
    check-cast v6, Lg40/j0;

    .line 301
    .line 302
    const/4 v8, 0x2

    .line 303
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 304
    .line 305
    .line 306
    return-object v2

    .line 307
    :pswitch_a
    move-object v7, p1

    .line 308
    new-instance v2, Ld40/k;

    .line 309
    .line 310
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 311
    .line 312
    move-object v3, p1

    .line 313
    check-cast v3, Ld40/n;

    .line 314
    .line 315
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 316
    .line 317
    move-object v4, p1

    .line 318
    check-cast v4, Ljava/lang/String;

    .line 319
    .line 320
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 321
    .line 322
    move-object v5, p1

    .line 323
    check-cast v5, Ljava/lang/String;

    .line 324
    .line 325
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 326
    .line 327
    move-object v6, p0

    .line 328
    check-cast v6, Ljava/lang/String;

    .line 329
    .line 330
    const/4 v8, 0x1

    .line 331
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 332
    .line 333
    .line 334
    return-object v2

    .line 335
    :pswitch_b
    move-object v7, p1

    .line 336
    new-instance v2, Ld40/k;

    .line 337
    .line 338
    iget-object p1, p0, Ld40/k;->f:Ljava/lang/Object;

    .line 339
    .line 340
    move-object v3, p1

    .line 341
    check-cast v3, Ld40/n;

    .line 342
    .line 343
    iget-object p1, p0, Ld40/k;->g:Ljava/lang/Object;

    .line 344
    .line 345
    move-object v4, p1

    .line 346
    check-cast v4, Ljava/lang/String;

    .line 347
    .line 348
    iget-object p1, p0, Ld40/k;->h:Ljava/lang/Object;

    .line 349
    .line 350
    move-object v5, p1

    .line 351
    check-cast v5, Ljava/lang/String;

    .line 352
    .line 353
    iget-object p0, p0, Ld40/k;->i:Ljava/lang/Object;

    .line 354
    .line 355
    move-object v6, p0

    .line 356
    check-cast v6, Lg40/a0;

    .line 357
    .line 358
    const/4 v8, 0x0

    .line 359
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 360
    .line 361
    .line 362
    return-object v2

    .line 363
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld40/k;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ld40/k;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ld40/k;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ld40/k;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Ld40/k;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_3
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Ld40/k;

    .line 65
    .line 66
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_4
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    check-cast p0, Ld40/k;

    .line 78
    .line 79
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_5
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, Ld40/k;

    .line 91
    .line 92
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :pswitch_6
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    check-cast p0, Ld40/k;

    .line 104
    .line 105
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :pswitch_7
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    check-cast p0, Ld40/k;

    .line 117
    .line 118
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_8
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    check-cast p0, Ld40/k;

    .line 130
    .line 131
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0

    .line 138
    :pswitch_9
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    check-cast p0, Ld40/k;

    .line 143
    .line 144
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0

    .line 151
    :pswitch_a
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    check-cast p0, Ld40/k;

    .line 156
    .line 157
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_b
    invoke-virtual {p0, p1}, Ld40/k;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    check-cast p0, Ld40/k;

    .line 169
    .line 170
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    invoke-virtual {p0, p1}, Ld40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0

    .line 177
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v8, p0

    .line 2
    .line 3
    iget v0, v8, Ld40/k;->d:I

    .line 4
    .line 5
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-spin-model-Spin$-spin$0"

    .line 6
    .line 7
    const/4 v2, 0x3

    .line 8
    const-string v3, "<this>"

    .line 9
    .line 10
    iget-object v6, v8, Ld40/k;->i:Ljava/lang/Object;

    .line 11
    .line 12
    const/4 v7, 0x2

    .line 13
    iget-object v9, v8, Ld40/k;->g:Ljava/lang/Object;

    .line 14
    .line 15
    const-string v10, "call to \'resume\' before \'invoke\' with coroutine"

    .line 16
    .line 17
    const/4 v11, 0x1

    .line 18
    iget-object v12, v8, Ld40/k;->h:Ljava/lang/Object;

    .line 19
    .line 20
    packed-switch v0, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    check-cast v12, Lxj0/f;

    .line 24
    .line 25
    sget-object v13, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    iget v0, v8, Ld40/k;->e:I

    .line 28
    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    if-eq v0, v11, :cond_1

    .line 32
    .line 33
    if-ne v0, v7, :cond_0

    .line 34
    .line 35
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    move-object/from16 v0, p1

    .line 39
    .line 40
    goto :goto_4

    .line 41
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw v0

    .line 47
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    move-object/from16 v0, p1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object v0, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Lyk0/q;

    .line 59
    .line 60
    iget-object v0, v0, Lyk0/q;->b:Lti0/a;

    .line 61
    .line 62
    iput v11, v8, Ld40/k;->e:I

    .line 63
    .line 64
    invoke-interface {v0, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    if-ne v0, v13, :cond_3

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_3
    :goto_0
    check-cast v0, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 72
    .line 73
    check-cast v9, Lxj0/f;

    .line 74
    .line 75
    iget-wide v1, v9, Lxj0/f;->a:D

    .line 76
    .line 77
    iget-wide v3, v9, Lxj0/f;->b:D

    .line 78
    .line 79
    if-eqz v12, :cond_4

    .line 80
    .line 81
    iget-wide v9, v12, Lxj0/f;->a:D

    .line 82
    .line 83
    new-instance v11, Ljava/lang/Double;

    .line 84
    .line 85
    invoke-direct {v11, v9, v10}, Ljava/lang/Double;-><init>(D)V

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_4
    const/4 v11, 0x0

    .line 90
    :goto_1
    if-eqz v12, :cond_5

    .line 91
    .line 92
    iget-wide v9, v12, Lxj0/f;->b:D

    .line 93
    .line 94
    new-instance v5, Ljava/lang/Double;

    .line 95
    .line 96
    invoke-direct {v5, v9, v10}, Ljava/lang/Double;-><init>(D)V

    .line 97
    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_5
    const/4 v5, 0x0

    .line 101
    :goto_2
    check-cast v6, Ljava/util/List;

    .line 102
    .line 103
    iput v7, v8, Ld40/k;->e:I

    .line 104
    .line 105
    move-object v7, v6

    .line 106
    move-object v6, v5

    .line 107
    move-object v5, v11

    .line 108
    invoke-interface/range {v0 .. v8}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getPlace(DDLjava/lang/Double;Ljava/lang/Double;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    if-ne v0, v13, :cond_6

    .line 113
    .line 114
    :goto_3
    move-object v0, v13

    .line 115
    :cond_6
    :goto_4
    return-object v0

    .line 116
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 117
    .line 118
    iget v1, v8, Ld40/k;->e:I

    .line 119
    .line 120
    if-eqz v1, :cond_9

    .line 121
    .line 122
    if-eq v1, v11, :cond_8

    .line 123
    .line 124
    if-ne v1, v7, :cond_7

    .line 125
    .line 126
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    move-object/from16 v0, p1

    .line 130
    .line 131
    goto/16 :goto_12

    .line 132
    .line 133
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 134
    .line 135
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw v0

    .line 139
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    move-object/from16 v1, p1

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v1, Lxy/g;

    .line 151
    .line 152
    iget-object v1, v1, Lxy/g;->b:Lti0/a;

    .line 153
    .line 154
    iput v11, v8, Ld40/k;->e:I

    .line 155
    .line 156
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    if-ne v1, v0, :cond_a

    .line 161
    .line 162
    goto/16 :goto_12

    .line 163
    .line 164
    :cond_a
    :goto_5
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 165
    .line 166
    check-cast v12, Laz/i;

    .line 167
    .line 168
    check-cast v9, Ljava/lang/String;

    .line 169
    .line 170
    check-cast v6, Lqp0/r;

    .line 171
    .line 172
    invoke-static {v12, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    const-string v2, "routeSettings"

    .line 176
    .line 177
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    iget-object v2, v12, Laz/i;->a:Laz/d;

    .line 181
    .line 182
    const-string v3, "LOCATION"

    .line 183
    .line 184
    if-eqz v2, :cond_c

    .line 185
    .line 186
    iget-object v10, v2, Laz/d;->b:Ljava/lang/String;

    .line 187
    .line 188
    iget-object v2, v2, Laz/d;->c:Lxj0/f;

    .line 189
    .line 190
    if-eqz v2, :cond_b

    .line 191
    .line 192
    new-instance v13, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 193
    .line 194
    iget-wide v14, v2, Lxj0/f;->a:D

    .line 195
    .line 196
    iget-wide v7, v2, Lxj0/f;->b:D

    .line 197
    .line 198
    invoke-direct {v13, v14, v15, v7, v8}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 199
    .line 200
    .line 201
    goto :goto_6

    .line 202
    :cond_b
    const/4 v13, 0x0

    .line 203
    :goto_6
    new-instance v2, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;

    .line 204
    .line 205
    invoke-direct {v2, v3, v10, v13}, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;-><init>(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)V

    .line 206
    .line 207
    .line 208
    goto :goto_7

    .line 209
    :cond_c
    const/4 v2, 0x0

    .line 210
    :goto_7
    iget-object v7, v12, Laz/i;->b:Laz/d;

    .line 211
    .line 212
    if-eqz v7, :cond_e

    .line 213
    .line 214
    iget-object v8, v7, Laz/d;->b:Ljava/lang/String;

    .line 215
    .line 216
    iget-object v7, v7, Laz/d;->c:Lxj0/f;

    .line 217
    .line 218
    if-eqz v7, :cond_d

    .line 219
    .line 220
    new-instance v10, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 221
    .line 222
    iget-wide v13, v7, Lxj0/f;->a:D

    .line 223
    .line 224
    iget-wide v4, v7, Lxj0/f;->b:D

    .line 225
    .line 226
    invoke-direct {v10, v13, v14, v4, v5}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 227
    .line 228
    .line 229
    goto :goto_8

    .line 230
    :cond_d
    const/4 v10, 0x0

    .line 231
    :goto_8
    new-instance v4, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;

    .line 232
    .line 233
    invoke-direct {v4, v3, v8, v10}, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;-><init>(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)V

    .line 234
    .line 235
    .line 236
    goto :goto_9

    .line 237
    :cond_e
    const/4 v4, 0x0

    .line 238
    :goto_9
    filled-new-array {v2, v4}, [Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;

    .line 239
    .line 240
    .line 241
    move-result-object v2

    .line 242
    invoke-static {v2}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    iget-boolean v3, v6, Lqp0/r;->g:Z

    .line 247
    .line 248
    new-instance v17, Lcz/myskoda/api/bff_maps/v3/BatteryLevelsDto;

    .line 249
    .line 250
    iget-object v4, v6, Lqp0/r;->e:Lqr0/l;

    .line 251
    .line 252
    if-eqz v4, :cond_f

    .line 253
    .line 254
    iget v4, v4, Lqr0/l;->d:I

    .line 255
    .line 256
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 257
    .line 258
    .line 259
    move-result-object v4

    .line 260
    move-object/from16 v18, v4

    .line 261
    .line 262
    goto :goto_a

    .line 263
    :cond_f
    const/16 v18, 0x0

    .line 264
    .line 265
    :goto_a
    iget-object v4, v6, Lqp0/r;->f:Lqr0/l;

    .line 266
    .line 267
    if-eqz v4, :cond_10

    .line 268
    .line 269
    iget v4, v4, Lqr0/l;->d:I

    .line 270
    .line 271
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 272
    .line 273
    .line 274
    move-result-object v4

    .line 275
    move-object/from16 v20, v4

    .line 276
    .line 277
    goto :goto_b

    .line 278
    :cond_10
    const/16 v20, 0x0

    .line 279
    .line 280
    :goto_b
    const/16 v21, 0x2

    .line 281
    .line 282
    const/16 v22, 0x0

    .line 283
    .line 284
    const/16 v19, 0x0

    .line 285
    .line 286
    invoke-direct/range {v17 .. v22}, Lcz/myskoda/api/bff_maps/v3/BatteryLevelsDto;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V

    .line 287
    .line 288
    .line 289
    move-object/from16 v4, v17

    .line 290
    .line 291
    iget-boolean v5, v6, Lqp0/r;->a:Z

    .line 292
    .line 293
    if-eqz v5, :cond_11

    .line 294
    .line 295
    const-string v5, "FERRIES"

    .line 296
    .line 297
    goto :goto_c

    .line 298
    :cond_11
    const/4 v5, 0x0

    .line 299
    :goto_c
    iget-boolean v7, v6, Lqp0/r;->b:Z

    .line 300
    .line 301
    if-eqz v7, :cond_12

    .line 302
    .line 303
    const-string v7, "MOTORWAYS"

    .line 304
    .line 305
    goto :goto_d

    .line 306
    :cond_12
    const/4 v7, 0x0

    .line 307
    :goto_d
    iget-boolean v8, v6, Lqp0/r;->c:Z

    .line 308
    .line 309
    if-eqz v8, :cond_13

    .line 310
    .line 311
    const-string v8, "TOLL_ROADS"

    .line 312
    .line 313
    goto :goto_e

    .line 314
    :cond_13
    const/4 v8, 0x0

    .line 315
    :goto_e
    iget-boolean v6, v6, Lqp0/r;->d:Z

    .line 316
    .line 317
    if-eqz v6, :cond_14

    .line 318
    .line 319
    const-string v6, "BORDER_CROSSINGS"

    .line 320
    .line 321
    goto :goto_f

    .line 322
    :cond_14
    const/4 v6, 0x0

    .line 323
    :goto_f
    filled-new-array {v5, v7, v8, v6}, [Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    invoke-static {v5}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 328
    .line 329
    .line 330
    move-result-object v5

    .line 331
    iget-object v6, v12, Laz/i;->c:Ljava/util/List;

    .line 332
    .line 333
    check-cast v6, Ljava/lang/Iterable;

    .line 334
    .line 335
    new-instance v7, Ljava/util/ArrayList;

    .line 336
    .line 337
    const/16 v15, 0xa

    .line 338
    .line 339
    invoke-static {v6, v15}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 340
    .line 341
    .line 342
    move-result v8

    .line 343
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 344
    .line 345
    .line 346
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 347
    .line 348
    .line 349
    move-result-object v6

    .line 350
    :goto_10
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 351
    .line 352
    .line 353
    move-result v8

    .line 354
    if-eqz v8, :cond_15

    .line 355
    .line 356
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v8

    .line 360
    check-cast v8, Laz/c;

    .line 361
    .line 362
    invoke-static {v8}, Llp/hf;->c(Laz/c;)Ljava/lang/String;

    .line 363
    .line 364
    .line 365
    move-result-object v8

    .line 366
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 367
    .line 368
    .line 369
    goto :goto_10

    .line 370
    :cond_15
    iget v6, v12, Laz/i;->d:I

    .line 371
    .line 372
    add-int/lit8 v18, v6, 0x1

    .line 373
    .line 374
    iget-boolean v6, v12, Laz/i;->g:Z

    .line 375
    .line 376
    iget-object v8, v12, Laz/i;->e:Ljava/util/List;

    .line 377
    .line 378
    check-cast v8, Ljava/lang/Iterable;

    .line 379
    .line 380
    new-instance v10, Ljava/util/ArrayList;

    .line 381
    .line 382
    const/16 v15, 0xa

    .line 383
    .line 384
    invoke-static {v8, v15}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 385
    .line 386
    .line 387
    move-result v11

    .line 388
    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 389
    .line 390
    .line 391
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 392
    .line 393
    .line 394
    move-result-object v8

    .line 395
    :goto_11
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 396
    .line 397
    .line 398
    move-result v11

    .line 399
    if-eqz v11, :cond_16

    .line 400
    .line 401
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v11

    .line 405
    check-cast v11, Laz/a;

    .line 406
    .line 407
    invoke-static {v11}, Llp/hf;->b(Laz/a;)Ljava/lang/String;

    .line 408
    .line 409
    .line 410
    move-result-object v11

    .line 411
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    goto :goto_11

    .line 415
    :cond_16
    iget-object v8, v12, Laz/i;->f:Laz/h;

    .line 416
    .line 417
    invoke-static {v8}, Llp/hf;->d(Laz/h;)Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v21

    .line 421
    iget-boolean v8, v12, Laz/i;->h:Z

    .line 422
    .line 423
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 424
    .line 425
    .line 426
    move-result-object v22

    .line 427
    new-instance v16, Lcz/myskoda/api/bff_maps/v3/AiStopoversDto;

    .line 428
    .line 429
    move/from16 v19, v6

    .line 430
    .line 431
    move-object/from16 v17, v7

    .line 432
    .line 433
    move-object/from16 v20, v10

    .line 434
    .line 435
    invoke-direct/range {v16 .. v22}, Lcz/myskoda/api/bff_maps/v3/AiStopoversDto;-><init>(Ljava/util/List;IZLjava/util/List;Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 436
    .line 437
    .line 438
    move-object/from16 v6, v16

    .line 439
    .line 440
    new-instance v7, Lcz/myskoda/api/bff_maps/v3/RoutePreferencesDto;

    .line 441
    .line 442
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 443
    .line 444
    .line 445
    move-result-object v3

    .line 446
    invoke-direct {v7, v3, v4, v6, v5}, Lcz/myskoda/api/bff_maps/v3/RoutePreferencesDto;-><init>(Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/BatteryLevelsDto;Lcz/myskoda/api/bff_maps/v3/AiStopoversDto;Ljava/util/List;)V

    .line 447
    .line 448
    .line 449
    new-instance v3, Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;

    .line 450
    .line 451
    invoke-direct {v3, v2, v9, v7}, Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;-><init>(Ljava/util/List;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/RoutePreferencesDto;)V

    .line 452
    .line 453
    .line 454
    const/4 v2, 0x2

    .line 455
    move-object/from16 v8, p0

    .line 456
    .line 457
    iput v2, v8, Ld40/k;->e:I

    .line 458
    .line 459
    invoke-interface {v1, v3, v8}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->calculateRoute(Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v1

    .line 463
    if-ne v1, v0, :cond_17

    .line 464
    .line 465
    goto :goto_12

    .line 466
    :cond_17
    move-object v0, v1

    .line 467
    :goto_12
    return-object v0

    .line 468
    :pswitch_1
    move v2, v7

    .line 469
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 470
    .line 471
    iget v1, v8, Ld40/k;->e:I

    .line 472
    .line 473
    if-eqz v1, :cond_1a

    .line 474
    .line 475
    if-eq v1, v11, :cond_19

    .line 476
    .line 477
    if-ne v1, v2, :cond_18

    .line 478
    .line 479
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 480
    .line 481
    .line 482
    move-object/from16 v0, p1

    .line 483
    .line 484
    goto :goto_15

    .line 485
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 486
    .line 487
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 488
    .line 489
    .line 490
    throw v0

    .line 491
    :cond_19
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 492
    .line 493
    .line 494
    move-object/from16 v1, p1

    .line 495
    .line 496
    goto :goto_13

    .line 497
    :cond_1a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 498
    .line 499
    .line 500
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 501
    .line 502
    check-cast v1, Lwo0/e;

    .line 503
    .line 504
    iget-object v1, v1, Lwo0/e;->b:Lti0/a;

    .line 505
    .line 506
    iput v11, v8, Ld40/k;->e:I

    .line 507
    .line 508
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v1

    .line 512
    if-ne v1, v0, :cond_1b

    .line 513
    .line 514
    goto :goto_15

    .line 515
    :cond_1b
    :goto_13
    check-cast v1, Lcz/myskoda/api/bff/v1/NotificationSubscriptionApi;

    .line 516
    .line 517
    check-cast v9, Ljava/lang/String;

    .line 518
    .line 519
    check-cast v6, Ljava/util/ArrayList;

    .line 520
    .line 521
    check-cast v12, Ljava/lang/String;

    .line 522
    .line 523
    new-instance v2, Ljava/util/ArrayList;

    .line 524
    .line 525
    const/16 v15, 0xa

    .line 526
    .line 527
    invoke-static {v6, v15}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 528
    .line 529
    .line 530
    move-result v3

    .line 531
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 532
    .line 533
    .line 534
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 535
    .line 536
    .line 537
    move-result-object v3

    .line 538
    :goto_14
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 539
    .line 540
    .line 541
    move-result v4

    .line 542
    if-eqz v4, :cond_1c

    .line 543
    .line 544
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 545
    .line 546
    .line 547
    move-result-object v4

    .line 548
    check-cast v4, Lap0/j;

    .line 549
    .line 550
    new-instance v5, Lcz/myskoda/api/bff/v1/NotificationServiceDto;

    .line 551
    .line 552
    iget-object v6, v4, Lap0/j;->a:Lap0/p;

    .line 553
    .line 554
    iget-object v6, v6, Lap0/p;->d:Ljava/lang/String;

    .line 555
    .line 556
    iget-boolean v7, v4, Lap0/j;->c:Z

    .line 557
    .line 558
    iget-object v4, v4, Lap0/j;->b:Ljava/lang/Boolean;

    .line 559
    .line 560
    invoke-direct {v5, v6, v7, v4}, Lcz/myskoda/api/bff/v1/NotificationServiceDto;-><init>(Ljava/lang/String;ZLjava/lang/Boolean;)V

    .line 561
    .line 562
    .line 563
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 564
    .line 565
    .line 566
    goto :goto_14

    .line 567
    :cond_1c
    new-instance v3, Lcz/myskoda/api/bff/v1/NotificationSettingsUpdateDto;

    .line 568
    .line 569
    invoke-direct {v3, v12, v2}, Lcz/myskoda/api/bff/v1/NotificationSettingsUpdateDto;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 570
    .line 571
    .line 572
    const/4 v2, 0x2

    .line 573
    iput v2, v8, Ld40/k;->e:I

    .line 574
    .line 575
    invoke-interface {v1, v9, v3, v8}, Lcz/myskoda/api/bff/v1/NotificationSubscriptionApi;->updateNotificationSettings(Ljava/lang/String;Lcz/myskoda/api/bff/v1/NotificationSettingsUpdateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 576
    .line 577
    .line 578
    move-result-object v1

    .line 579
    if-ne v1, v0, :cond_1d

    .line 580
    .line 581
    goto :goto_15

    .line 582
    :cond_1d
    move-object v0, v1

    .line 583
    :goto_15
    return-object v0

    .line 584
    :pswitch_2
    move v2, v7

    .line 585
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 586
    .line 587
    iget v1, v8, Ld40/k;->e:I

    .line 588
    .line 589
    if-eqz v1, :cond_20

    .line 590
    .line 591
    if-eq v1, v11, :cond_1f

    .line 592
    .line 593
    if-ne v1, v2, :cond_1e

    .line 594
    .line 595
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 596
    .line 597
    .line 598
    move-object/from16 v0, p1

    .line 599
    .line 600
    goto/16 :goto_1c

    .line 601
    .line 602
    :cond_1e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 603
    .line 604
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 605
    .line 606
    .line 607
    throw v0

    .line 608
    :cond_1f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 609
    .line 610
    .line 611
    move-object/from16 v1, p1

    .line 612
    .line 613
    goto :goto_16

    .line 614
    :cond_20
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 615
    .line 616
    .line 617
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 618
    .line 619
    check-cast v1, Lnp0/c;

    .line 620
    .line 621
    iget-object v1, v1, Lnp0/c;->b:Lti0/a;

    .line 622
    .line 623
    iput v11, v8, Ld40/k;->e:I

    .line 624
    .line 625
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 626
    .line 627
    .line 628
    move-result-object v1

    .line 629
    if-ne v1, v0, :cond_21

    .line 630
    .line 631
    goto/16 :goto_1c

    .line 632
    .line 633
    :cond_21
    :goto_16
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 634
    .line 635
    check-cast v9, Ljava/lang/String;

    .line 636
    .line 637
    if-nez v9, :cond_22

    .line 638
    .line 639
    const/4 v9, 0x0

    .line 640
    :cond_22
    check-cast v12, Ljava/util/List;

    .line 641
    .line 642
    check-cast v12, Ljava/lang/Iterable;

    .line 643
    .line 644
    new-instance v2, Ljava/util/ArrayList;

    .line 645
    .line 646
    const/16 v15, 0xa

    .line 647
    .line 648
    invoke-static {v12, v15}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 649
    .line 650
    .line 651
    move-result v4

    .line 652
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 653
    .line 654
    .line 655
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 656
    .line 657
    .line 658
    move-result-object v4

    .line 659
    :goto_17
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 660
    .line 661
    .line 662
    move-result v5

    .line 663
    if-eqz v5, :cond_24

    .line 664
    .line 665
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 666
    .line 667
    .line 668
    move-result-object v5

    .line 669
    check-cast v5, Lqp0/b0;

    .line 670
    .line 671
    sget-object v7, Lnp0/h;->a:Ljava/util/List;

    .line 672
    .line 673
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    iget-object v7, v5, Lqp0/b0;->a:Ljava/lang/String;

    .line 677
    .line 678
    iget-object v10, v5, Lqp0/b0;->c:Lqp0/t0;

    .line 679
    .line 680
    invoke-static {v10}, Lnp0/h;->a(Lqp0/t0;)Ljava/lang/String;

    .line 681
    .line 682
    .line 683
    move-result-object v10

    .line 684
    iget-object v5, v5, Lqp0/b0;->d:Lxj0/f;

    .line 685
    .line 686
    if-eqz v5, :cond_23

    .line 687
    .line 688
    new-instance v12, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 689
    .line 690
    iget-wide v13, v5, Lxj0/f;->a:D

    .line 691
    .line 692
    move-object/from16 p1, v4

    .line 693
    .line 694
    iget-wide v4, v5, Lxj0/f;->b:D

    .line 695
    .line 696
    invoke-direct {v12, v13, v14, v4, v5}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 697
    .line 698
    .line 699
    goto :goto_18

    .line 700
    :cond_23
    move-object/from16 p1, v4

    .line 701
    .line 702
    const/4 v12, 0x0

    .line 703
    :goto_18
    new-instance v4, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;

    .line 704
    .line 705
    invoke-direct {v4, v10, v7, v12}, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;-><init>(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)V

    .line 706
    .line 707
    .line 708
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 709
    .line 710
    .line 711
    move-object/from16 v4, p1

    .line 712
    .line 713
    goto :goto_17

    .line 714
    :cond_24
    check-cast v6, Lqp0/s;

    .line 715
    .line 716
    sget-object v3, Lnp0/h;->a:Ljava/util/List;

    .line 717
    .line 718
    iget-object v3, v6, Lqp0/s;->a:Lqp0/r;

    .line 719
    .line 720
    new-instance v17, Lcz/myskoda/api/bff_maps/v3/BatteryLevelsDto;

    .line 721
    .line 722
    iget-object v4, v3, Lqp0/r;->e:Lqr0/l;

    .line 723
    .line 724
    if-eqz v4, :cond_25

    .line 725
    .line 726
    iget v4, v4, Lqr0/l;->d:I

    .line 727
    .line 728
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 729
    .line 730
    .line 731
    move-result-object v4

    .line 732
    move-object/from16 v18, v4

    .line 733
    .line 734
    goto :goto_19

    .line 735
    :cond_25
    const/16 v18, 0x0

    .line 736
    .line 737
    :goto_19
    iget-object v4, v3, Lqp0/r;->f:Lqr0/l;

    .line 738
    .line 739
    if-eqz v4, :cond_26

    .line 740
    .line 741
    iget v4, v4, Lqr0/l;->d:I

    .line 742
    .line 743
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 744
    .line 745
    .line 746
    move-result-object v4

    .line 747
    move-object/from16 v20, v4

    .line 748
    .line 749
    goto :goto_1a

    .line 750
    :cond_26
    const/16 v20, 0x0

    .line 751
    .line 752
    :goto_1a
    const/16 v21, 0x2

    .line 753
    .line 754
    const/16 v22, 0x0

    .line 755
    .line 756
    const/16 v19, 0x0

    .line 757
    .line 758
    invoke-direct/range {v17 .. v22}, Lcz/myskoda/api/bff_maps/v3/BatteryLevelsDto;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V

    .line 759
    .line 760
    .line 761
    iget-boolean v4, v6, Lqp0/s;->b:Z

    .line 762
    .line 763
    if-eqz v4, :cond_27

    .line 764
    .line 765
    move-object/from16 v20, v17

    .line 766
    .line 767
    goto :goto_1b

    .line 768
    :cond_27
    const/16 v20, 0x0

    .line 769
    .line 770
    :goto_1b
    invoke-static {v3, v11}, Ljp/cg;->c(Lqp0/r;Z)Ljava/util/List;

    .line 771
    .line 772
    .line 773
    move-result-object v22

    .line 774
    iget-boolean v3, v3, Lqp0/r;->g:Z

    .line 775
    .line 776
    new-instance v18, Lcz/myskoda/api/bff_maps/v3/RoutePreferencesDto;

    .line 777
    .line 778
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 779
    .line 780
    .line 781
    move-result-object v19

    .line 782
    const/16 v23, 0x4

    .line 783
    .line 784
    const/16 v24, 0x0

    .line 785
    .line 786
    const/16 v21, 0x0

    .line 787
    .line 788
    invoke-direct/range {v18 .. v24}, Lcz/myskoda/api/bff_maps/v3/RoutePreferencesDto;-><init>(Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/BatteryLevelsDto;Lcz/myskoda/api/bff_maps/v3/AiStopoversDto;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    .line 789
    .line 790
    .line 791
    move-object/from16 v3, v18

    .line 792
    .line 793
    new-instance v4, Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;

    .line 794
    .line 795
    invoke-direct {v4, v2, v9, v3}, Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;-><init>(Ljava/util/List;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/RoutePreferencesDto;)V

    .line 796
    .line 797
    .line 798
    const/4 v2, 0x2

    .line 799
    iput v2, v8, Ld40/k;->e:I

    .line 800
    .line 801
    invoke-interface {v1, v4, v8}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->calculateRoute(Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 802
    .line 803
    .line 804
    move-result-object v1

    .line 805
    if-ne v1, v0, :cond_28

    .line 806
    .line 807
    goto :goto_1c

    .line 808
    :cond_28
    move-object v0, v1

    .line 809
    :goto_1c
    return-object v0

    .line 810
    :pswitch_3
    check-cast v9, Lm6/w;

    .line 811
    .line 812
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 813
    .line 814
    iget v1, v8, Ld40/k;->e:I

    .line 815
    .line 816
    if-eqz v1, :cond_2c

    .line 817
    .line 818
    if-eq v1, v11, :cond_2b

    .line 819
    .line 820
    const/4 v3, 0x2

    .line 821
    if-eq v1, v3, :cond_2a

    .line 822
    .line 823
    if-ne v1, v2, :cond_29

    .line 824
    .line 825
    iget-object v0, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 826
    .line 827
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 828
    .line 829
    .line 830
    goto :goto_20

    .line 831
    :cond_29
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 832
    .line 833
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 834
    .line 835
    .line 836
    throw v0

    .line 837
    :cond_2a
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 838
    .line 839
    check-cast v1, Lm6/d;

    .line 840
    .line 841
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 842
    .line 843
    .line 844
    move-object/from16 v3, p1

    .line 845
    .line 846
    goto :goto_1e

    .line 847
    :cond_2b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 848
    .line 849
    .line 850
    move-object/from16 v1, p1

    .line 851
    .line 852
    goto :goto_1d

    .line 853
    :cond_2c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 854
    .line 855
    .line 856
    iput v11, v8, Ld40/k;->e:I

    .line 857
    .line 858
    invoke-static {v9, v11, v8}, Lm6/w;->f(Lm6/w;ZLrx0/c;)Ljava/lang/Object;

    .line 859
    .line 860
    .line 861
    move-result-object v1

    .line 862
    if-ne v1, v0, :cond_2d

    .line 863
    .line 864
    goto :goto_20

    .line 865
    :cond_2d
    :goto_1d
    check-cast v1, Lm6/d;

    .line 866
    .line 867
    check-cast v12, Lpx0/g;

    .line 868
    .line 869
    new-instance v3, Lk31/t;

    .line 870
    .line 871
    check-cast v6, Lay0/n;

    .line 872
    .line 873
    const/16 v4, 0x14

    .line 874
    .line 875
    const/4 v5, 0x0

    .line 876
    invoke-direct {v3, v4, v6, v1, v5}, Lk31/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 877
    .line 878
    .line 879
    iput-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 880
    .line 881
    const/4 v4, 0x2

    .line 882
    iput v4, v8, Ld40/k;->e:I

    .line 883
    .line 884
    invoke-static {v12, v3, v8}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 885
    .line 886
    .line 887
    move-result-object v3

    .line 888
    if-ne v3, v0, :cond_2e

    .line 889
    .line 890
    goto :goto_20

    .line 891
    :cond_2e
    :goto_1e
    iget-object v4, v1, Lm6/d;->b:Ljava/lang/Object;

    .line 892
    .line 893
    if-eqz v4, :cond_2f

    .line 894
    .line 895
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 896
    .line 897
    .line 898
    move-result v4

    .line 899
    goto :goto_1f

    .line 900
    :cond_2f
    const/4 v4, 0x0

    .line 901
    :goto_1f
    iget v5, v1, Lm6/d;->c:I

    .line 902
    .line 903
    if-ne v4, v5, :cond_31

    .line 904
    .line 905
    iget-object v1, v1, Lm6/d;->b:Ljava/lang/Object;

    .line 906
    .line 907
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 908
    .line 909
    .line 910
    move-result v1

    .line 911
    if-nez v1, :cond_30

    .line 912
    .line 913
    iput-object v3, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 914
    .line 915
    iput v2, v8, Ld40/k;->e:I

    .line 916
    .line 917
    invoke-virtual {v9, v3, v11, v8}, Lm6/w;->j(Ljava/lang/Object;ZLrx0/c;)Ljava/lang/Object;

    .line 918
    .line 919
    .line 920
    move-result-object v1

    .line 921
    if-ne v1, v0, :cond_30

    .line 922
    .line 923
    goto :goto_20

    .line 924
    :cond_30
    move-object v0, v3

    .line 925
    :goto_20
    return-object v0

    .line 926
    :cond_31
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 927
    .line 928
    const-string v1, "Data in DataStore was mutated but DataStore is only compatible with Immutable types."

    .line 929
    .line 930
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 931
    .line 932
    .line 933
    throw v0

    .line 934
    :pswitch_4
    check-cast v6, Lkotlin/jvm/internal/d0;

    .line 935
    .line 936
    check-cast v9, Lkotlin/jvm/internal/f0;

    .line 937
    .line 938
    check-cast v12, Lm6/w;

    .line 939
    .line 940
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 941
    .line 942
    iget v1, v8, Ld40/k;->e:I

    .line 943
    .line 944
    if-eqz v1, :cond_35

    .line 945
    .line 946
    if-eq v1, v11, :cond_34

    .line 947
    .line 948
    const/4 v3, 0x2

    .line 949
    if-eq v1, v3, :cond_33

    .line 950
    .line 951
    if-ne v1, v2, :cond_32

    .line 952
    .line 953
    iget-object v0, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 954
    .line 955
    check-cast v0, Ljava/io/Serializable;

    .line 956
    .line 957
    move-object v6, v0

    .line 958
    check-cast v6, Lkotlin/jvm/internal/d0;

    .line 959
    .line 960
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 961
    .line 962
    .line 963
    move-object/from16 v1, p1

    .line 964
    .line 965
    goto :goto_23

    .line 966
    :cond_32
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 967
    .line 968
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 969
    .line 970
    .line 971
    throw v0

    .line 972
    :cond_33
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 973
    .line 974
    check-cast v1, Ljava/io/Serializable;

    .line 975
    .line 976
    check-cast v1, Lkotlin/jvm/internal/d0;

    .line 977
    .line 978
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lm6/b; {:try_start_0 .. :try_end_0} :catch_0

    .line 979
    .line 980
    .line 981
    move-object v3, v1

    .line 982
    move-object/from16 v1, p1

    .line 983
    .line 984
    goto :goto_22

    .line 985
    :cond_34
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 986
    .line 987
    check-cast v1, Ljava/io/Serializable;

    .line 988
    .line 989
    check-cast v1, Lkotlin/jvm/internal/f0;

    .line 990
    .line 991
    :try_start_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Lm6/b; {:try_start_1 .. :try_end_1} :catch_0

    .line 992
    .line 993
    .line 994
    move-object v3, v1

    .line 995
    move-object/from16 v1, p1

    .line 996
    .line 997
    goto :goto_21

    .line 998
    :cond_35
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 999
    .line 1000
    .line 1001
    :try_start_2
    iput-object v9, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1002
    .line 1003
    iput v11, v8, Ld40/k;->e:I

    .line 1004
    .line 1005
    invoke-virtual {v12, v8}, Lm6/w;->i(Lrx0/c;)Ljava/lang/Object;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v1

    .line 1009
    if-ne v1, v0, :cond_36

    .line 1010
    .line 1011
    goto :goto_25

    .line 1012
    :cond_36
    move-object v3, v9

    .line 1013
    :goto_21
    iput-object v1, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 1014
    .line 1015
    invoke-virtual {v12}, Lm6/w;->g()Lm6/i0;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v1

    .line 1019
    iput-object v6, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1020
    .line 1021
    const/4 v3, 0x2

    .line 1022
    iput v3, v8, Ld40/k;->e:I

    .line 1023
    .line 1024
    invoke-interface {v1, v8}, Lm6/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v1

    .line 1028
    if-ne v1, v0, :cond_37

    .line 1029
    .line 1030
    goto :goto_25

    .line 1031
    :cond_37
    move-object v3, v6

    .line 1032
    :goto_22
    check-cast v1, Ljava/lang/Number;

    .line 1033
    .line 1034
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1035
    .line 1036
    .line 1037
    move-result v1

    .line 1038
    iput v1, v3, Lkotlin/jvm/internal/d0;->d:I
    :try_end_2
    .catch Lm6/b; {:try_start_2 .. :try_end_2} :catch_0

    .line 1039
    .line 1040
    goto :goto_24

    .line 1041
    :catch_0
    iget-object v1, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 1042
    .line 1043
    iput-object v6, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1044
    .line 1045
    iput v2, v8, Ld40/k;->e:I

    .line 1046
    .line 1047
    invoke-virtual {v12, v1, v11, v8}, Lm6/w;->j(Ljava/lang/Object;ZLrx0/c;)Ljava/lang/Object;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v1

    .line 1051
    if-ne v1, v0, :cond_38

    .line 1052
    .line 1053
    goto :goto_25

    .line 1054
    :cond_38
    :goto_23
    check-cast v1, Ljava/lang/Number;

    .line 1055
    .line 1056
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1057
    .line 1058
    .line 1059
    move-result v0

    .line 1060
    iput v0, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 1061
    .line 1062
    :goto_24
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1063
    .line 1064
    :goto_25
    return-object v0

    .line 1065
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1066
    .line 1067
    iget v3, v8, Ld40/k;->e:I

    .line 1068
    .line 1069
    if-eqz v3, :cond_3b

    .line 1070
    .line 1071
    if-eq v3, v11, :cond_3a

    .line 1072
    .line 1073
    const/4 v4, 0x2

    .line 1074
    if-ne v3, v4, :cond_39

    .line 1075
    .line 1076
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1077
    .line 1078
    .line 1079
    move-object/from16 v0, p1

    .line 1080
    .line 1081
    goto/16 :goto_2d

    .line 1082
    .line 1083
    :cond_39
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1084
    .line 1085
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1086
    .line 1087
    .line 1088
    throw v0

    .line 1089
    :cond_3a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1090
    .line 1091
    .line 1092
    move-object/from16 v3, p1

    .line 1093
    .line 1094
    goto :goto_26

    .line 1095
    :cond_3b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1096
    .line 1097
    .line 1098
    iget-object v3, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1099
    .line 1100
    check-cast v3, Ljz/m;

    .line 1101
    .line 1102
    iget-object v3, v3, Ljz/m;->b:Lti0/a;

    .line 1103
    .line 1104
    iput v11, v8, Ld40/k;->e:I

    .line 1105
    .line 1106
    invoke-interface {v3, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v3

    .line 1110
    if-ne v3, v0, :cond_3c

    .line 1111
    .line 1112
    goto/16 :goto_2d

    .line 1113
    .line 1114
    :cond_3c
    :goto_26
    check-cast v3, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 1115
    .line 1116
    check-cast v9, Ljava/lang/String;

    .line 1117
    .line 1118
    check-cast v6, Lmz/b;

    .line 1119
    .line 1120
    check-cast v12, Ljava/lang/String;

    .line 1121
    .line 1122
    iget-wide v4, v6, Lmz/b;->b:J

    .line 1123
    .line 1124
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1125
    .line 1126
    .line 1127
    iget-object v1, v6, Lmz/b;->a:Lmz/a;

    .line 1128
    .line 1129
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 1130
    .line 1131
    .line 1132
    move-result v1

    .line 1133
    const-string v7, "Required value was null."

    .line 1134
    .line 1135
    if-eqz v1, :cond_42

    .line 1136
    .line 1137
    if-eq v1, v11, :cond_41

    .line 1138
    .line 1139
    const/4 v2, 0x2

    .line 1140
    if-ne v1, v2, :cond_40

    .line 1141
    .line 1142
    new-instance v16, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;

    .line 1143
    .line 1144
    sget v1, Lmy0/c;->g:I

    .line 1145
    .line 1146
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 1147
    .line 1148
    invoke-static {v4, v5, v1}, Lmy0/c;->n(JLmy0/e;)J

    .line 1149
    .line 1150
    .line 1151
    move-result-wide v1

    .line 1152
    long-to-int v1, v1

    .line 1153
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v18

    .line 1157
    iget-object v1, v6, Lmz/b;->d:Lqr0/q;

    .line 1158
    .line 1159
    if-eqz v1, :cond_3f

    .line 1160
    .line 1161
    iget-wide v4, v1, Lqr0/q;->a:D

    .line 1162
    .line 1163
    iget-object v1, v1, Lqr0/q;->b:Lqr0/r;

    .line 1164
    .line 1165
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 1166
    .line 1167
    .line 1168
    move-result v1

    .line 1169
    if-eqz v1, :cond_3e

    .line 1170
    .line 1171
    if-ne v1, v11, :cond_3d

    .line 1172
    .line 1173
    new-instance v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 1174
    .line 1175
    sget-object v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->FAHRENHEIT:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 1176
    .line 1177
    invoke-direct {v1, v4, v5, v2}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;-><init>(DLcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;)V

    .line 1178
    .line 1179
    .line 1180
    :goto_27
    move-object/from16 v20, v1

    .line 1181
    .line 1182
    goto :goto_28

    .line 1183
    :cond_3d
    new-instance v0, La8/r0;

    .line 1184
    .line 1185
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1186
    .line 1187
    .line 1188
    throw v0

    .line 1189
    :cond_3e
    new-instance v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 1190
    .line 1191
    sget-object v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->CELSIUS:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 1192
    .line 1193
    invoke-direct {v1, v4, v5, v2}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;-><init>(DLcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;)V

    .line 1194
    .line 1195
    .line 1196
    goto :goto_27

    .line 1197
    :goto_28
    const/16 v21, 0x4

    .line 1198
    .line 1199
    const/16 v22, 0x0

    .line 1200
    .line 1201
    const/16 v19, 0x0

    .line 1202
    .line 1203
    move-object/from16 v17, v12

    .line 1204
    .line 1205
    invoke-direct/range {v16 .. v22}, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;-><init>(Ljava/lang/String;Ljava/lang/Integer;Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;ILkotlin/jvm/internal/g;)V

    .line 1206
    .line 1207
    .line 1208
    :goto_29
    move-object/from16 v1, v16

    .line 1209
    .line 1210
    const/4 v2, 0x2

    .line 1211
    goto/16 :goto_2c

    .line 1212
    .line 1213
    :cond_3f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1214
    .line 1215
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1216
    .line 1217
    .line 1218
    throw v0

    .line 1219
    :cond_40
    new-instance v0, La8/r0;

    .line 1220
    .line 1221
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1222
    .line 1223
    .line 1224
    throw v0

    .line 1225
    :cond_41
    move-object/from16 v17, v12

    .line 1226
    .line 1227
    new-instance v16, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;

    .line 1228
    .line 1229
    sget v1, Lmy0/c;->g:I

    .line 1230
    .line 1231
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 1232
    .line 1233
    invoke-static {v4, v5, v1}, Lmy0/c;->n(JLmy0/e;)J

    .line 1234
    .line 1235
    .line 1236
    move-result-wide v1

    .line 1237
    long-to-int v1, v1

    .line 1238
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1239
    .line 1240
    .line 1241
    move-result-object v18

    .line 1242
    const/16 v21, 0xc

    .line 1243
    .line 1244
    const/16 v22, 0x0

    .line 1245
    .line 1246
    const/16 v19, 0x0

    .line 1247
    .line 1248
    const/16 v20, 0x0

    .line 1249
    .line 1250
    invoke-direct/range {v16 .. v22}, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;-><init>(Ljava/lang/String;Ljava/lang/Integer;Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;ILkotlin/jvm/internal/g;)V

    .line 1251
    .line 1252
    .line 1253
    goto :goto_29

    .line 1254
    :cond_42
    move-object/from16 v17, v12

    .line 1255
    .line 1256
    new-instance v16, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;

    .line 1257
    .line 1258
    sget v1, Lmy0/c;->g:I

    .line 1259
    .line 1260
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 1261
    .line 1262
    invoke-static {v4, v5, v1}, Lmy0/c;->n(JLmy0/e;)J

    .line 1263
    .line 1264
    .line 1265
    move-result-wide v4

    .line 1266
    long-to-int v1, v4

    .line 1267
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v18

    .line 1271
    iget-object v1, v6, Lmz/b;->c:Lmz/d;

    .line 1272
    .line 1273
    if-eqz v1, :cond_48

    .line 1274
    .line 1275
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 1276
    .line 1277
    .line 1278
    move-result v1

    .line 1279
    if-eqz v1, :cond_46

    .line 1280
    .line 1281
    if-eq v1, v11, :cond_45

    .line 1282
    .line 1283
    const/4 v4, 0x2

    .line 1284
    if-eq v1, v4, :cond_44

    .line 1285
    .line 1286
    if-ne v1, v2, :cond_43

    .line 1287
    .line 1288
    sget-object v1, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;->HEATING:Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;

    .line 1289
    .line 1290
    :goto_2a
    move-object/from16 v19, v1

    .line 1291
    .line 1292
    goto :goto_2b

    .line 1293
    :cond_43
    new-instance v0, La8/r0;

    .line 1294
    .line 1295
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1296
    .line 1297
    .line 1298
    throw v0

    .line 1299
    :cond_44
    sget-object v1, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;->HEATING:Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;

    .line 1300
    .line 1301
    goto :goto_2a

    .line 1302
    :cond_45
    sget-object v1, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;->VENTILATION:Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;

    .line 1303
    .line 1304
    goto :goto_2a

    .line 1305
    :cond_46
    sget-object v1, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;->HEATING:Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;

    .line 1306
    .line 1307
    goto :goto_2a

    .line 1308
    :goto_2b
    const/16 v21, 0x8

    .line 1309
    .line 1310
    const/16 v22, 0x0

    .line 1311
    .line 1312
    const/16 v20, 0x0

    .line 1313
    .line 1314
    invoke-direct/range {v16 .. v22}, Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;-><init>(Ljava/lang/String;Ljava/lang/Integer;Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto$StartMode;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;ILkotlin/jvm/internal/g;)V

    .line 1315
    .line 1316
    .line 1317
    goto :goto_29

    .line 1318
    :goto_2c
    iput v2, v8, Ld40/k;->e:I

    .line 1319
    .line 1320
    invoke-interface {v3, v9, v1, v8}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->startAuxiliaryHeating(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v1

    .line 1324
    if-ne v1, v0, :cond_47

    .line 1325
    .line 1326
    goto :goto_2d

    .line 1327
    :cond_47
    move-object v0, v1

    .line 1328
    :goto_2d
    return-object v0

    .line 1329
    :cond_48
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1330
    .line 1331
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1332
    .line 1333
    .line 1334
    throw v0

    .line 1335
    :pswitch_6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1336
    .line 1337
    iget v2, v8, Ld40/k;->e:I

    .line 1338
    .line 1339
    if-eqz v2, :cond_4b

    .line 1340
    .line 1341
    if-eq v2, v11, :cond_4a

    .line 1342
    .line 1343
    const/4 v3, 0x2

    .line 1344
    if-ne v2, v3, :cond_49

    .line 1345
    .line 1346
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1347
    .line 1348
    .line 1349
    move-object/from16 v0, p1

    .line 1350
    .line 1351
    goto :goto_30

    .line 1352
    :cond_49
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1353
    .line 1354
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1355
    .line 1356
    .line 1357
    throw v0

    .line 1358
    :cond_4a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1359
    .line 1360
    .line 1361
    move-object/from16 v2, p1

    .line 1362
    .line 1363
    goto :goto_2e

    .line 1364
    :cond_4b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1365
    .line 1366
    .line 1367
    iget-object v2, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1368
    .line 1369
    check-cast v2, Ljz/m;

    .line 1370
    .line 1371
    iget-object v2, v2, Ljz/m;->b:Lti0/a;

    .line 1372
    .line 1373
    iput v11, v8, Ld40/k;->e:I

    .line 1374
    .line 1375
    invoke-interface {v2, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v2

    .line 1379
    if-ne v2, v0, :cond_4c

    .line 1380
    .line 1381
    goto :goto_30

    .line 1382
    :cond_4c
    :goto_2e
    check-cast v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 1383
    .line 1384
    check-cast v9, Ljava/lang/String;

    .line 1385
    .line 1386
    check-cast v6, Ljava/util/List;

    .line 1387
    .line 1388
    check-cast v12, Ljava/lang/String;

    .line 1389
    .line 1390
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1391
    .line 1392
    .line 1393
    check-cast v6, Ljava/lang/Iterable;

    .line 1394
    .line 1395
    new-instance v1, Ljava/util/ArrayList;

    .line 1396
    .line 1397
    const/16 v15, 0xa

    .line 1398
    .line 1399
    invoke-static {v6, v15}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1400
    .line 1401
    .line 1402
    move-result v3

    .line 1403
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 1404
    .line 1405
    .line 1406
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v3

    .line 1410
    :goto_2f
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1411
    .line 1412
    .line 1413
    move-result v4

    .line 1414
    if-eqz v4, :cond_4d

    .line 1415
    .line 1416
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1417
    .line 1418
    .line 1419
    move-result-object v4

    .line 1420
    check-cast v4, Lao0/c;

    .line 1421
    .line 1422
    invoke-static {v4}, Lwn0/c;->a(Lao0/c;)Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v4

    .line 1426
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1427
    .line 1428
    .line 1429
    goto :goto_2f

    .line 1430
    :cond_4d
    new-instance v3, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;

    .line 1431
    .line 1432
    invoke-direct {v3, v12, v1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 1433
    .line 1434
    .line 1435
    const/4 v4, 0x2

    .line 1436
    iput v4, v8, Ld40/k;->e:I

    .line 1437
    .line 1438
    invoke-interface {v2, v9, v3, v8}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAuxiliaryHeatingTimers(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1439
    .line 1440
    .line 1441
    move-result-object v1

    .line 1442
    if-ne v1, v0, :cond_4e

    .line 1443
    .line 1444
    goto :goto_30

    .line 1445
    :cond_4e
    move-object v0, v1

    .line 1446
    :goto_30
    return-object v0

    .line 1447
    :pswitch_7
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1448
    .line 1449
    iget v1, v8, Ld40/k;->e:I

    .line 1450
    .line 1451
    if-eqz v1, :cond_50

    .line 1452
    .line 1453
    if-ne v1, v11, :cond_4f

    .line 1454
    .line 1455
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1456
    .line 1457
    .line 1458
    move-object/from16 v0, p1

    .line 1459
    .line 1460
    goto :goto_31

    .line 1461
    :cond_4f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1462
    .line 1463
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1464
    .line 1465
    .line 1466
    throw v0

    .line 1467
    :cond_50
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1468
    .line 1469
    .line 1470
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1471
    .line 1472
    check-cast v1, Lis0/d;

    .line 1473
    .line 1474
    iget-object v1, v1, Lis0/d;->c:Lcz/myskoda/api/vas/EnrollmentApi;

    .line 1475
    .line 1476
    check-cast v9, Ljava/lang/String;

    .line 1477
    .line 1478
    check-cast v12, Ljava/lang/String;

    .line 1479
    .line 1480
    new-instance v2, Lcz/myskoda/api/vas/CheckOneTimeKeyRequestDto;

    .line 1481
    .line 1482
    check-cast v6, Ljava/lang/String;

    .line 1483
    .line 1484
    invoke-direct {v2, v6}, Lcz/myskoda/api/vas/CheckOneTimeKeyRequestDto;-><init>(Ljava/lang/String;)V

    .line 1485
    .line 1486
    .line 1487
    iput v11, v8, Ld40/k;->e:I

    .line 1488
    .line 1489
    invoke-interface {v1, v9, v12, v2, v8}, Lcz/myskoda/api/vas/EnrollmentApi;->checkOneTimeKeyRequest(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/vas/CheckOneTimeKeyRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v1

    .line 1493
    if-ne v1, v0, :cond_51

    .line 1494
    .line 1495
    goto :goto_31

    .line 1496
    :cond_51
    move-object v0, v1

    .line 1497
    :goto_31
    return-object v0

    .line 1498
    :pswitch_8
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1499
    .line 1500
    iget v1, v8, Ld40/k;->e:I

    .line 1501
    .line 1502
    if-eqz v1, :cond_54

    .line 1503
    .line 1504
    if-eq v1, v11, :cond_53

    .line 1505
    .line 1506
    const/4 v2, 0x2

    .line 1507
    if-ne v1, v2, :cond_52

    .line 1508
    .line 1509
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1510
    .line 1511
    .line 1512
    move-object/from16 v0, p1

    .line 1513
    .line 1514
    goto :goto_33

    .line 1515
    :cond_52
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1516
    .line 1517
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1518
    .line 1519
    .line 1520
    throw v0

    .line 1521
    :cond_53
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1522
    .line 1523
    .line 1524
    move-object/from16 v1, p1

    .line 1525
    .line 1526
    goto :goto_32

    .line 1527
    :cond_54
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1528
    .line 1529
    .line 1530
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1531
    .line 1532
    check-cast v1, Li70/r;

    .line 1533
    .line 1534
    iget-object v1, v1, Li70/r;->b:Lti0/a;

    .line 1535
    .line 1536
    iput v11, v8, Ld40/k;->e:I

    .line 1537
    .line 1538
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1539
    .line 1540
    .line 1541
    move-result-object v1

    .line 1542
    if-ne v1, v0, :cond_55

    .line 1543
    .line 1544
    goto :goto_33

    .line 1545
    :cond_55
    :goto_32
    check-cast v1, Lcz/myskoda/api/bff/v1/TripStatisticsApi;

    .line 1546
    .line 1547
    check-cast v9, Ljava/lang/String;

    .line 1548
    .line 1549
    check-cast v12, Ljava/lang/String;

    .line 1550
    .line 1551
    check-cast v6, Ll70/d;

    .line 1552
    .line 1553
    invoke-static {v6, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1554
    .line 1555
    .line 1556
    new-instance v2, Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;

    .line 1557
    .line 1558
    iget-object v3, v6, Ll70/d;->c:Ljava/lang/String;

    .line 1559
    .line 1560
    iget-object v4, v6, Ll70/d;->b:Ljava/math/BigDecimal;

    .line 1561
    .line 1562
    invoke-virtual {v4}, Ljava/math/BigDecimal;->floatValue()F

    .line 1563
    .line 1564
    .line 1565
    move-result v4

    .line 1566
    iget-object v5, v6, Ll70/d;->d:Ll70/h;

    .line 1567
    .line 1568
    invoke-static {v5}, Llp/z9;->b(Ll70/h;)Ljava/lang/String;

    .line 1569
    .line 1570
    .line 1571
    move-result-object v5

    .line 1572
    iget-object v6, v6, Ll70/d;->e:Ljava/time/LocalDate;

    .line 1573
    .line 1574
    invoke-direct {v2, v3, v4, v5, v6}, Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;-><init>(Ljava/lang/String;FLjava/lang/String;Ljava/time/LocalDate;)V

    .line 1575
    .line 1576
    .line 1577
    const/4 v3, 0x2

    .line 1578
    iput v3, v8, Ld40/k;->e:I

    .line 1579
    .line 1580
    invoke-interface {v1, v9, v12, v2, v8}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->editFuelPrice(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1581
    .line 1582
    .line 1583
    move-result-object v1

    .line 1584
    if-ne v1, v0, :cond_56

    .line 1585
    .line 1586
    goto :goto_33

    .line 1587
    :cond_56
    move-object v0, v1

    .line 1588
    :goto_33
    return-object v0

    .line 1589
    :pswitch_9
    move v3, v7

    .line 1590
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1591
    .line 1592
    iget v1, v8, Ld40/k;->e:I

    .line 1593
    .line 1594
    if-eqz v1, :cond_59

    .line 1595
    .line 1596
    if-eq v1, v11, :cond_58

    .line 1597
    .line 1598
    if-ne v1, v3, :cond_57

    .line 1599
    .line 1600
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1601
    .line 1602
    .line 1603
    move-object/from16 v0, p1

    .line 1604
    .line 1605
    goto :goto_35

    .line 1606
    :cond_57
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1607
    .line 1608
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1609
    .line 1610
    .line 1611
    throw v0

    .line 1612
    :cond_58
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1613
    .line 1614
    .line 1615
    move-object/from16 v1, p1

    .line 1616
    .line 1617
    goto :goto_34

    .line 1618
    :cond_59
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1619
    .line 1620
    .line 1621
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1622
    .line 1623
    check-cast v1, Ld40/n;

    .line 1624
    .line 1625
    iget-object v1, v1, Ld40/n;->b:Lti0/a;

    .line 1626
    .line 1627
    iput v11, v8, Ld40/k;->e:I

    .line 1628
    .line 1629
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1630
    .line 1631
    .line 1632
    move-result-object v1

    .line 1633
    if-ne v1, v0, :cond_5a

    .line 1634
    .line 1635
    goto :goto_35

    .line 1636
    :cond_5a
    :goto_34
    check-cast v1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 1637
    .line 1638
    check-cast v9, Ljava/lang/String;

    .line 1639
    .line 1640
    check-cast v12, Ljava/lang/String;

    .line 1641
    .line 1642
    new-instance v2, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;

    .line 1643
    .line 1644
    invoke-direct {v2, v11}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;-><init>(Z)V

    .line 1645
    .line 1646
    .line 1647
    const/4 v3, 0x2

    .line 1648
    iput v3, v8, Ld40/k;->e:I

    .line 1649
    .line 1650
    invoke-interface {v1, v9, v12, v2, v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->updateLoyaltyMemberReward(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyRewardPatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1651
    .line 1652
    .line 1653
    move-result-object v1

    .line 1654
    if-ne v1, v0, :cond_5b

    .line 1655
    .line 1656
    goto :goto_35

    .line 1657
    :cond_5b
    move-object v0, v1

    .line 1658
    :goto_35
    return-object v0

    .line 1659
    :pswitch_a
    move v3, v7

    .line 1660
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1661
    .line 1662
    iget v1, v8, Ld40/k;->e:I

    .line 1663
    .line 1664
    if-eqz v1, :cond_5e

    .line 1665
    .line 1666
    if-eq v1, v11, :cond_5d

    .line 1667
    .line 1668
    if-ne v1, v3, :cond_5c

    .line 1669
    .line 1670
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1671
    .line 1672
    .line 1673
    move-object/from16 v0, p1

    .line 1674
    .line 1675
    goto :goto_37

    .line 1676
    :cond_5c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1677
    .line 1678
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1679
    .line 1680
    .line 1681
    throw v0

    .line 1682
    :cond_5d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1683
    .line 1684
    .line 1685
    move-object/from16 v1, p1

    .line 1686
    .line 1687
    goto :goto_36

    .line 1688
    :cond_5e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1689
    .line 1690
    .line 1691
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1692
    .line 1693
    check-cast v1, Ld40/n;

    .line 1694
    .line 1695
    iget-object v1, v1, Ld40/n;->b:Lti0/a;

    .line 1696
    .line 1697
    iput v11, v8, Ld40/k;->e:I

    .line 1698
    .line 1699
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1700
    .line 1701
    .line 1702
    move-result-object v1

    .line 1703
    if-ne v1, v0, :cond_5f

    .line 1704
    .line 1705
    goto :goto_37

    .line 1706
    :cond_5f
    :goto_36
    check-cast v1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 1707
    .line 1708
    check-cast v9, Ljava/lang/String;

    .line 1709
    .line 1710
    check-cast v12, Ljava/lang/String;

    .line 1711
    .line 1712
    check-cast v6, Ljava/lang/String;

    .line 1713
    .line 1714
    new-instance v2, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;

    .line 1715
    .line 1716
    invoke-direct {v2, v6}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;-><init>(Ljava/lang/String;)V

    .line 1717
    .line 1718
    .line 1719
    const/4 v3, 0x2

    .line 1720
    iput v3, v8, Ld40/k;->e:I

    .line 1721
    .line 1722
    invoke-interface {v1, v9, v12, v2, v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->enrollUserIntoLoyaltyChallenge(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1723
    .line 1724
    .line 1725
    move-result-object v1

    .line 1726
    if-ne v1, v0, :cond_60

    .line 1727
    .line 1728
    goto :goto_37

    .line 1729
    :cond_60
    move-object v0, v1

    .line 1730
    :goto_37
    return-object v0

    .line 1731
    :pswitch_b
    move v3, v7

    .line 1732
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1733
    .line 1734
    iget v1, v8, Ld40/k;->e:I

    .line 1735
    .line 1736
    if-eqz v1, :cond_63

    .line 1737
    .line 1738
    if-eq v1, v11, :cond_62

    .line 1739
    .line 1740
    if-ne v1, v3, :cond_61

    .line 1741
    .line 1742
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1743
    .line 1744
    .line 1745
    move-object/from16 v0, p1

    .line 1746
    .line 1747
    goto :goto_39

    .line 1748
    :cond_61
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1749
    .line 1750
    invoke-direct {v0, v10}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1751
    .line 1752
    .line 1753
    throw v0

    .line 1754
    :cond_62
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1755
    .line 1756
    .line 1757
    move-object/from16 v1, p1

    .line 1758
    .line 1759
    goto :goto_38

    .line 1760
    :cond_63
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1761
    .line 1762
    .line 1763
    iget-object v1, v8, Ld40/k;->f:Ljava/lang/Object;

    .line 1764
    .line 1765
    check-cast v1, Ld40/n;

    .line 1766
    .line 1767
    iget-object v1, v1, Ld40/n;->b:Lti0/a;

    .line 1768
    .line 1769
    iput v11, v8, Ld40/k;->e:I

    .line 1770
    .line 1771
    invoke-interface {v1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1772
    .line 1773
    .line 1774
    move-result-object v1

    .line 1775
    if-ne v1, v0, :cond_64

    .line 1776
    .line 1777
    goto :goto_39

    .line 1778
    :cond_64
    :goto_38
    check-cast v1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 1779
    .line 1780
    check-cast v9, Ljava/lang/String;

    .line 1781
    .line 1782
    check-cast v12, Ljava/lang/String;

    .line 1783
    .line 1784
    check-cast v6, Lg40/a0;

    .line 1785
    .line 1786
    new-instance v2, Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;

    .line 1787
    .line 1788
    iget-object v3, v6, Lg40/a0;->a:Ljava/lang/String;

    .line 1789
    .line 1790
    invoke-direct {v2, v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;-><init>(Ljava/lang/String;)V

    .line 1791
    .line 1792
    .line 1793
    const/4 v3, 0x2

    .line 1794
    iput v3, v8, Ld40/k;->e:I

    .line 1795
    .line 1796
    invoke-interface {v1, v9, v12, v2, v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->enrollUserIntoLoyaltyGame(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/GameEnrollmentRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1797
    .line 1798
    .line 1799
    move-result-object v1

    .line 1800
    if-ne v1, v0, :cond_65

    .line 1801
    .line 1802
    goto :goto_39

    .line 1803
    :cond_65
    move-object v0, v1

    .line 1804
    :goto_39
    return-object v0

    .line 1805
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
