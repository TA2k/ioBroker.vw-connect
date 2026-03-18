.class public final Ldi/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Lzg/h;

.field public synthetic f:Lah/h;

.field public synthetic g:Z

.field public synthetic h:Ljava/lang/Throwable;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldi/n;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Ldi/n;->d:I

    .line 2
    .line 3
    check-cast p1, Lzg/h;

    .line 4
    .line 5
    check-cast p2, Lah/h;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Boolean;

    .line 8
    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    check-cast p4, Ljava/lang/Throwable;

    .line 17
    .line 18
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 19
    .line 20
    new-instance p3, Ldi/n;

    .line 21
    .line 22
    const/4 v0, 0x5

    .line 23
    const/4 v1, 0x1

    .line 24
    invoke-direct {p3, v0, p5, v1}, Ldi/n;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    iput-object p1, p3, Ldi/n;->e:Lzg/h;

    .line 28
    .line 29
    iput-object p2, p3, Ldi/n;->f:Lah/h;

    .line 30
    .line 31
    iput-boolean p0, p3, Ldi/n;->g:Z

    .line 32
    .line 33
    iput-object p4, p3, Ldi/n;->h:Ljava/lang/Throwable;

    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    invoke-virtual {p3, p0}, Ldi/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :pswitch_0
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    check-cast p4, Ljava/lang/Throwable;

    .line 47
    .line 48
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 49
    .line 50
    new-instance p3, Ldi/n;

    .line 51
    .line 52
    const/4 v0, 0x5

    .line 53
    const/4 v1, 0x0

    .line 54
    invoke-direct {p3, v0, p5, v1}, Ldi/n;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    iput-object p1, p3, Ldi/n;->e:Lzg/h;

    .line 58
    .line 59
    iput-object p2, p3, Ldi/n;->f:Lah/h;

    .line 60
    .line 61
    iput-boolean p0, p3, Ldi/n;->g:Z

    .line 62
    .line 63
    iput-object p4, p3, Ldi/n;->h:Ljava/lang/Throwable;

    .line 64
    .line 65
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    invoke-virtual {p3, p0}, Ldi/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Ldi/n;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ldi/n;->e:Lzg/h;

    .line 12
    .line 13
    iget-object v5, p0, Ldi/n;->f:Lah/h;

    .line 14
    .line 15
    iget-boolean v6, p0, Ldi/n;->g:Z

    .line 16
    .line 17
    iget-object p0, p0, Ldi/n;->h:Ljava/lang/Throwable;

    .line 18
    .line 19
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    if-eqz v6, :cond_0

    .line 25
    .line 26
    new-instance p0, Llc/q;

    .line 27
    .line 28
    sget-object p1, Llc/a;->c:Llc/c;

    .line 29
    .line 30
    invoke-direct {p0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto/16 :goto_a

    .line 34
    .line 35
    :cond_0
    if-eqz p0, :cond_1

    .line 36
    .line 37
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    new-instance p1, Llc/q;

    .line 42
    .line 43
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object p0, p1

    .line 47
    goto/16 :goto_a

    .line 48
    .line 49
    :cond_1
    move-object p0, v0

    .line 50
    new-instance v0, Lei/d;

    .line 51
    .line 52
    if-eqz p0, :cond_2

    .line 53
    .line 54
    iget-object p1, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 55
    .line 56
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 57
    .line 58
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    goto :goto_0

    .line 63
    :cond_2
    move p1, v1

    .line 64
    :goto_0
    if-eqz p0, :cond_3

    .line 65
    .line 66
    iget-object v6, p0, Lzg/h;->e:Lzg/g;

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_3
    move-object v6, v4

    .line 70
    :goto_1
    sget-object v7, Lzg/g;->h:Lzg/g;

    .line 71
    .line 72
    if-eq v6, v7, :cond_4

    .line 73
    .line 74
    move-object v6, v2

    .line 75
    move v2, v3

    .line 76
    goto :goto_2

    .line 77
    :cond_4
    move-object v6, v2

    .line 78
    move v2, v1

    .line 79
    :goto_2
    if-eqz p0, :cond_5

    .line 80
    .line 81
    iget-object v7, p0, Lzg/h;->h:Ljava/lang/String;

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_5
    move-object v7, v4

    .line 85
    :goto_3
    if-nez v7, :cond_6

    .line 86
    .line 87
    move-object v7, v6

    .line 88
    :cond_6
    if-eqz v5, :cond_7

    .line 89
    .line 90
    iget-object v8, v5, Lah/h;->c:Lah/n;

    .line 91
    .line 92
    if-eqz v8, :cond_7

    .line 93
    .line 94
    iget-object v8, v8, Lah/n;->a:Ljava/lang/String;

    .line 95
    .line 96
    goto :goto_4

    .line 97
    :cond_7
    move-object v8, v4

    .line 98
    :goto_4
    if-nez v8, :cond_8

    .line 99
    .line 100
    move-object v8, v6

    .line 101
    :cond_8
    if-eqz v5, :cond_9

    .line 102
    .line 103
    iget-boolean v9, v5, Lah/h;->a:Z

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_9
    move v9, v1

    .line 107
    :goto_5
    if-eqz v5, :cond_a

    .line 108
    .line 109
    iget-object v10, v5, Lah/h;->e:Lah/c;

    .line 110
    .line 111
    if-eqz v10, :cond_a

    .line 112
    .line 113
    iget-object v10, v10, Lah/c;->b:Ljava/lang/String;

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_a
    move-object v10, v4

    .line 117
    :goto_6
    if-nez v10, :cond_b

    .line 118
    .line 119
    goto :goto_7

    .line 120
    :cond_b
    move-object v6, v10

    .line 121
    :goto_7
    if-eqz v5, :cond_c

    .line 122
    .line 123
    iget-object v5, v5, Lah/h;->b:Lah/g;

    .line 124
    .line 125
    goto :goto_8

    .line 126
    :cond_c
    move-object v5, v4

    .line 127
    :goto_8
    sget-object v10, Lah/g;->e:Lah/g;

    .line 128
    .line 129
    if-ne v5, v10, :cond_d

    .line 130
    .line 131
    goto :goto_9

    .line 132
    :cond_d
    move v3, v1

    .line 133
    :goto_9
    if-eqz p0, :cond_e

    .line 134
    .line 135
    iget-object v4, p0, Lzg/h;->o:Ljava/lang/String;

    .line 136
    .line 137
    :cond_e
    move v5, v9

    .line 138
    new-instance v9, Lei/c;

    .line 139
    .line 140
    if-eqz p0, :cond_f

    .line 141
    .line 142
    iget-object p0, p0, Lzg/h;->t:Lzg/q1;

    .line 143
    .line 144
    if-eqz p0, :cond_f

    .line 145
    .line 146
    iget-boolean v1, p0, Lzg/q1;->d:Z

    .line 147
    .line 148
    :cond_f
    invoke-direct {v9, v1}, Lei/c;-><init>(Z)V

    .line 149
    .line 150
    .line 151
    move-object v1, v7

    .line 152
    move v7, v3

    .line 153
    move-object v3, v1

    .line 154
    move-object v1, v8

    .line 155
    move-object v8, v4

    .line 156
    move-object v4, v1

    .line 157
    move v1, p1

    .line 158
    invoke-direct/range {v0 .. v9}, Lei/d;-><init>(ZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLjava/lang/String;Lei/c;)V

    .line 159
    .line 160
    .line 161
    new-instance p0, Llc/q;

    .line 162
    .line 163
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    :goto_a
    return-object p0

    .line 167
    :pswitch_0
    move-object v6, v2

    .line 168
    iget-object v0, p0, Ldi/n;->e:Lzg/h;

    .line 169
    .line 170
    iget-object v2, p0, Ldi/n;->f:Lah/h;

    .line 171
    .line 172
    iget-boolean v5, p0, Ldi/n;->g:Z

    .line 173
    .line 174
    iget-object p0, p0, Ldi/n;->h:Ljava/lang/Throwable;

    .line 175
    .line 176
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 177
    .line 178
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    if-eqz v5, :cond_10

    .line 182
    .line 183
    new-instance p0, Llc/q;

    .line 184
    .line 185
    sget-object p1, Llc/a;->c:Llc/c;

    .line 186
    .line 187
    invoke-direct {p0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    goto/16 :goto_16

    .line 191
    .line 192
    :cond_10
    if-eqz p0, :cond_11

    .line 193
    .line 194
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    new-instance p1, Llc/q;

    .line 199
    .line 200
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    move-object p0, p1

    .line 204
    goto/16 :goto_16

    .line 205
    .line 206
    :cond_11
    move-object p0, v0

    .line 207
    new-instance v0, Ldi/l;

    .line 208
    .line 209
    if-eqz p0, :cond_12

    .line 210
    .line 211
    iget-object p1, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 212
    .line 213
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 214
    .line 215
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result p1

    .line 219
    goto :goto_b

    .line 220
    :cond_12
    move p1, v1

    .line 221
    :goto_b
    if-eqz p0, :cond_13

    .line 222
    .line 223
    iget-object v5, p0, Lzg/h;->e:Lzg/g;

    .line 224
    .line 225
    goto :goto_c

    .line 226
    :cond_13
    move-object v5, v4

    .line 227
    :goto_c
    sget-object v7, Lzg/g;->h:Lzg/g;

    .line 228
    .line 229
    if-eq v5, v7, :cond_14

    .line 230
    .line 231
    move-object v5, v2

    .line 232
    move v2, v3

    .line 233
    goto :goto_d

    .line 234
    :cond_14
    move-object v5, v2

    .line 235
    move v2, v1

    .line 236
    :goto_d
    if-eqz p0, :cond_15

    .line 237
    .line 238
    iget-object v7, p0, Lzg/h;->h:Ljava/lang/String;

    .line 239
    .line 240
    goto :goto_e

    .line 241
    :cond_15
    move-object v7, v4

    .line 242
    :goto_e
    if-nez v7, :cond_16

    .line 243
    .line 244
    move-object v7, v6

    .line 245
    :cond_16
    if-eqz v5, :cond_17

    .line 246
    .line 247
    iget-object v8, v5, Lah/h;->c:Lah/n;

    .line 248
    .line 249
    if-eqz v8, :cond_17

    .line 250
    .line 251
    iget-object v8, v8, Lah/n;->a:Ljava/lang/String;

    .line 252
    .line 253
    goto :goto_f

    .line 254
    :cond_17
    move-object v8, v4

    .line 255
    :goto_f
    if-nez v8, :cond_18

    .line 256
    .line 257
    move-object v8, v6

    .line 258
    :cond_18
    if-eqz v5, :cond_19

    .line 259
    .line 260
    iget-boolean v9, v5, Lah/h;->a:Z

    .line 261
    .line 262
    goto :goto_10

    .line 263
    :cond_19
    move v9, v1

    .line 264
    :goto_10
    if-eqz v5, :cond_1a

    .line 265
    .line 266
    iget-object v10, v5, Lah/h;->e:Lah/c;

    .line 267
    .line 268
    if-eqz v10, :cond_1a

    .line 269
    .line 270
    iget-object v10, v10, Lah/c;->b:Ljava/lang/String;

    .line 271
    .line 272
    goto :goto_11

    .line 273
    :cond_1a
    move-object v10, v4

    .line 274
    :goto_11
    if-nez v10, :cond_1b

    .line 275
    .line 276
    move-object v10, v6

    .line 277
    :cond_1b
    if-eqz v5, :cond_1c

    .line 278
    .line 279
    iget-object v5, v5, Lah/h;->b:Lah/g;

    .line 280
    .line 281
    goto :goto_12

    .line 282
    :cond_1c
    move-object v5, v4

    .line 283
    :goto_12
    sget-object v11, Lah/g;->e:Lah/g;

    .line 284
    .line 285
    if-ne v5, v11, :cond_1d

    .line 286
    .line 287
    move v5, v3

    .line 288
    move-object v3, v7

    .line 289
    move v7, v5

    .line 290
    goto :goto_13

    .line 291
    :cond_1d
    move v5, v3

    .line 292
    move-object v3, v7

    .line 293
    move v7, v1

    .line 294
    :goto_13
    if-eqz p0, :cond_1e

    .line 295
    .line 296
    iget-object v11, p0, Lzg/h;->o:Ljava/lang/String;

    .line 297
    .line 298
    goto :goto_14

    .line 299
    :cond_1e
    move-object v11, v4

    .line 300
    :goto_14
    if-eqz p0, :cond_1f

    .line 301
    .line 302
    iget-object v12, p0, Lzg/h;->q:Lzg/h2;

    .line 303
    .line 304
    if-eqz v12, :cond_1f

    .line 305
    .line 306
    iget-object v4, v12, Lzg/h2;->d:Ljava/lang/String;

    .line 307
    .line 308
    :cond_1f
    if-nez v4, :cond_20

    .line 309
    .line 310
    move-object v4, v6

    .line 311
    :cond_20
    if-eqz p0, :cond_21

    .line 312
    .line 313
    iget-object p0, p0, Lzg/h;->q:Lzg/h2;

    .line 314
    .line 315
    if-eqz p0, :cond_21

    .line 316
    .line 317
    iget-boolean p0, p0, Lzg/h2;->e:Z

    .line 318
    .line 319
    if-ne p0, v5, :cond_21

    .line 320
    .line 321
    move v1, p1

    .line 322
    move-object v6, v10

    .line 323
    move v10, v5

    .line 324
    move v5, v9

    .line 325
    move-object v9, v4

    .line 326
    move-object v4, v8

    .line 327
    move-object v8, v11

    .line 328
    goto :goto_15

    .line 329
    :cond_21
    move v5, v9

    .line 330
    move-object v6, v10

    .line 331
    move v10, v1

    .line 332
    move-object v9, v4

    .line 333
    move-object v4, v8

    .line 334
    move-object v8, v11

    .line 335
    move v1, p1

    .line 336
    :goto_15
    invoke-direct/range {v0 .. v10}, Ldi/l;-><init>(ZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLjava/lang/String;Ljava/lang/String;Z)V

    .line 337
    .line 338
    .line 339
    new-instance p0, Llc/q;

    .line 340
    .line 341
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 342
    .line 343
    .line 344
    :goto_16
    return-object p0

    .line 345
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
