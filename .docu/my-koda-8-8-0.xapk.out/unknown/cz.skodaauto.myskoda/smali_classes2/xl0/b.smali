.class public final Lxl0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lretrofit2/Response;

.field public final synthetic f:Lxl0/f;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lxl0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxl0/b;->e:Lretrofit2/Response;

    .line 4
    .line 5
    iput-object p2, p0, Lxl0/b;->f:Lxl0/f;

    .line 6
    .line 7
    iput-object p3, p0, Lxl0/b;->g:Lay0/k;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lxl0/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lxl0/b;

    .line 7
    .line 8
    iget-object v3, p0, Lxl0/b;->g:Lay0/k;

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    iget-object v1, p0, Lxl0/b;->e:Lretrofit2/Response;

    .line 12
    .line 13
    iget-object v2, p0, Lxl0/b;->f:Lxl0/f;

    .line 14
    .line 15
    move-object v4, p2

    .line 16
    invoke-direct/range {v0 .. v5}, Lxl0/b;-><init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    move-object v4, p2

    .line 21
    new-instance v1, Lxl0/b;

    .line 22
    .line 23
    move-object v5, v4

    .line 24
    iget-object v4, p0, Lxl0/b;->g:Lay0/k;

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    iget-object v2, p0, Lxl0/b;->e:Lretrofit2/Response;

    .line 28
    .line 29
    iget-object v3, p0, Lxl0/b;->f:Lxl0/f;

    .line 30
    .line 31
    invoke-direct/range {v1 .. v6}, Lxl0/b;-><init>(Lretrofit2/Response;Lxl0/f;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    return-object v1

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lxl0/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lxl0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lxl0/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lxl0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lxl0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lxl0/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lxl0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lxl0/b;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lxl0/b;->g:Lay0/k;

    .line 4
    .line 5
    iget-object v2, p0, Lxl0/b;->e:Lretrofit2/Response;

    .line 6
    .line 7
    iget-object p0, p0, Lxl0/b;->f:Lxl0/f;

    .line 8
    .line 9
    const-string v3, " "

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iget-object p1, v2, Lretrofit2/Response;->a:Ld01/t0;

    .line 20
    .line 21
    iget v4, p1, Ld01/t0;->g:I

    .line 22
    .line 23
    const/16 v0, 0x198

    .line 24
    .line 25
    const-string v5, " finished with unsuccessful http status code "

    .line 26
    .line 27
    const-string v6, "API request "

    .line 28
    .line 29
    const/4 v7, 0x0

    .line 30
    if-eq v4, v0, :cond_2

    .line 31
    .line 32
    const/16 v0, 0x1f8

    .line 33
    .line 34
    if-eq v4, v0, :cond_2

    .line 35
    .line 36
    iget-object p1, p1, Ld01/t0;->d:Ld01/k0;

    .line 37
    .line 38
    iget-object v0, p1, Ld01/k0;->b:Ljava/lang/String;

    .line 39
    .line 40
    iget-object p1, p1, Ld01/k0;->a:Ld01/a0;

    .line 41
    .line 42
    new-instance v8, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-direct {v8, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v8, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-eqz v1, :cond_1

    .line 67
    .line 68
    :try_start_0
    iget-object v0, v2, Lretrofit2/Response;->c:Ld01/v0;

    .line 69
    .line 70
    if-eqz v0, :cond_0

    .line 71
    .line 72
    invoke-virtual {v0}, Ld01/v0;->f()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 76
    goto :goto_2

    .line 77
    :catch_0
    move-exception v0

    .line 78
    goto :goto_1

    .line 79
    :cond_0
    :goto_0
    move-object v0, v7

    .line 80
    goto :goto_2

    .line 81
    :goto_1
    new-instance v3, Lu2/a;

    .line 82
    .line 83
    const/16 v5, 0x1c

    .line 84
    .line 85
    invoke-direct {v3, v0, v5}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {v7, p0, v3}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :goto_2
    if-eqz v0, :cond_1

    .line 93
    .line 94
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    move-object v7, v0

    .line 99
    check-cast v7, Lbm0/c;

    .line 100
    .line 101
    :cond_1
    new-instance v9, Lbm0/d;

    .line 102
    .line 103
    invoke-direct {v9, v4, p1, v7}, Lbm0/d;-><init>(ILjava/lang/String;Lbm0/c;)V

    .line 104
    .line 105
    .line 106
    invoke-static {p0, v2}, Lxl0/f;->a(Lxl0/f;Lretrofit2/Response;)Lne0/a;

    .line 107
    .line 108
    .line 109
    move-result-object v11

    .line 110
    sget-object v12, Lne0/b;->e:Lne0/b;

    .line 111
    .line 112
    new-instance v8, Lne0/c;

    .line 113
    .line 114
    const/4 v10, 0x0

    .line 115
    const/16 v13, 0xa

    .line 116
    .line 117
    invoke-direct/range {v8 .. v13}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 118
    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_2
    new-instance v0, Lne0/c;

    .line 122
    .line 123
    new-instance v1, Lbm0/a;

    .line 124
    .line 125
    new-instance p1, Lbm0/d;

    .line 126
    .line 127
    iget-object v4, v2, Lretrofit2/Response;->a:Ld01/t0;

    .line 128
    .line 129
    iget v8, v4, Ld01/t0;->g:I

    .line 130
    .line 131
    iget-object v4, v4, Ld01/t0;->d:Ld01/k0;

    .line 132
    .line 133
    iget-object v9, v4, Ld01/k0;->b:Ljava/lang/String;

    .line 134
    .line 135
    iget-object v4, v4, Ld01/k0;->a:Ld01/a0;

    .line 136
    .line 137
    new-instance v10, Ljava/lang/StringBuilder;

    .line 138
    .line 139
    invoke-direct {v10, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v10, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    invoke-direct {p1, v8, v3, v7}, Lbm0/d;-><init>(ILjava/lang/String;Lbm0/c;)V

    .line 162
    .line 163
    .line 164
    const-string v3, "Unable to proceed request."

    .line 165
    .line 166
    invoke-direct {v1, v3, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 167
    .line 168
    .line 169
    invoke-static {p0, v2}, Lxl0/f;->a(Lxl0/f;Lretrofit2/Response;)Lne0/a;

    .line 170
    .line 171
    .line 172
    move-result-object v3

    .line 173
    sget-object v4, Lne0/b;->f:Lne0/b;

    .line 174
    .line 175
    const/16 v5, 0xa

    .line 176
    .line 177
    const/4 v2, 0x0

    .line 178
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 179
    .line 180
    .line 181
    move-object v8, v0

    .line 182
    :goto_3
    return-object v8

    .line 183
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 184
    .line 185
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    iget-object p1, v2, Lretrofit2/Response;->b:Ljava/lang/Object;

    .line 189
    .line 190
    iget-object v4, v2, Lretrofit2/Response;->a:Ld01/t0;

    .line 191
    .line 192
    const-string v5, "message"

    .line 193
    .line 194
    if-eqz p1, :cond_3

    .line 195
    .line 196
    :try_start_1
    invoke-interface {v1, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    new-instance v0, Lne0/e;

    .line 201
    .line 202
    invoke-direct {v0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 203
    .line 204
    .line 205
    goto :goto_4

    .line 206
    :catch_1
    move-exception v0

    .line 207
    move-object p1, v0

    .line 208
    new-instance v6, Lne0/c;

    .line 209
    .line 210
    new-instance v7, La8/r0;

    .line 211
    .line 212
    iget-object v0, v4, Ld01/t0;->d:Ld01/k0;

    .line 213
    .line 214
    iget-object v1, v0, Ld01/k0;->b:Ljava/lang/String;

    .line 215
    .line 216
    iget-object v0, v0, Ld01/k0;->a:Ld01/a0;

    .line 217
    .line 218
    new-instance v4, Ljava/lang/StringBuilder;

    .line 219
    .line 220
    const-string v8, "Unable to parse response body of API request "

    .line 221
    .line 222
    invoke-direct {v4, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 226
    .line 227
    .line 228
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 232
    .line 233
    .line 234
    const-string v0, " to model class."

    .line 235
    .line 236
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    invoke-direct {v7, v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 247
    .line 248
    .line 249
    invoke-static {p0, v2}, Lxl0/f;->a(Lxl0/f;Lretrofit2/Response;)Lne0/a;

    .line 250
    .line 251
    .line 252
    move-result-object v9

    .line 253
    sget-object v10, Lne0/b;->e:Lne0/b;

    .line 254
    .line 255
    const/16 v11, 0xa

    .line 256
    .line 257
    const/4 v8, 0x0

    .line 258
    invoke-direct/range {v6 .. v11}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 259
    .line 260
    .line 261
    move-object v0, v6

    .line 262
    goto :goto_4

    .line 263
    :cond_3
    new-instance v0, Lne0/c;

    .line 264
    .line 265
    new-instance v1, La8/r0;

    .line 266
    .line 267
    iget-object p1, v4, Ld01/t0;->d:Ld01/k0;

    .line 268
    .line 269
    iget-object v4, p1, Ld01/k0;->b:Ljava/lang/String;

    .line 270
    .line 271
    iget-object p1, p1, Ld01/k0;->a:Ld01/a0;

    .line 272
    .line 273
    new-instance v6, Ljava/lang/StringBuilder;

    .line 274
    .line 275
    const-string v7, "API response of "

    .line 276
    .line 277
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 287
    .line 288
    .line 289
    const-string p1, " doesn\'t contain any body"

    .line 290
    .line 291
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object p1

    .line 298
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    invoke-direct {v1, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    invoke-static {p0, v2}, Lxl0/f;->a(Lxl0/f;Lretrofit2/Response;)Lne0/a;

    .line 305
    .line 306
    .line 307
    move-result-object v3

    .line 308
    sget-object v4, Lne0/b;->e:Lne0/b;

    .line 309
    .line 310
    const/16 v5, 0xa

    .line 311
    .line 312
    const/4 v2, 0x0

    .line 313
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 314
    .line 315
    .line 316
    :goto_4
    return-object v0

    .line 317
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
