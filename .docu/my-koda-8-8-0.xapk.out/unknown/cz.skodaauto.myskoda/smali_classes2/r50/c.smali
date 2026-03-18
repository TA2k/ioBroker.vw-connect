.class public final Lr50/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lk21/a;

.field public g:Lk21/a;


# direct methods
.method public synthetic constructor <init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lr50/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr50/c;->f:Lk21/a;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lr50/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr50/c;

    .line 7
    .line 8
    iget-object p0, p0, Lr50/c;->f:Lk21/a;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lr50/c;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lr50/c;

    .line 16
    .line 17
    iget-object p0, p0, Lr50/c;->f:Lk21/a;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lr50/c;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lr50/c;

    .line 25
    .line 26
    iget-object p0, p0, Lr50/c;->f:Lk21/a;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lr50/c;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lr50/c;

    .line 34
    .line 35
    iget-object p0, p0, Lr50/c;->f:Lk21/a;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lr50/c;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lr50/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr50/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr50/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr50/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr50/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr50/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr50/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lr50/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lr50/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lr50/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lr50/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lr50/c;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lr50/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lr50/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lr50/c;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lr50/c;->g:Lk21/a;

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 33
    .line 34
    const-string v1, "[bff-api-auth-no-logging]"

    .line 35
    .line 36
    const-class v3, Ld01/h0;

    .line 37
    .line 38
    invoke-static {p1, v3, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    const-class v3, Lti0/a;

    .line 43
    .line 44
    invoke-virtual {p1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget-object v3, p0, Lr50/c;->f:Lk21/a;

    .line 49
    .line 50
    const/4 v4, 0x0

    .line 51
    invoke-virtual {v3, p1, v1, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    check-cast p1, Lti0/a;

    .line 56
    .line 57
    iput-object v3, p0, Lr50/c;->g:Lk21/a;

    .line 58
    .line 59
    iput v2, p0, Lr50/c;->e:I

    .line 60
    .line 61
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v0, :cond_2

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    move-object p0, v3

    .line 69
    :goto_0
    check-cast p1, Ld01/h0;

    .line 70
    .line 71
    invoke-static {p0, p1}, Lzl0/b;->c(Lk21/a;Ld01/h0;)Lretrofit2/Retrofit;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    :goto_1
    return-object v0

    .line 76
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    iget v1, p0, Lr50/c;->e:I

    .line 79
    .line 80
    const/4 v2, 0x1

    .line 81
    if-eqz v1, :cond_4

    .line 82
    .line 83
    if-ne v1, v2, :cond_3

    .line 84
    .line 85
    iget-object p0, p0, Lr50/c;->g:Lk21/a;

    .line 86
    .line 87
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 92
    .line 93
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 94
    .line 95
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 103
    .line 104
    const-string v1, "[bff-api-auth]"

    .line 105
    .line 106
    const-class v3, Ld01/h0;

    .line 107
    .line 108
    invoke-static {p1, v3, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    const-class v3, Lti0/a;

    .line 113
    .line 114
    invoke-virtual {p1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    iget-object v3, p0, Lr50/c;->f:Lk21/a;

    .line 119
    .line 120
    const/4 v4, 0x0

    .line 121
    invoke-virtual {v3, p1, v1, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    check-cast p1, Lti0/a;

    .line 126
    .line 127
    iput-object v3, p0, Lr50/c;->g:Lk21/a;

    .line 128
    .line 129
    iput v2, p0, Lr50/c;->e:I

    .line 130
    .line 131
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    if-ne p1, v0, :cond_5

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_5
    move-object p0, v3

    .line 139
    :goto_2
    check-cast p1, Ld01/h0;

    .line 140
    .line 141
    invoke-static {p0, p1}, Lzl0/b;->c(Lk21/a;Ld01/h0;)Lretrofit2/Retrofit;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    :goto_3
    return-object v0

    .line 146
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 147
    .line 148
    iget v1, p0, Lr50/c;->e:I

    .line 149
    .line 150
    const/4 v2, 0x1

    .line 151
    if-eqz v1, :cond_7

    .line 152
    .line 153
    if-ne v1, v2, :cond_6

    .line 154
    .line 155
    iget-object p0, p0, Lr50/c;->g:Lk21/a;

    .line 156
    .line 157
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 162
    .line 163
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 164
    .line 165
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p0

    .line 169
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 173
    .line 174
    const-string v1, "[bff-api-no-auth]"

    .line 175
    .line 176
    const-class v3, Ld01/h0;

    .line 177
    .line 178
    invoke-static {p1, v3, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    const-class v3, Lti0/a;

    .line 183
    .line 184
    invoke-virtual {p1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    iget-object v3, p0, Lr50/c;->f:Lk21/a;

    .line 189
    .line 190
    const/4 v4, 0x0

    .line 191
    invoke-virtual {v3, p1, v1, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    check-cast p1, Lti0/a;

    .line 196
    .line 197
    iput-object v3, p0, Lr50/c;->g:Lk21/a;

    .line 198
    .line 199
    iput v2, p0, Lr50/c;->e:I

    .line 200
    .line 201
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    if-ne p1, v0, :cond_8

    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_8
    move-object p0, v3

    .line 209
    :goto_4
    check-cast p1, Ld01/h0;

    .line 210
    .line 211
    invoke-static {p0, p1}, Lzl0/b;->c(Lk21/a;Ld01/h0;)Lretrofit2/Retrofit;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    :goto_5
    return-object v0

    .line 216
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 217
    .line 218
    iget v1, p0, Lr50/c;->e:I

    .line 219
    .line 220
    const/4 v2, 0x1

    .line 221
    const/4 v3, 0x0

    .line 222
    if-eqz v1, :cond_a

    .line 223
    .line 224
    if-ne v1, v2, :cond_9

    .line 225
    .line 226
    iget-object p0, p0, Lr50/c;->g:Lk21/a;

    .line 227
    .line 228
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    move-object v4, p0

    .line 232
    goto :goto_6

    .line 233
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 234
    .line 235
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 236
    .line 237
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    throw p0

    .line 241
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    const-class p1, Lam0/f;

    .line 245
    .line 246
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 247
    .line 248
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 249
    .line 250
    .line 251
    move-result-object p1

    .line 252
    iget-object v1, p0, Lr50/c;->f:Lk21/a;

    .line 253
    .line 254
    invoke-virtual {v1, p1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    check-cast p1, Ltr0/c;

    .line 259
    .line 260
    iput-object v1, p0, Lr50/c;->g:Lk21/a;

    .line 261
    .line 262
    iput v2, p0, Lr50/c;->e:I

    .line 263
    .line 264
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 265
    .line 266
    invoke-interface {p1, v4, p0}, Ltr0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object p1

    .line 270
    if-ne p1, v0, :cond_b

    .line 271
    .line 272
    goto/16 :goto_7

    .line 273
    .line 274
    :cond_b
    move-object v4, v1

    .line 275
    :goto_6
    check-cast p1, Ljava/lang/String;

    .line 276
    .line 277
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 278
    .line 279
    const-class v0, Lli0/a;

    .line 280
    .line 281
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    invoke-virtual {v4, v0, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    move-object v7, v0

    .line 290
    check-cast v7, Lli0/a;

    .line 291
    .line 292
    const/4 v0, 0x2

    .line 293
    new-array v0, v0, [Ldm0/l;

    .line 294
    .line 295
    const-class v1, Lnc0/r;

    .line 296
    .line 297
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    invoke-virtual {v4, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    const/4 v5, 0x0

    .line 306
    aput-object v1, v0, v5

    .line 307
    .line 308
    const-class v1, Luc0/c;

    .line 309
    .line 310
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    invoke-virtual {v4, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v1

    .line 318
    aput-object v1, v0, v2

    .line 319
    .line 320
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 321
    .line 322
    .line 323
    move-result-object v6

    .line 324
    const-class v0, Ldm0/o;

    .line 325
    .line 326
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 327
    .line 328
    .line 329
    move-result-object p0

    .line 330
    invoke-virtual {v4, p0, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object p0

    .line 334
    move-object v10, p0

    .line 335
    check-cast v10, Ldm0/o;

    .line 336
    .line 337
    const/4 v9, 0x0

    .line 338
    const/16 v11, 0x51

    .line 339
    .line 340
    const/4 v5, 0x0

    .line 341
    const-string v8, "cariad-mdk-be"

    .line 342
    .line 343
    invoke-static/range {v4 .. v11}, Lzl0/b;->b(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;I)Ld01/h0;

    .line 344
    .line 345
    .line 346
    move-result-object p0

    .line 347
    new-instance v0, Lr50/a;

    .line 348
    .line 349
    const/4 v1, 0x1

    .line 350
    invoke-direct {v0, p0, v1}, Lr50/a;-><init>(Ld01/h0;I)V

    .line 351
    .line 352
    .line 353
    invoke-static {v0}, Ljp/n1;->a(Lay0/k;)Lzv0/c;

    .line 354
    .line 355
    .line 356
    move-result-object v6

    .line 357
    new-instance v5, Li51/a;

    .line 358
    .line 359
    invoke-static {v4}, Llp/va;->a(Lk21/a;)Landroid/content/Context;

    .line 360
    .line 361
    .line 362
    move-result-object v8

    .line 363
    const-string p0, "baseUrl"

    .line 364
    .line 365
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    new-instance p0, Ly41/g;

    .line 369
    .line 370
    invoke-direct {p0, p1}, Ly41/g;-><init>(Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    new-instance v0, Lj51/i;

    .line 374
    .line 375
    invoke-direct {v0}, Lj51/i;-><init>()V

    .line 376
    .line 377
    .line 378
    new-instance v1, Lj51/h;

    .line 379
    .line 380
    new-instance v7, Lxo/g;

    .line 381
    .line 382
    sget-object v12, Lko/h;->c:Lko/h;

    .line 383
    .line 384
    sget-object v10, Lxo/g;->n:Lc2/k;

    .line 385
    .line 386
    sget-object v11, Lko/b;->a:Lko/a;

    .line 387
    .line 388
    invoke-direct/range {v7 .. v12}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 389
    .line 390
    .line 391
    new-instance v2, Ly41/g;

    .line 392
    .line 393
    invoke-direct {v2, p1}, Ly41/g;-><init>(Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    invoke-direct {v1, v7, v2}, Lj51/h;-><init>(Lxo/g;Ly41/g;)V

    .line 397
    .line 398
    .line 399
    move-object v7, p0

    .line 400
    move-object v9, v1

    .line 401
    move-object v10, v8

    .line 402
    move-object v8, v0

    .line 403
    invoke-direct/range {v5 .. v10}, Li51/a;-><init>(Lzv0/c;Ly41/g;Lj51/i;Lj51/h;Landroid/content/Context;)V

    .line 404
    .line 405
    .line 406
    move-object v0, v5

    .line 407
    :goto_7
    return-object v0

    .line 408
    nop

    .line 409
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
