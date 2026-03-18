.class public final Ln00/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ln00/c;


# direct methods
.method public synthetic constructor <init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ln00/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln00/a;->f:Ln00/c;

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
    iget p1, p0, Ln00/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ln00/a;

    .line 7
    .line 8
    iget-object p0, p0, Ln00/a;->f:Ln00/c;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ln00/a;-><init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ln00/a;

    .line 16
    .line 17
    iget-object p0, p0, Ln00/a;->f:Ln00/c;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ln00/a;-><init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ln00/a;

    .line 25
    .line 26
    iget-object p0, p0, Ln00/a;->f:Ln00/c;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ln00/a;-><init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ln00/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Ln00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ln00/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ln00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ln00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ln00/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ln00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ln00/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ln00/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ln00/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Ln00/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ln00/a;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Ln00/a;->f:Ln00/c;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

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
    iget-object p1, v2, Ln00/c;->k:Ll00/c;

    .line 33
    .line 34
    iput v3, p0, Ln00/a;->e:I

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, p0}, Ll00/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    if-ne p0, v0, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    :goto_0
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, Ln00/b;

    .line 51
    .line 52
    iget-object p0, p0, Ln00/b;->b:Ljava/lang/String;

    .line 53
    .line 54
    const-string p1, "infoUrl"

    .line 55
    .line 56
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance p1, Ln00/b;

    .line 60
    .line 61
    const/4 v0, 0x0

    .line 62
    invoke-direct {p1, v0, p0}, Ln00/b;-><init>(ZLjava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2, p1}, Lql0/j;->g(Lql0/h;)V

    .line 66
    .line 67
    .line 68
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    :goto_1
    return-object v0

    .line 71
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v1, p0, Ln00/a;->e:I

    .line 74
    .line 75
    const/4 v2, 0x3

    .line 76
    const/4 v3, 0x2

    .line 77
    const/4 v4, 0x1

    .line 78
    iget-object v5, p0, Ln00/a;->f:Ln00/c;

    .line 79
    .line 80
    if-eqz v1, :cond_6

    .line 81
    .line 82
    if-eq v1, v4, :cond_5

    .line 83
    .line 84
    if-eq v1, v3, :cond_4

    .line 85
    .line 86
    if-ne v1, v2, :cond_3

    .line 87
    .line 88
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    iget-object p1, v5, Ln00/c;->l:Lhh0/a;

    .line 112
    .line 113
    sget-object v1, Lih0/a;->e:Lih0/a;

    .line 114
    .line 115
    iput v4, p0, Ln00/a;->e:I

    .line 116
    .line 117
    invoke-virtual {p1, v1, p0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    if-ne p1, v0, :cond_7

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_7
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 127
    .line 128
    .line 129
    move-result p1

    .line 130
    if-eqz p1, :cond_9

    .line 131
    .line 132
    iget-object p1, v5, Ln00/c;->h:Ll00/i;

    .line 133
    .line 134
    iput v3, p0, Ln00/a;->e:I

    .line 135
    .line 136
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    iget-object v1, p1, Ll00/i;->a:Lkf0/z;

    .line 140
    .line 141
    invoke-virtual {v1}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    check-cast v1, Lyy0/i;

    .line 146
    .line 147
    new-instance v3, Lac/l;

    .line 148
    .line 149
    const/16 v4, 0x1c

    .line 150
    .line 151
    invoke-direct {v3, v4, v1, p1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    if-ne v3, v0, :cond_8

    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_8
    move-object p1, v3

    .line 158
    :goto_3
    check-cast p1, Lyy0/i;

    .line 159
    .line 160
    new-instance v1, Llb0/q0;

    .line 161
    .line 162
    const/4 v3, 0x0

    .line 163
    const/16 v4, 0x13

    .line 164
    .line 165
    invoke-direct {v1, v5, v3, v4}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 166
    .line 167
    .line 168
    iput v2, p0, Ln00/a;->e:I

    .line 169
    .line 170
    invoke-static {v1, p0, p1}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    if-ne p0, v0, :cond_9

    .line 175
    .line 176
    goto :goto_5

    .line 177
    :cond_9
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    :goto_5
    return-object v0

    .line 180
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 181
    .line 182
    iget v1, p0, Ln00/a;->e:I

    .line 183
    .line 184
    const/4 v2, 0x3

    .line 185
    const/4 v3, 0x2

    .line 186
    const/4 v4, 0x1

    .line 187
    iget-object v5, p0, Ln00/a;->f:Ln00/c;

    .line 188
    .line 189
    if-eqz v1, :cond_d

    .line 190
    .line 191
    if-eq v1, v4, :cond_c

    .line 192
    .line 193
    if-eq v1, v3, :cond_b

    .line 194
    .line 195
    if-ne v1, v2, :cond_a

    .line 196
    .line 197
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    goto :goto_8

    .line 201
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 202
    .line 203
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 204
    .line 205
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw p0

    .line 209
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    goto :goto_7

    .line 213
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    goto :goto_6

    .line 217
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    iget-object p1, v5, Ln00/c;->l:Lhh0/a;

    .line 221
    .line 222
    sget-object v1, Lih0/a;->e:Lih0/a;

    .line 223
    .line 224
    iput v4, p0, Ln00/a;->e:I

    .line 225
    .line 226
    invoke-virtual {p1, v1, p0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    if-ne p1, v0, :cond_e

    .line 231
    .line 232
    goto :goto_9

    .line 233
    :cond_e
    :goto_6
    check-cast p1, Ljava/lang/Boolean;

    .line 234
    .line 235
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 236
    .line 237
    .line 238
    move-result p1

    .line 239
    if-eqz p1, :cond_10

    .line 240
    .line 241
    iget-object p1, v5, Ln00/c;->h:Ll00/i;

    .line 242
    .line 243
    iput v3, p0, Ln00/a;->e:I

    .line 244
    .line 245
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 246
    .line 247
    .line 248
    iget-object v1, p1, Ll00/i;->a:Lkf0/z;

    .line 249
    .line 250
    invoke-virtual {v1}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    check-cast v1, Lyy0/i;

    .line 255
    .line 256
    new-instance v3, Lac/l;

    .line 257
    .line 258
    const/16 v4, 0x1c

    .line 259
    .line 260
    invoke-direct {v3, v4, v1, p1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    if-ne v3, v0, :cond_f

    .line 264
    .line 265
    goto :goto_9

    .line 266
    :cond_f
    move-object p1, v3

    .line 267
    :goto_7
    check-cast p1, Lyy0/i;

    .line 268
    .line 269
    new-instance v1, Lma0/c;

    .line 270
    .line 271
    const/4 v3, 0x4

    .line 272
    invoke-direct {v1, v5, v3}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 273
    .line 274
    .line 275
    iput v2, p0, Ln00/a;->e:I

    .line 276
    .line 277
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object p0

    .line 281
    if-ne p0, v0, :cond_10

    .line 282
    .line 283
    goto :goto_9

    .line 284
    :cond_10
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    :goto_9
    return-object v0

    .line 287
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
