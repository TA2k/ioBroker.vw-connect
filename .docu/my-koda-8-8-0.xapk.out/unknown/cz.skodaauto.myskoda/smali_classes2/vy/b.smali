.class public final Lvy/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lvy/h;


# direct methods
.method public synthetic constructor <init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvy/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvy/b;->f:Lvy/h;

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
    iget p1, p0, Lvy/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lvy/b;

    .line 7
    .line 8
    iget-object p0, p0, Lvy/b;->f:Lvy/h;

    .line 9
    .line 10
    const/4 v0, 0x5

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lvy/b;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lvy/b;

    .line 16
    .line 17
    iget-object p0, p0, Lvy/b;->f:Lvy/h;

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lvy/b;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lvy/b;

    .line 25
    .line 26
    iget-object p0, p0, Lvy/b;->f:Lvy/h;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lvy/b;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lvy/b;

    .line 34
    .line 35
    iget-object p0, p0, Lvy/b;->f:Lvy/h;

    .line 36
    .line 37
    const/4 v0, 0x2

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lvy/b;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lvy/b;

    .line 43
    .line 44
    iget-object p0, p0, Lvy/b;->f:Lvy/h;

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lvy/b;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lvy/b;

    .line 52
    .line 53
    iget-object p0, p0, Lvy/b;->f:Lvy/h;

    .line 54
    .line 55
    const/4 v0, 0x0

    .line 56
    invoke-direct {p1, p0, p2, v0}, Lvy/b;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lvy/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lvy/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lvy/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lvy/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lvy/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lvy/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lvy/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lvy/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lvy/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lvy/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lvy/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lvy/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lvy/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lvy/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lvy/b;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lvy/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lvy/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lvy/b;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lvy/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvy/b;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x0

    .line 8
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 9
    .line 10
    iget-object v6, v0, Lvy/b;->f:Lvy/h;

    .line 11
    .line 12
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v8, 0x1

    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v2, v0, Lvy/b;->e:I

    .line 21
    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    if-ne v2, v8, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    move-object/from16 v0, p1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v6, Lvy/h;->n:Lty/m;

    .line 42
    .line 43
    iput v8, v0, Lvy/b;->e:I

    .line 44
    .line 45
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v2, v0}, Lty/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    if-ne v0, v1, :cond_2

    .line 53
    .line 54
    move-object v7, v1

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    :goto_0
    check-cast v0, Lne0/t;

    .line 57
    .line 58
    instance-of v1, v0, Lne0/e;

    .line 59
    .line 60
    if-eqz v1, :cond_3

    .line 61
    .line 62
    check-cast v0, Lne0/e;

    .line 63
    .line 64
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Llx0/b0;

    .line 67
    .line 68
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    check-cast v0, Lvy/d;

    .line 73
    .line 74
    iget-object v1, v6, Lvy/h;->k:Lij0/a;

    .line 75
    .line 76
    invoke-static {v0, v1, v4}, Llp/oc;->a(Lvy/d;Lij0/a;Z)Lvy/d;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-virtual {v6, v0}, Lql0/j;->g(Lql0/h;)V

    .line 81
    .line 82
    .line 83
    :cond_3
    :goto_1
    return-object v7

    .line 84
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 85
    .line 86
    iget v2, v0, Lvy/b;->e:I

    .line 87
    .line 88
    if-eqz v2, :cond_5

    .line 89
    .line 90
    if-ne v2, v8, :cond_4

    .line 91
    .line 92
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 97
    .line 98
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw v0

    .line 102
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iput v8, v0, Lvy/b;->e:I

    .line 106
    .line 107
    iget-object v2, v6, Lvy/h;->t:Llb0/g;

    .line 108
    .line 109
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    check-cast v2, Lyy0/i;

    .line 114
    .line 115
    new-instance v4, Lqa0/a;

    .line 116
    .line 117
    const/16 v5, 0x15

    .line 118
    .line 119
    invoke-direct {v4, v3, v6, v5}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 120
    .line 121
    .line 122
    invoke-static {v2, v4}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    if-ne v0, v1, :cond_6

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_6
    move-object v0, v7

    .line 134
    :goto_2
    if-ne v0, v1, :cond_7

    .line 135
    .line 136
    move-object v7, v1

    .line 137
    :cond_7
    :goto_3
    return-object v7

    .line 138
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 139
    .line 140
    iget v2, v0, Lvy/b;->e:I

    .line 141
    .line 142
    if-eqz v2, :cond_9

    .line 143
    .line 144
    if-ne v2, v8, :cond_8

    .line 145
    .line 146
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 151
    .line 152
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw v0

    .line 156
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iput v8, v0, Lvy/b;->e:I

    .line 160
    .line 161
    iget-object v2, v6, Lvy/h;->m:Lty/h;

    .line 162
    .line 163
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    check-cast v2, Lyy0/i;

    .line 168
    .line 169
    iget-object v5, v6, Lvy/h;->p:Lty/f;

    .line 170
    .line 171
    sget-object v8, Luy/c;->d:Luy/c;

    .line 172
    .line 173
    invoke-virtual {v5, v8}, Lty/f;->a(Luy/c;)Lyy0/i;

    .line 174
    .line 175
    .line 176
    move-result-object v5

    .line 177
    new-instance v8, Lc00/q;

    .line 178
    .line 179
    const/4 v9, 0x3

    .line 180
    const/4 v10, 0x5

    .line 181
    invoke-direct {v8, v9, v3, v10}, Lc00/q;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 182
    .line 183
    .line 184
    new-instance v9, Lbn0/f;

    .line 185
    .line 186
    invoke-direct {v9, v2, v5, v8, v10}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 187
    .line 188
    .line 189
    new-instance v2, Lvy/f;

    .line 190
    .line 191
    invoke-direct {v2, v6, v3, v4}, Lvy/f;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 192
    .line 193
    .line 194
    invoke-static {v2, v0, v9}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    if-ne v0, v1, :cond_a

    .line 199
    .line 200
    goto :goto_4

    .line 201
    :cond_a
    move-object v0, v7

    .line 202
    :goto_4
    if-ne v0, v1, :cond_b

    .line 203
    .line 204
    move-object v7, v1

    .line 205
    :cond_b
    :goto_5
    return-object v7

    .line 206
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 207
    .line 208
    iget v2, v0, Lvy/b;->e:I

    .line 209
    .line 210
    if-eqz v2, :cond_d

    .line 211
    .line 212
    if-ne v2, v8, :cond_c

    .line 213
    .line 214
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    goto :goto_6

    .line 218
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 219
    .line 220
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw v0

    .line 224
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    iget-object v2, v6, Lvy/h;->j:Lkf0/b0;

    .line 228
    .line 229
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v2

    .line 233
    check-cast v2, Lyy0/i;

    .line 234
    .line 235
    new-instance v3, Lvy/c;

    .line 236
    .line 237
    invoke-direct {v3, v6, v8}, Lvy/c;-><init>(Lvy/h;I)V

    .line 238
    .line 239
    .line 240
    iput v8, v0, Lvy/b;->e:I

    .line 241
    .line 242
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    if-ne v0, v1, :cond_e

    .line 247
    .line 248
    move-object v7, v1

    .line 249
    :cond_e
    :goto_6
    return-object v7

    .line 250
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 251
    .line 252
    iget v3, v0, Lvy/b;->e:I

    .line 253
    .line 254
    if-eqz v3, :cond_11

    .line 255
    .line 256
    if-eq v3, v8, :cond_10

    .line 257
    .line 258
    if-ne v3, v2, :cond_f

    .line 259
    .line 260
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    goto :goto_9

    .line 264
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 265
    .line 266
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    throw v0

    .line 270
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    move-object/from16 v3, p1

    .line 274
    .line 275
    goto :goto_7

    .line 276
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 277
    .line 278
    .line 279
    iget-object v3, v6, Lvy/h;->v:Lcf0/e;

    .line 280
    .line 281
    iput v8, v0, Lvy/b;->e:I

    .line 282
    .line 283
    invoke-virtual {v3, v7, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    if-ne v3, v1, :cond_12

    .line 288
    .line 289
    goto :goto_8

    .line 290
    :cond_12
    :goto_7
    check-cast v3, Ljava/lang/Boolean;

    .line 291
    .line 292
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 293
    .line 294
    .line 295
    move-result v14

    .line 296
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 297
    .line 298
    .line 299
    move-result-object v3

    .line 300
    move-object v8, v3

    .line 301
    check-cast v8, Lvy/d;

    .line 302
    .line 303
    const/16 v16, 0x0

    .line 304
    .line 305
    const/16 v17, 0x37f

    .line 306
    .line 307
    const/4 v9, 0x0

    .line 308
    const/4 v10, 0x0

    .line 309
    const/4 v11, 0x0

    .line 310
    const/4 v12, 0x0

    .line 311
    const/4 v13, 0x0

    .line 312
    const/4 v15, 0x0

    .line 313
    invoke-static/range {v8 .. v17}, Lvy/d;->a(Lvy/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZI)Lvy/d;

    .line 314
    .line 315
    .line 316
    move-result-object v3

    .line 317
    invoke-virtual {v6, v3}, Lql0/j;->g(Lql0/h;)V

    .line 318
    .line 319
    .line 320
    if-eqz v14, :cond_13

    .line 321
    .line 322
    iget-object v3, v6, Lvy/h;->u:Lty/g;

    .line 323
    .line 324
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v3

    .line 328
    check-cast v3, Lyy0/i;

    .line 329
    .line 330
    new-instance v5, Lvy/c;

    .line 331
    .line 332
    invoke-direct {v5, v6, v4}, Lvy/c;-><init>(Lvy/h;I)V

    .line 333
    .line 334
    .line 335
    iput v2, v0, Lvy/b;->e:I

    .line 336
    .line 337
    invoke-interface {v3, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    if-ne v0, v1, :cond_13

    .line 342
    .line 343
    :goto_8
    move-object v7, v1

    .line 344
    :cond_13
    :goto_9
    return-object v7

    .line 345
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 346
    .line 347
    iget v9, v0, Lvy/b;->e:I

    .line 348
    .line 349
    if-eqz v9, :cond_15

    .line 350
    .line 351
    if-ne v9, v8, :cond_14

    .line 352
    .line 353
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    goto :goto_c

    .line 357
    :cond_14
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 358
    .line 359
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    throw v0

    .line 363
    :cond_15
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 364
    .line 365
    .line 366
    iget-object v5, v6, Lvy/h;->w:Lkf0/v;

    .line 367
    .line 368
    invoke-static {v5}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v5

    .line 372
    check-cast v5, Lyy0/i;

    .line 373
    .line 374
    iget-object v9, v6, Lvy/h;->h:Lkf0/e0;

    .line 375
    .line 376
    sget-object v10, Lss0/e;->f:Lss0/e;

    .line 377
    .line 378
    invoke-virtual {v9, v10}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 379
    .line 380
    .line 381
    move-result-object v9

    .line 382
    new-instance v10, Lqa0/a;

    .line 383
    .line 384
    const/16 v11, 0x14

    .line 385
    .line 386
    invoke-direct {v10, v6, v3, v11}, Lqa0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 387
    .line 388
    .line 389
    iput v8, v0, Lvy/b;->e:I

    .line 390
    .line 391
    new-array v2, v2, [Lyy0/i;

    .line 392
    .line 393
    aput-object v5, v2, v4

    .line 394
    .line 395
    aput-object v9, v2, v8

    .line 396
    .line 397
    new-instance v4, Lyy0/g1;

    .line 398
    .line 399
    invoke-direct {v4, v10, v3}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 400
    .line 401
    .line 402
    sget-object v3, Lyy0/h1;->d:Lyy0/h1;

    .line 403
    .line 404
    sget-object v5, Lzy0/q;->d:Lzy0/q;

    .line 405
    .line 406
    invoke-static {v3, v4, v0, v5, v2}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 411
    .line 412
    if-ne v0, v2, :cond_16

    .line 413
    .line 414
    goto :goto_a

    .line 415
    :cond_16
    move-object v0, v7

    .line 416
    :goto_a
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 417
    .line 418
    if-ne v0, v2, :cond_17

    .line 419
    .line 420
    goto :goto_b

    .line 421
    :cond_17
    move-object v0, v7

    .line 422
    :goto_b
    if-ne v0, v1, :cond_18

    .line 423
    .line 424
    move-object v7, v1

    .line 425
    :cond_18
    :goto_c
    return-object v7

    .line 426
    nop

    .line 427
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
