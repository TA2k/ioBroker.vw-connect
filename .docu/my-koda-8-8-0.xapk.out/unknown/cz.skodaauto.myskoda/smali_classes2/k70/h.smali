.class public final Lk70/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lk70/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 4
    .line 5
    iput-boolean p2, p0, Lk70/h;->h:Z

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lk70/h;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Lk70/h;

    .line 11
    .line 12
    iget-object v1, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Llb0/b0;

    .line 15
    .line 16
    iget-boolean p0, p0, Lk70/h;->h:Z

    .line 17
    .line 18
    const/4 v2, 0x4

    .line 19
    invoke-direct {v0, v1, p0, p3, v2}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Lk70/h;->f:Lyy0/j;

    .line 23
    .line 24
    iput-object p2, v0, Lk70/h;->g:Ljava/lang/Object;

    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Lk70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_0
    new-instance v0, Lk70/h;

    .line 34
    .line 35
    iget-object v1, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Llb0/w;

    .line 38
    .line 39
    iget-boolean p0, p0, Lk70/h;->h:Z

    .line 40
    .line 41
    const/4 v2, 0x3

    .line 42
    invoke-direct {v0, v1, p0, p3, v2}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, v0, Lk70/h;->f:Lyy0/j;

    .line 46
    .line 47
    iput-object p2, v0, Lk70/h;->g:Ljava/lang/Object;

    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Lk70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    new-instance v0, Lk70/h;

    .line 57
    .line 58
    iget-object v1, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v1, Llb0/s;

    .line 61
    .line 62
    iget-boolean p0, p0, Lk70/h;->h:Z

    .line 63
    .line 64
    const/4 v2, 0x2

    .line 65
    invoke-direct {v0, v1, p0, p3, v2}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    iput-object p1, v0, Lk70/h;->f:Lyy0/j;

    .line 69
    .line 70
    iput-object p2, v0, Lk70/h;->g:Ljava/lang/Object;

    .line 71
    .line 72
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    invoke-virtual {v0, p0}, Lk70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_2
    new-instance v0, Lk70/h;

    .line 80
    .line 81
    iget-object v1, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v1, Lk80/c;

    .line 84
    .line 85
    iget-boolean p0, p0, Lk70/h;->h:Z

    .line 86
    .line 87
    const/4 v2, 0x1

    .line 88
    invoke-direct {v0, v1, p0, p3, v2}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 89
    .line 90
    .line 91
    iput-object p1, v0, Lk70/h;->f:Lyy0/j;

    .line 92
    .line 93
    iput-object p2, v0, Lk70/h;->g:Ljava/lang/Object;

    .line 94
    .line 95
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Lk70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :pswitch_3
    new-instance v0, Lk70/h;

    .line 103
    .line 104
    iget-object v1, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v1, Lk70/k;

    .line 107
    .line 108
    iget-boolean p0, p0, Lk70/h;->h:Z

    .line 109
    .line 110
    const/4 v2, 0x0

    .line 111
    invoke-direct {v0, v1, p0, p3, v2}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 112
    .line 113
    .line 114
    iput-object p1, v0, Lk70/h;->f:Lyy0/j;

    .line 115
    .line 116
    iput-object p2, v0, Lk70/h;->g:Ljava/lang/Object;

    .line 117
    .line 118
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    invoke-virtual {v0, p0}, Lk70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lk70/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lk70/h;->e:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lk70/h;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lne0/t;

    .line 35
    .line 36
    instance-of v3, v1, Lne0/e;

    .line 37
    .line 38
    const/4 v8, 0x0

    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    check-cast v1, Lne0/e;

    .line 42
    .line 43
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lss0/k;

    .line 46
    .line 47
    iget-object v3, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v3, Llb0/b0;

    .line 50
    .line 51
    iget-object v5, v3, Llb0/b0;->b:Ljb0/x;

    .line 52
    .line 53
    iget-object v6, v1, Lss0/k;->a:Ljava/lang/String;

    .line 54
    .line 55
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 56
    .line 57
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, v5, Ljb0/x;->a:Lxl0/f;

    .line 61
    .line 62
    new-instance v4, Ljb0/w;

    .line 63
    .line 64
    const/4 v9, 0x2

    .line 65
    iget-boolean v7, p0, Lk70/h;->h:Z

    .line 66
    .line 67
    invoke-direct/range {v4 .. v9}, Ljb0/w;-><init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v4}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    goto :goto_0

    .line 75
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 76
    .line 77
    if-eqz v3, :cond_4

    .line 78
    .line 79
    new-instance v3, Lyy0/m;

    .line 80
    .line 81
    const/4 v4, 0x0

    .line 82
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    move-object v1, v3

    .line 86
    :goto_0
    iput-object v8, p0, Lk70/h;->f:Lyy0/j;

    .line 87
    .line 88
    iput-object v8, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 89
    .line 90
    iput v2, p0, Lk70/h;->e:I

    .line 91
    .line 92
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v0, :cond_3

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    :goto_2
    return-object v0

    .line 102
    :cond_4
    new-instance p0, La8/r0;

    .line 103
    .line 104
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 105
    .line 106
    .line 107
    throw p0

    .line 108
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    iget v1, p0, Lk70/h;->e:I

    .line 111
    .line 112
    const/4 v2, 0x1

    .line 113
    if-eqz v1, :cond_6

    .line 114
    .line 115
    if-ne v1, v2, :cond_5

    .line 116
    .line 117
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 122
    .line 123
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 124
    .line 125
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iget-object p1, p0, Lk70/h;->f:Lyy0/j;

    .line 133
    .line 134
    iget-object v1, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v1, Lne0/t;

    .line 137
    .line 138
    instance-of v3, v1, Lne0/e;

    .line 139
    .line 140
    const/4 v8, 0x0

    .line 141
    if-eqz v3, :cond_7

    .line 142
    .line 143
    check-cast v1, Lne0/e;

    .line 144
    .line 145
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v1, Lss0/k;

    .line 148
    .line 149
    iget-object v3, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v3, Llb0/w;

    .line 152
    .line 153
    iget-object v5, v3, Llb0/w;->b:Ljb0/x;

    .line 154
    .line 155
    iget-object v6, v1, Lss0/k;->a:Ljava/lang/String;

    .line 156
    .line 157
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 158
    .line 159
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    iget-object v1, v5, Ljb0/x;->a:Lxl0/f;

    .line 163
    .line 164
    new-instance v4, Ljb0/w;

    .line 165
    .line 166
    const/4 v9, 0x1

    .line 167
    iget-boolean v7, p0, Lk70/h;->h:Z

    .line 168
    .line 169
    invoke-direct/range {v4 .. v9}, Ljb0/w;-><init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v1, v4}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    goto :goto_3

    .line 177
    :cond_7
    instance-of v3, v1, Lne0/c;

    .line 178
    .line 179
    if-eqz v3, :cond_9

    .line 180
    .line 181
    new-instance v3, Lyy0/m;

    .line 182
    .line 183
    const/4 v4, 0x0

    .line 184
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 185
    .line 186
    .line 187
    move-object v1, v3

    .line 188
    :goto_3
    iput-object v8, p0, Lk70/h;->f:Lyy0/j;

    .line 189
    .line 190
    iput-object v8, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 191
    .line 192
    iput v2, p0, Lk70/h;->e:I

    .line 193
    .line 194
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-ne p0, v0, :cond_8

    .line 199
    .line 200
    goto :goto_5

    .line 201
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 202
    .line 203
    :goto_5
    return-object v0

    .line 204
    :cond_9
    new-instance p0, La8/r0;

    .line 205
    .line 206
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 211
    .line 212
    iget v1, p0, Lk70/h;->e:I

    .line 213
    .line 214
    const/4 v2, 0x1

    .line 215
    if-eqz v1, :cond_b

    .line 216
    .line 217
    if-ne v1, v2, :cond_a

    .line 218
    .line 219
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    goto :goto_7

    .line 223
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 224
    .line 225
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 226
    .line 227
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw p0

    .line 231
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    iget-object p1, p0, Lk70/h;->f:Lyy0/j;

    .line 235
    .line 236
    iget-object v1, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast v1, Lne0/t;

    .line 239
    .line 240
    instance-of v3, v1, Lne0/e;

    .line 241
    .line 242
    const/4 v8, 0x0

    .line 243
    if-eqz v3, :cond_c

    .line 244
    .line 245
    check-cast v1, Lne0/e;

    .line 246
    .line 247
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 248
    .line 249
    check-cast v1, Lss0/k;

    .line 250
    .line 251
    iget-object v3, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast v3, Llb0/s;

    .line 254
    .line 255
    iget-object v5, v3, Llb0/s;->b:Ljb0/x;

    .line 256
    .line 257
    iget-object v6, v1, Lss0/k;->a:Ljava/lang/String;

    .line 258
    .line 259
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 260
    .line 261
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    iget-object v1, v5, Ljb0/x;->a:Lxl0/f;

    .line 265
    .line 266
    new-instance v4, Ljb0/w;

    .line 267
    .line 268
    const/4 v9, 0x0

    .line 269
    iget-boolean v7, p0, Lk70/h;->h:Z

    .line 270
    .line 271
    invoke-direct/range {v4 .. v9}, Ljb0/w;-><init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v1, v4}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    goto :goto_6

    .line 279
    :cond_c
    instance-of v3, v1, Lne0/c;

    .line 280
    .line 281
    if-eqz v3, :cond_e

    .line 282
    .line 283
    new-instance v3, Lyy0/m;

    .line 284
    .line 285
    const/4 v4, 0x0

    .line 286
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 287
    .line 288
    .line 289
    move-object v1, v3

    .line 290
    :goto_6
    iput-object v8, p0, Lk70/h;->f:Lyy0/j;

    .line 291
    .line 292
    iput-object v8, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 293
    .line 294
    iput v2, p0, Lk70/h;->e:I

    .line 295
    .line 296
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    if-ne p0, v0, :cond_d

    .line 301
    .line 302
    goto :goto_8

    .line 303
    :cond_d
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 304
    .line 305
    :goto_8
    return-object v0

    .line 306
    :cond_e
    new-instance p0, La8/r0;

    .line 307
    .line 308
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 309
    .line 310
    .line 311
    throw p0

    .line 312
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 313
    .line 314
    iget v1, p0, Lk70/h;->e:I

    .line 315
    .line 316
    const/4 v2, 0x1

    .line 317
    if-eqz v1, :cond_10

    .line 318
    .line 319
    if-ne v1, v2, :cond_f

    .line 320
    .line 321
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    goto :goto_a

    .line 325
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 326
    .line 327
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 328
    .line 329
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    throw p0

    .line 333
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    iget-object p1, p0, Lk70/h;->f:Lyy0/j;

    .line 337
    .line 338
    iget-object v1, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v1, Lne0/t;

    .line 341
    .line 342
    instance-of v3, v1, Lne0/e;

    .line 343
    .line 344
    const/4 v4, 0x0

    .line 345
    if-eqz v3, :cond_11

    .line 346
    .line 347
    check-cast v1, Lne0/e;

    .line 348
    .line 349
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v1, Lss0/j0;

    .line 352
    .line 353
    iget-object v1, v1, Lss0/j0;->d:Ljava/lang/String;

    .line 354
    .line 355
    iget-object v3, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v3, Lk80/c;

    .line 358
    .line 359
    iget-object v3, v3, Lk80/c;->a:Lj80/d;

    .line 360
    .line 361
    const-string v5, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 362
    .line 363
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    iget-object v5, v3, Lj80/d;->a:Lxl0/f;

    .line 367
    .line 368
    new-instance v6, Lj80/c;

    .line 369
    .line 370
    iget-boolean v7, p0, Lk70/h;->h:Z

    .line 371
    .line 372
    invoke-direct {v6, v3, v7, v1, v4}, Lj80/c;-><init>(Lj80/d;ZLjava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 373
    .line 374
    .line 375
    new-instance v1, Lim0/b;

    .line 376
    .line 377
    const/16 v3, 0xf

    .line 378
    .line 379
    invoke-direct {v1, v3}, Lim0/b;-><init>(I)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v5, v6, v1, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 383
    .line 384
    .line 385
    move-result-object v1

    .line 386
    goto :goto_9

    .line 387
    :cond_11
    instance-of v3, v1, Lne0/c;

    .line 388
    .line 389
    if-eqz v3, :cond_13

    .line 390
    .line 391
    new-instance v3, Lyy0/m;

    .line 392
    .line 393
    const/4 v5, 0x0

    .line 394
    invoke-direct {v3, v1, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 395
    .line 396
    .line 397
    move-object v1, v3

    .line 398
    :goto_9
    iput-object v4, p0, Lk70/h;->f:Lyy0/j;

    .line 399
    .line 400
    iput-object v4, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 401
    .line 402
    iput v2, p0, Lk70/h;->e:I

    .line 403
    .line 404
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object p0

    .line 408
    if-ne p0, v0, :cond_12

    .line 409
    .line 410
    goto :goto_b

    .line 411
    :cond_12
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 412
    .line 413
    :goto_b
    return-object v0

    .line 414
    :cond_13
    new-instance p0, La8/r0;

    .line 415
    .line 416
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 417
    .line 418
    .line 419
    throw p0

    .line 420
    :pswitch_3
    iget-object v0, p0, Lk70/h;->i:Ljava/lang/Object;

    .line 421
    .line 422
    check-cast v0, Lk70/k;

    .line 423
    .line 424
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 425
    .line 426
    iget v2, p0, Lk70/h;->e:I

    .line 427
    .line 428
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 429
    .line 430
    const/4 v4, 0x1

    .line 431
    if-eqz v2, :cond_16

    .line 432
    .line 433
    if-ne v2, v4, :cond_15

    .line 434
    .line 435
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    :cond_14
    move-object v1, v3

    .line 439
    goto/16 :goto_e

    .line 440
    .line 441
    :cond_15
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 442
    .line 443
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 444
    .line 445
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    throw p0

    .line 449
    :cond_16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 450
    .line 451
    .line 452
    iget-object p1, p0, Lk70/h;->f:Lyy0/j;

    .line 453
    .line 454
    iget-object v2, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 455
    .line 456
    check-cast v2, Lne0/t;

    .line 457
    .line 458
    instance-of v5, v2, Lne0/e;

    .line 459
    .line 460
    const/4 v6, 0x0

    .line 461
    if-eqz v5, :cond_18

    .line 462
    .line 463
    check-cast v2, Lne0/e;

    .line 464
    .line 465
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 466
    .line 467
    check-cast v2, Lss0/j0;

    .line 468
    .line 469
    iget-object v10, v2, Lss0/j0;->d:Ljava/lang/String;

    .line 470
    .line 471
    iget-object v2, v0, Lk70/k;->e:Lk70/s;

    .line 472
    .line 473
    iget-object v2, v2, Lk70/s;->a:Lk70/x;

    .line 474
    .line 475
    check-cast v2, Li70/c;

    .line 476
    .line 477
    iget-object v2, v2, Li70/c;->d:Lyy0/l1;

    .line 478
    .line 479
    iget-object v2, v2, Lyy0/l1;->d:Lyy0/a2;

    .line 480
    .line 481
    invoke-interface {v2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move-result-object v2

    .line 485
    move-object v9, v2

    .line 486
    check-cast v9, Ll70/k;

    .line 487
    .line 488
    iget-object v8, v0, Lk70/k;->b:Li70/t;

    .line 489
    .line 490
    iget-object v0, v0, Lk70/k;->c:Lk70/x;

    .line 491
    .line 492
    check-cast v0, Li70/c;

    .line 493
    .line 494
    iget-object v0, v0, Li70/c;->e:Ljava/lang/String;

    .line 495
    .line 496
    iget-boolean v2, p0, Lk70/h;->h:Z

    .line 497
    .line 498
    if-nez v2, :cond_17

    .line 499
    .line 500
    move-object v11, v0

    .line 501
    goto :goto_c

    .line 502
    :cond_17
    move-object v11, v6

    .line 503
    :goto_c
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 504
    .line 505
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 506
    .line 507
    .line 508
    const-string v0, "filter"

    .line 509
    .line 510
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 511
    .line 512
    .line 513
    iget-object v0, v8, Li70/t;->a:Lxl0/f;

    .line 514
    .line 515
    new-instance v7, Li70/s;

    .line 516
    .line 517
    const/4 v12, 0x0

    .line 518
    invoke-direct/range {v7 .. v12}, Li70/s;-><init>(Li70/t;Ll70/k;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 519
    .line 520
    .line 521
    new-instance v2, Li70/q;

    .line 522
    .line 523
    const/4 v5, 0x2

    .line 524
    invoke-direct {v2, v5}, Li70/q;-><init>(I)V

    .line 525
    .line 526
    .line 527
    invoke-virtual {v0, v7, v2, v6}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 528
    .line 529
    .line 530
    move-result-object v0

    .line 531
    goto :goto_d

    .line 532
    :cond_18
    instance-of v0, v2, Lne0/c;

    .line 533
    .line 534
    if-eqz v0, :cond_19

    .line 535
    .line 536
    new-instance v0, Lyy0/m;

    .line 537
    .line 538
    const/4 v5, 0x0

    .line 539
    invoke-direct {v0, v2, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 540
    .line 541
    .line 542
    :goto_d
    iput-object v6, p0, Lk70/h;->f:Lyy0/j;

    .line 543
    .line 544
    iput-object v6, p0, Lk70/h;->g:Ljava/lang/Object;

    .line 545
    .line 546
    iput v4, p0, Lk70/h;->e:I

    .line 547
    .line 548
    invoke-static {p1, v0, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 549
    .line 550
    .line 551
    move-result-object p0

    .line 552
    if-ne p0, v1, :cond_14

    .line 553
    .line 554
    :goto_e
    return-object v1

    .line 555
    :cond_19
    new-instance p0, La8/r0;

    .line 556
    .line 557
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 558
    .line 559
    .line 560
    throw p0

    .line 561
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
