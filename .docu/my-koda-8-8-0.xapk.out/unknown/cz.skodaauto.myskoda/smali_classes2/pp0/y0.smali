.class public final Lpp0/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lpp0/c0;

.field public final c:Lnp0/c;

.field public final d:Lkf0/k;

.field public final e:Lpp0/v0;

.field public final f:Lsf0/a;


# direct methods
.method public constructor <init>(Lkf0/b0;Lpp0/c0;Lnp0/c;Lkf0/k;Lpp0/v0;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/y0;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/y0;->b:Lpp0/c0;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/y0;->c:Lnp0/c;

    .line 9
    .line 10
    iput-object p4, p0, Lpp0/y0;->d:Lkf0/k;

    .line 11
    .line 12
    iput-object p5, p0, Lpp0/y0;->e:Lpp0/v0;

    .line 13
    .line 14
    iput-object p6, p0, Lpp0/y0;->f:Lsf0/a;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lpp0/y0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lpp0/w0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lpp0/w0;

    .line 7
    .line 8
    iget v1, v0, Lpp0/w0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lpp0/w0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/w0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lpp0/w0;-><init>(Lpp0/y0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lpp0/w0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/w0;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    packed-switch v2, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p1

    .line 48
    :pswitch_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object p1

    .line 52
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    return-object p1

    .line 56
    :pswitch_3
    iget-object v2, v0, Lpp0/w0;->e:Lqp0/o;

    .line 57
    .line 58
    iget-object v5, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_4

    .line 64
    .line 65
    :pswitch_4
    iget-object v2, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    move-object v5, v2

    .line 71
    goto :goto_3

    .line 72
    :pswitch_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object p1, p0, Lpp0/y0;->a:Lkf0/b0;

    .line 80
    .line 81
    invoke-virtual {p1}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    check-cast p1, Lyy0/i;

    .line 86
    .line 87
    iput v3, v0, Lpp0/w0;->h:I

    .line 88
    .line 89
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    if-ne p1, v1, :cond_1

    .line 94
    .line 95
    goto/16 :goto_5

    .line 96
    .line 97
    :cond_1
    :goto_1
    check-cast p1, Lss0/j0;

    .line 98
    .line 99
    if-eqz p1, :cond_2

    .line 100
    .line 101
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_2
    move-object p1, v4

    .line 105
    :goto_2
    iget-object v2, p0, Lpp0/y0;->b:Lpp0/c0;

    .line 106
    .line 107
    check-cast v2, Lnp0/b;

    .line 108
    .line 109
    iget-object v2, v2, Lnp0/b;->g:Lyy0/l1;

    .line 110
    .line 111
    iput-object p1, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 112
    .line 113
    const/4 v5, 0x2

    .line 114
    iput v5, v0, Lpp0/w0;->h:I

    .line 115
    .line 116
    invoke-static {v2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    if-ne v2, v1, :cond_3

    .line 121
    .line 122
    goto/16 :goto_5

    .line 123
    .line 124
    :cond_3
    move-object v5, p1

    .line 125
    move-object p1, v2

    .line 126
    :goto_3
    move-object v2, p1

    .line 127
    check-cast v2, Lqp0/o;

    .line 128
    .line 129
    if-nez v5, :cond_4

    .line 130
    .line 131
    new-instance v6, Lne0/c;

    .line 132
    .line 133
    new-instance v7, Ljava/lang/IllegalStateException;

    .line 134
    .line 135
    const-string p0, "No active vin"

    .line 136
    .line 137
    invoke-direct {v7, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    const/4 v10, 0x0

    .line 141
    const/16 v11, 0x1e

    .line 142
    .line 143
    const/4 v8, 0x0

    .line 144
    const/4 v9, 0x0

    .line 145
    invoke-direct/range {v6 .. v11}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 146
    .line 147
    .line 148
    return-object v6

    .line 149
    :cond_4
    if-nez v2, :cond_5

    .line 150
    .line 151
    new-instance v0, Lne0/c;

    .line 152
    .line 153
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 154
    .line 155
    const-string p0, "No active route"

    .line 156
    .line 157
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    const/4 v4, 0x0

    .line 161
    const/16 v5, 0x1e

    .line 162
    .line 163
    const/4 v2, 0x0

    .line 164
    const/4 v3, 0x0

    .line 165
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 166
    .line 167
    .line 168
    return-object v0

    .line 169
    :cond_5
    iput-object v5, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 170
    .line 171
    iput-object v2, v0, Lpp0/w0;->e:Lqp0/o;

    .line 172
    .line 173
    const/4 p1, 0x3

    .line 174
    iput p1, v0, Lpp0/w0;->h:I

    .line 175
    .line 176
    iget-object p1, p0, Lpp0/y0;->d:Lkf0/k;

    .line 177
    .line 178
    invoke-virtual {p1, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    if-ne p1, v1, :cond_6

    .line 183
    .line 184
    goto :goto_5

    .line 185
    :cond_6
    :goto_4
    check-cast p1, Lss0/b;

    .line 186
    .line 187
    sget-object v6, Lss0/e;->A1:Lss0/e;

    .line 188
    .line 189
    invoke-static {p1, v6}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    if-eqz p1, :cond_a

    .line 194
    .line 195
    iget-boolean p1, v2, Lqp0/o;->h:Z

    .line 196
    .line 197
    iget-object v2, v2, Lqp0/o;->a:Ljava/util/List;

    .line 198
    .line 199
    if-eqz p1, :cond_8

    .line 200
    .line 201
    invoke-static {v2}, Ljp/eg;->d(Ljava/util/List;)Ljava/util/ArrayList;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    iput-object v4, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 206
    .line 207
    iput-object v4, v0, Lpp0/w0;->e:Lqp0/o;

    .line 208
    .line 209
    const/4 v2, 0x4

    .line 210
    iput v2, v0, Lpp0/w0;->h:I

    .line 211
    .line 212
    invoke-virtual {p0, v5, p1, v0}, Lpp0/y0;->c(Ljava/lang/String;Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    if-ne p0, v1, :cond_7

    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_7
    return-object p0

    .line 220
    :cond_8
    check-cast v2, Ljava/lang/Iterable;

    .line 221
    .line 222
    invoke-static {v2, v3}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 223
    .line 224
    .line 225
    move-result-object p1

    .line 226
    iput-object v4, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 227
    .line 228
    iput-object v4, v0, Lpp0/w0;->e:Lqp0/o;

    .line 229
    .line 230
    const/4 v2, 0x5

    .line 231
    iput v2, v0, Lpp0/w0;->h:I

    .line 232
    .line 233
    invoke-virtual {p0, v5, p1, v0}, Lpp0/y0;->c(Ljava/lang/String;Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    if-ne p0, v1, :cond_9

    .line 238
    .line 239
    goto :goto_5

    .line 240
    :cond_9
    return-object p0

    .line 241
    :cond_a
    iget-object p1, v2, Lqp0/o;->a:Ljava/util/List;

    .line 242
    .line 243
    invoke-static {p1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object p1

    .line 247
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    iput-object v4, v0, Lpp0/w0;->d:Ljava/lang/String;

    .line 252
    .line 253
    iput-object v4, v0, Lpp0/w0;->e:Lqp0/o;

    .line 254
    .line 255
    const/4 v2, 0x6

    .line 256
    iput v2, v0, Lpp0/w0;->h:I

    .line 257
    .line 258
    invoke-virtual {p0, v5, p1, v0}, Lpp0/y0;->c(Ljava/lang/String;Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    if-ne p0, v1, :cond_b

    .line 263
    .line 264
    :goto_5
    return-object v1

    .line 265
    :cond_b
    return-object p0

    .line 266
    nop

    .line 267
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Ljava/lang/String;Ljava/util/List;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lpp0/x0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lpp0/x0;

    .line 7
    .line 8
    iget v1, v0, Lpp0/x0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lpp0/x0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/x0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lpp0/x0;-><init>(Lpp0/y0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lpp0/x0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/x0;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v10, 0x0

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    if-eq v2, v3, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lpp0/x0;->e:Ljava/util/List;

    .line 41
    .line 42
    check-cast p0, Ljava/util/List;

    .line 43
    .line 44
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p3

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-object p1, v0, Lpp0/x0;->e:Ljava/util/List;

    .line 57
    .line 58
    move-object p2, p1

    .line 59
    check-cast p2, Ljava/util/List;

    .line 60
    .line 61
    iget-object p1, v0, Lpp0/x0;->d:Ljava/lang/String;

    .line 62
    .line 63
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_3
    move-object v8, p1

    .line 67
    move-object v9, p2

    .line 68
    goto :goto_4

    .line 69
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iput-object p1, v0, Lpp0/x0;->d:Ljava/lang/String;

    .line 73
    .line 74
    move-object p3, p2

    .line 75
    check-cast p3, Ljava/util/List;

    .line 76
    .line 77
    iput-object p3, v0, Lpp0/x0;->e:Ljava/util/List;

    .line 78
    .line 79
    iput v3, v0, Lpp0/x0;->h:I

    .line 80
    .line 81
    move-object p3, p2

    .line 82
    check-cast p3, Ljava/lang/Iterable;

    .line 83
    .line 84
    new-instance v2, Ljava/util/ArrayList;

    .line 85
    .line 86
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 87
    .line 88
    .line 89
    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object p3

    .line 93
    :cond_5
    :goto_1
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    if-eqz v3, :cond_7

    .line 98
    .line 99
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    check-cast v3, Lqp0/b0;

    .line 104
    .line 105
    iget-object v3, v3, Lqp0/b0;->l:Ljava/lang/String;

    .line 106
    .line 107
    if-eqz v3, :cond_6

    .line 108
    .line 109
    new-instance v5, Ldk0/a;

    .line 110
    .line 111
    sget-object v6, Ldk0/b;->f:Ldk0/b;

    .line 112
    .line 113
    invoke-direct {v5, v3, v6}, Ldk0/a;-><init>(Ljava/lang/String;Ldk0/b;)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_6
    move-object v5, v10

    .line 118
    :goto_2
    if-eqz v5, :cond_5

    .line 119
    .line 120
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_7
    iget-object p3, p0, Lpp0/y0;->e:Lpp0/v0;

    .line 125
    .line 126
    invoke-virtual {p3, v2, v0}, Lpp0/v0;->b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 131
    .line 132
    if-ne p3, v2, :cond_8

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_8
    sget-object p3, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    :goto_3
    if-ne p3, v1, :cond_3

    .line 138
    .line 139
    goto :goto_5

    .line 140
    :goto_4
    iget-object v7, p0, Lpp0/y0;->c:Lnp0/c;

    .line 141
    .line 142
    const-string p1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 143
    .line 144
    invoke-static {v8, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    const-string p1, "waypoints"

    .line 148
    .line 149
    invoke-static {v9, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    iget-object p1, v7, Lnp0/c;->a:Lxl0/f;

    .line 153
    .line 154
    new-instance v5, La30/b;

    .line 155
    .line 156
    const/16 v6, 0x1d

    .line 157
    .line 158
    invoke-direct/range {v5 .. v10}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {p1, v5}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    iget-object p0, p0, Lpp0/y0;->f:Lsf0/a;

    .line 166
    .line 167
    invoke-static {p1, p0, v10}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    iput-object v10, v0, Lpp0/x0;->d:Ljava/lang/String;

    .line 172
    .line 173
    iput-object v10, v0, Lpp0/x0;->e:Ljava/util/List;

    .line 174
    .line 175
    iput v4, v0, Lpp0/x0;->h:I

    .line 176
    .line 177
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    if-ne p0, v1, :cond_9

    .line 182
    .line 183
    :goto_5
    return-object v1

    .line 184
    :cond_9
    return-object p0
.end method
