.class public final Lq40/o;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lnn0/k;

.field public final i:Lo40/d;

.field public final j:Lo40/g;

.field public final k:Lnn0/i;

.field public final l:Lnn0/e0;

.field public final m:Lnn0/o;

.field public final n:Lo40/a;

.field public final o:Lij0/a;

.field public final p:Lo40/m;

.field public final q:Lcs0/l;


# direct methods
.method public constructor <init>(Lnn0/k;Lo40/d;Lo40/g;Lnn0/i;Lnn0/e0;Lnn0/o;Lo40/a;Lij0/a;Lo40/m;Lcs0/l;)V
    .locals 6

    .line 1
    new-instance v0, Lq40/l;

    .line 2
    .line 3
    new-instance v2, Lon0/j;

    .line 4
    .line 5
    const-string v1, ""

    .line 6
    .line 7
    invoke-direct {v2, v1, v1}, Lon0/j;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 v4, 0x1

    .line 11
    sget-object v5, Lqr0/s;->d:Lqr0/s;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct/range {v0 .. v5}, Lq40/l;-><init>(Lon0/e;Lon0/j;Lql0/g;ZLqr0/s;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lq40/o;->h:Lnn0/k;

    .line 22
    .line 23
    iput-object p2, p0, Lq40/o;->i:Lo40/d;

    .line 24
    .line 25
    iput-object p3, p0, Lq40/o;->j:Lo40/g;

    .line 26
    .line 27
    iput-object p4, p0, Lq40/o;->k:Lnn0/i;

    .line 28
    .line 29
    iput-object p5, p0, Lq40/o;->l:Lnn0/e0;

    .line 30
    .line 31
    iput-object p6, p0, Lq40/o;->m:Lnn0/o;

    .line 32
    .line 33
    iput-object p7, p0, Lq40/o;->n:Lo40/a;

    .line 34
    .line 35
    iput-object p8, p0, Lq40/o;->o:Lij0/a;

    .line 36
    .line 37
    iput-object p9, p0, Lq40/o;->p:Lo40/m;

    .line 38
    .line 39
    move-object/from16 p1, p10

    .line 40
    .line 41
    iput-object p1, p0, Lq40/o;->q:Lcs0/l;

    .line 42
    .line 43
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    new-instance p2, Lq40/k;

    .line 48
    .line 49
    const/4 p3, 0x0

    .line 50
    const/4 p4, 0x0

    .line 51
    invoke-direct {p2, p0, p4, p3}, Lq40/k;-><init>(Lq40/o;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    const/4 p0, 0x3

    .line 55
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public static final h(Lq40/o;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lq40/m;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lq40/m;

    .line 10
    .line 11
    iget v1, v0, Lq40/m;->g:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lq40/m;->g:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lq40/m;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Lq40/m;-><init>(Lq40/o;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Lq40/m;->e:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lq40/m;->g:I

    .line 33
    .line 34
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    packed-switch v2, :pswitch_data_0

    .line 38
    .line 39
    .line 40
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object v3

    .line 52
    :pswitch_1
    iget-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 53
    .line 54
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_6

    .line 58
    .line 59
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-object v3

    .line 63
    :pswitch_3
    iget-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto/16 :goto_5

    .line 69
    .line 70
    :pswitch_4
    iget-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 71
    .line 72
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_3

    .line 76
    :pswitch_5
    iget-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :pswitch_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object p1, p0, Lq40/o;->q:Lcs0/l;

    .line 90
    .line 91
    const/4 v2, 0x1

    .line 92
    iput v2, v0, Lq40/m;->g:I

    .line 93
    .line 94
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p1, v0}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v1, :cond_1

    .line 102
    .line 103
    goto/16 :goto_7

    .line 104
    .line 105
    :cond_1
    :goto_1
    move-object v2, p1

    .line 106
    check-cast v2, Lqr0/s;

    .line 107
    .line 108
    iget-object p1, p0, Lq40/o;->m:Lnn0/o;

    .line 109
    .line 110
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    check-cast p1, Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    if-eqz p1, :cond_3

    .line 121
    .line 122
    iget-object p1, p0, Lq40/o;->l:Lnn0/e0;

    .line 123
    .line 124
    iget-object p1, p1, Lnn0/e0;->a:Lln0/d;

    .line 125
    .line 126
    const/4 v5, 0x0

    .line 127
    iput-boolean v5, p1, Lln0/d;->b:Z

    .line 128
    .line 129
    iget-object p1, p0, Lq40/o;->k:Lnn0/i;

    .line 130
    .line 131
    iput-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 132
    .line 133
    const/4 v5, 0x2

    .line 134
    iput v5, v0, Lq40/m;->g:I

    .line 135
    .line 136
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    iget-object p1, p1, Lnn0/i;->a:Lln0/d;

    .line 140
    .line 141
    iget-object p1, p1, Lln0/d;->a:Ljava/lang/String;

    .line 142
    .line 143
    if-ne p1, v1, :cond_2

    .line 144
    .line 145
    goto/16 :goto_7

    .line 146
    .line 147
    :cond_2
    :goto_2
    check-cast p1, Ljava/lang/String;

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_3
    iget-object p1, p0, Lq40/o;->i:Lo40/d;

    .line 151
    .line 152
    iput-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 153
    .line 154
    const/4 v5, 0x3

    .line 155
    iput v5, v0, Lq40/m;->g:I

    .line 156
    .line 157
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    iget-object p1, p1, Lo40/d;->a:Lln0/g;

    .line 161
    .line 162
    iget-object p1, p1, Lln0/g;->d:Ljava/lang/String;

    .line 163
    .line 164
    if-ne p1, v1, :cond_4

    .line 165
    .line 166
    goto :goto_7

    .line 167
    :cond_4
    :goto_3
    check-cast p1, Ljava/lang/String;

    .line 168
    .line 169
    :goto_4
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 170
    .line 171
    .line 172
    move-result v5

    .line 173
    if-nez v5, :cond_6

    .line 174
    .line 175
    iget-object v5, p0, Lq40/o;->n:Lo40/a;

    .line 176
    .line 177
    iput-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 178
    .line 179
    const/4 v6, 0x4

    .line 180
    iput v6, v0, Lq40/m;->g:I

    .line 181
    .line 182
    invoke-virtual {v5, p1, v0}, Lo40/a;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    if-ne p1, v1, :cond_5

    .line 187
    .line 188
    goto :goto_7

    .line 189
    :cond_5
    :goto_5
    check-cast p1, Lyy0/i;

    .line 190
    .line 191
    new-instance v5, Lq40/n;

    .line 192
    .line 193
    const/4 v6, 0x0

    .line 194
    invoke-direct {v5, p0, v2, v6}, Lq40/n;-><init>(Lq40/o;Lqr0/s;I)V

    .line 195
    .line 196
    .line 197
    iput-object v4, v0, Lq40/m;->d:Lqr0/s;

    .line 198
    .line 199
    const/4 p0, 0x5

    .line 200
    iput p0, v0, Lq40/m;->g:I

    .line 201
    .line 202
    invoke-interface {p1, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    if-ne p0, v1, :cond_8

    .line 207
    .line 208
    goto :goto_7

    .line 209
    :cond_6
    iget-object p1, p0, Lq40/o;->j:Lo40/g;

    .line 210
    .line 211
    iput-object v2, v0, Lq40/m;->d:Lqr0/s;

    .line 212
    .line 213
    const/4 v5, 0x6

    .line 214
    iput v5, v0, Lq40/m;->g:I

    .line 215
    .line 216
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 217
    .line 218
    .line 219
    iget-object p1, p1, Lo40/g;->a:Lm40/g;

    .line 220
    .line 221
    iget-object v5, p1, Lm40/g;->a:Lxl0/f;

    .line 222
    .line 223
    new-instance v6, La90/s;

    .line 224
    .line 225
    const/16 v7, 0xe

    .line 226
    .line 227
    invoke-direct {v6, p1, v4, v7}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 228
    .line 229
    .line 230
    new-instance p1, Lm40/e;

    .line 231
    .line 232
    const/4 v7, 0x0

    .line 233
    invoke-direct {p1, v7}, Lm40/e;-><init>(I)V

    .line 234
    .line 235
    .line 236
    new-instance v7, Lm40/e;

    .line 237
    .line 238
    const/4 v8, 0x1

    .line 239
    invoke-direct {v7, v8}, Lm40/e;-><init>(I)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v5, v6, p1, v7}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 243
    .line 244
    .line 245
    move-result-object p1

    .line 246
    if-ne p1, v1, :cond_7

    .line 247
    .line 248
    goto :goto_7

    .line 249
    :cond_7
    :goto_6
    check-cast p1, Lyy0/i;

    .line 250
    .line 251
    new-instance v5, Lq40/n;

    .line 252
    .line 253
    const/4 v6, 0x1

    .line 254
    invoke-direct {v5, p0, v2, v6}, Lq40/n;-><init>(Lq40/o;Lqr0/s;I)V

    .line 255
    .line 256
    .line 257
    iput-object v4, v0, Lq40/m;->d:Lqr0/s;

    .line 258
    .line 259
    const/4 p0, 0x7

    .line 260
    iput p0, v0, Lq40/m;->g:I

    .line 261
    .line 262
    invoke-interface {p1, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    if-ne p0, v1, :cond_8

    .line 267
    .line 268
    :goto_7
    return-object v1

    .line 269
    :cond_8
    return-object v3

    .line 270
    nop

    .line 271
    :pswitch_data_0
    .packed-switch 0x0
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

.method public static final j(Lq40/o;Lne0/s;Lqr0/s;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lq40/o;->h:Lnn0/k;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lon0/f;

    .line 8
    .line 9
    instance-of v1, p1, Lne0/c;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    check-cast p1, Lne0/c;

    .line 15
    .line 16
    iget-object p2, p0, Lq40/o;->o:Lij0/a;

    .line 17
    .line 18
    iget-object v0, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 19
    .line 20
    instance-of v1, v0, Lbm0/d;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    check-cast v0, Lbm0/d;

    .line 26
    .line 27
    iget-object v0, v0, Lbm0/d;->e:Lbm0/c;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    iget-object v2, v0, Lbm0/c;->a:Ljava/lang/String;

    .line 32
    .line 33
    :cond_0
    const-string v0, "VENDOR_ERROR"

    .line 34
    .line 35
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    check-cast p1, Lq40/l;

    .line 46
    .line 47
    iget-object v4, p0, Lq40/o;->o:Lij0/a;

    .line 48
    .line 49
    new-array v0, v3, [Ljava/lang/Object;

    .line 50
    .line 51
    move-object v1, v4

    .line 52
    check-cast v1, Ljj0/f;

    .line 53
    .line 54
    const v2, 0x7f120e5c

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1, v2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    new-array v0, v3, [Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p2, Ljj0/f;

    .line 64
    .line 65
    const v1, 0x7f120e5b

    .line 66
    .line 67
    .line 68
    invoke-virtual {p2, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    const v0, 0x7f12038b

    .line 73
    .line 74
    .line 75
    new-array v1, v3, [Ljava/lang/Object;

    .line 76
    .line 77
    invoke-virtual {p2, v0, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    const v0, 0x7f120373

    .line 82
    .line 83
    .line 84
    new-array v1, v3, [Ljava/lang/Object;

    .line 85
    .line 86
    invoke-virtual {p2, v0, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v8

    .line 90
    const/16 v9, 0x60

    .line 91
    .line 92
    invoke-static/range {v4 .. v9}, Ljp/rf;->a(Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lql0/g;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    invoke-static {p1, p2, v3}, Lq40/l;->a(Lq40/l;Lql0/g;Z)Lq40/l;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    goto :goto_2

    .line 101
    :cond_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    check-cast v0, Lq40/l;

    .line 106
    .line 107
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-static {v0, p1, v3}, Lq40/l;->a(Lq40/l;Lql0/g;Z)Lq40/l;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    goto :goto_2

    .line 116
    :cond_2
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 117
    .line 118
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-eqz v1, :cond_3

    .line 123
    .line 124
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    check-cast p1, Lq40/l;

    .line 129
    .line 130
    const/4 p2, 0x1

    .line 131
    invoke-static {p1, v2, p2}, Lq40/l;->a(Lq40/l;Lql0/g;Z)Lq40/l;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    goto :goto_2

    .line 136
    :cond_3
    instance-of v1, p1, Lne0/e;

    .line 137
    .line 138
    if-eqz v1, :cond_5

    .line 139
    .line 140
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    check-cast v1, Lq40/l;

    .line 145
    .line 146
    check-cast p1, Lne0/e;

    .line 147
    .line 148
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 149
    .line 150
    move-object v3, p1

    .line 151
    check-cast v3, Lon0/e;

    .line 152
    .line 153
    if-eqz v0, :cond_4

    .line 154
    .line 155
    new-instance p1, Lon0/j;

    .line 156
    .line 157
    iget-object v0, v0, Lon0/f;->a:Lon0/j;

    .line 158
    .line 159
    iget-object v2, v0, Lon0/j;->a:Ljava/lang/String;

    .line 160
    .line 161
    iget-object v0, v0, Lon0/j;->b:Ljava/lang/String;

    .line 162
    .line 163
    invoke-direct {p1, v2, v0}, Lon0/j;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    :goto_0
    move-object v4, p1

    .line 167
    goto :goto_1

    .line 168
    :cond_4
    new-instance p1, Lon0/j;

    .line 169
    .line 170
    iget-object v0, v3, Lon0/e;->k:Lon0/l;

    .line 171
    .line 172
    iget-object v2, v0, Lon0/l;->a:Ljava/lang/String;

    .line 173
    .line 174
    iget-object v0, v0, Lon0/l;->b:Ljava/lang/String;

    .line 175
    .line 176
    invoke-direct {p1, v2, v0}, Lon0/j;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    goto :goto_0

    .line 180
    :goto_1
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 181
    .line 182
    .line 183
    const-string p1, "fuelUnitType"

    .line 184
    .line 185
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    new-instance v2, Lq40/l;

    .line 189
    .line 190
    const/4 v5, 0x0

    .line 191
    const/4 v6, 0x0

    .line 192
    move-object v7, p2

    .line 193
    invoke-direct/range {v2 .. v7}, Lq40/l;-><init>(Lon0/e;Lon0/j;Lql0/g;ZLqr0/s;)V

    .line 194
    .line 195
    .line 196
    move-object p1, v2

    .line 197
    :goto_2
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 198
    .line 199
    .line 200
    return-void

    .line 201
    :cond_5
    new-instance p0, La8/r0;

    .line 202
    .line 203
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 204
    .line 205
    .line 206
    throw p0
.end method
