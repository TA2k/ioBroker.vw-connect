.class public final Lvy/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lvy/v;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lvy/v;)V
    .locals 0

    .line 1
    iput p1, p0, Lvy/k;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lvy/k;->f:Lvy/v;

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
    iget p1, p0, Lvy/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lvy/k;

    .line 7
    .line 8
    iget-object p0, p0, Lvy/k;->f:Lvy/v;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, v0, p2, p0}, Lvy/k;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lvy/k;

    .line 16
    .line 17
    iget-object p0, p0, Lvy/k;->f:Lvy/v;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, v0, p2, p0}, Lvy/k;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lvy/k;

    .line 25
    .line 26
    iget-object p0, p0, Lvy/k;->f:Lvy/v;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, v0, p2, p0}, Lvy/k;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

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
    iget v0, p0, Lvy/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lvy/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lvy/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lvy/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lvy/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lvy/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lvy/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lvy/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lvy/k;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lvy/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lvy/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lvy/k;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Lvy/k;->f:Lvy/v;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

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
    iget-object p1, v3, Lvy/v;->q:Lty/m;

    .line 33
    .line 34
    iput v2, p0, Lvy/k;->e:I

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, p0}, Lty/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    if-ne p1, v0, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    :goto_0
    check-cast p1, Lne0/t;

    .line 47
    .line 48
    instance-of p0, p1, Lne0/e;

    .line 49
    .line 50
    if-eqz p0, :cond_3

    .line 51
    .line 52
    move-object p0, p1

    .line 53
    check-cast p0, Lne0/e;

    .line 54
    .line 55
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Llx0/b0;

    .line 58
    .line 59
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Lvy/p;

    .line 64
    .line 65
    sget-object v0, Lvy/o;->g:Lvy/o;

    .line 66
    .line 67
    invoke-static {p0, v0}, Llp/pc;->h(Lvy/p;Lvy/o;)Lvy/p;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 72
    .line 73
    .line 74
    :cond_3
    instance-of p0, p1, Lne0/c;

    .line 75
    .line 76
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    if-eqz p0, :cond_4

    .line 79
    .line 80
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    move-object v4, p0

    .line 85
    check-cast v4, Lvy/p;

    .line 86
    .line 87
    iget-object v7, v3, Lvy/v;->w:Lvy/o;

    .line 88
    .line 89
    const/4 v10, 0x0

    .line 90
    const/16 v11, 0x1df

    .line 91
    .line 92
    const/4 v5, 0x0

    .line 93
    const/4 v6, 0x0

    .line 94
    const/4 v8, 0x0

    .line 95
    const/4 v9, 0x0

    .line 96
    invoke-static/range {v4 .. v11}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 101
    .line 102
    .line 103
    :cond_4
    :goto_1
    return-object v0

    .line 104
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v1, p0, Lvy/k;->e:I

    .line 107
    .line 108
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    const/4 v3, 0x1

    .line 111
    if-eqz v1, :cond_7

    .line 112
    .line 113
    if-ne v1, v3, :cond_6

    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_5
    move-object v0, v2

    .line 119
    goto :goto_3

    .line 120
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 121
    .line 122
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 123
    .line 124
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iput v3, p0, Lvy/k;->e:I

    .line 132
    .line 133
    iget-object p1, p0, Lvy/k;->f:Lvy/v;

    .line 134
    .line 135
    iget-object v1, p1, Lvy/v;->o:Lty/h;

    .line 136
    .line 137
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    check-cast v1, Lyy0/i;

    .line 142
    .line 143
    iget-object v3, p1, Lvy/v;->t:Lty/f;

    .line 144
    .line 145
    sget-object v4, Luy/c;->d:Luy/c;

    .line 146
    .line 147
    invoke-virtual {v3, v4}, Lty/f;->a(Luy/c;)Lyy0/i;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    sget-object v5, Luy/c;->e:Luy/c;

    .line 152
    .line 153
    invoke-virtual {v3, v5}, Lty/f;->a(Luy/c;)Lyy0/i;

    .line 154
    .line 155
    .line 156
    move-result-object v3

    .line 157
    new-instance v5, Lga0/z;

    .line 158
    .line 159
    const/4 v6, 0x4

    .line 160
    const/4 v7, 0x2

    .line 161
    const/4 v8, 0x0

    .line 162
    invoke-direct {v5, v6, v8, v7}, Lga0/z;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 163
    .line 164
    .line 165
    invoke-static {v1, v4, v3, v5}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 166
    .line 167
    .line 168
    move-result-object v1

    .line 169
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    new-instance v3, Lvy/m;

    .line 174
    .line 175
    const/4 v4, 0x1

    .line 176
    invoke-direct {v3, v4, v8, p1}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 177
    .line 178
    .line 179
    invoke-static {v3, p0, v1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    if-ne p0, v0, :cond_8

    .line 184
    .line 185
    goto :goto_2

    .line 186
    :cond_8
    move-object p0, v2

    .line 187
    :goto_2
    if-ne p0, v0, :cond_5

    .line 188
    .line 189
    :goto_3
    return-object v0

    .line 190
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 191
    .line 192
    iget v1, p0, Lvy/k;->e:I

    .line 193
    .line 194
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 195
    .line 196
    const/4 v3, 0x1

    .line 197
    if-eqz v1, :cond_b

    .line 198
    .line 199
    if-ne v1, v3, :cond_a

    .line 200
    .line 201
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    :cond_9
    move-object v0, v2

    .line 205
    goto :goto_5

    .line 206
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 207
    .line 208
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 209
    .line 210
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    throw p0

    .line 214
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    iput v3, p0, Lvy/k;->e:I

    .line 218
    .line 219
    iget-object p1, p0, Lvy/k;->f:Lvy/v;

    .line 220
    .line 221
    iget-object v1, p1, Lvy/v;->u:Llb0/g;

    .line 222
    .line 223
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    check-cast v1, Lyy0/i;

    .line 228
    .line 229
    new-instance v3, Lvy/q;

    .line 230
    .line 231
    const/4 v4, 0x0

    .line 232
    const/4 v5, 0x0

    .line 233
    invoke-direct {v3, v5, v4, p1}, Lvy/q;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 234
    .line 235
    .line 236
    invoke-static {v1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    if-ne p0, v0, :cond_c

    .line 245
    .line 246
    goto :goto_4

    .line 247
    :cond_c
    move-object p0, v2

    .line 248
    :goto_4
    if-ne p0, v0, :cond_9

    .line 249
    .line 250
    :goto_5
    return-object v0

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
