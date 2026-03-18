.class public final Lc00/p0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Z

.field public f:I

.field public g:I

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public synthetic j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc00/q0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lc00/p0;->d:I

    .line 1
    iput-object p1, p0, Lc00/p0;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Leb/j0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lc00/p0;->d:I

    .line 2
    iput-object p1, p0, Lc00/p0;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget v0, p0, Lc00/p0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc00/p0;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/p0;->j:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Leb/j0;

    .line 11
    .line 12
    invoke-direct {p1, p0, p2}, Lc00/p0;-><init>(Leb/j0;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance v0, Lc00/p0;

    .line 17
    .line 18
    iget-object p0, p0, Lc00/p0;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lc00/q0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lc00/p0;-><init>(Lc00/q0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lc00/p0;->j:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc00/p0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/p0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lc00/p0;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lc00/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lc00/p0;->d:I

    .line 2
    .line 3
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x1

    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v0, p0, Lc00/p0;->g:I

    .line 15
    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    if-eq v0, v5, :cond_1

    .line 19
    .line 20
    if-ne v0, v3, :cond_0

    .line 21
    .line 22
    iget v4, p0, Lc00/p0;->f:I

    .line 23
    .line 24
    iget-boolean v5, p0, Lc00/p0;->e:Z

    .line 25
    .line 26
    iget-object v0, p0, Lc00/p0;->i:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Ljava/util/Iterator;

    .line 29
    .line 30
    iget-object v1, p0, Lc00/p0;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Leb/j0;

    .line 33
    .line 34
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Ls41/b;->a:Lpw0/a;

    .line 52
    .line 53
    :goto_0
    sget-object p1, Ls41/b;->b:Ljava/util/LinkedHashSet;

    .line 54
    .line 55
    iget-object v0, p0, Lc00/p0;->j:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v1, v0

    .line 58
    check-cast v1, Leb/j0;

    .line 59
    .line 60
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-nez p1, :cond_3

    .line 69
    .line 70
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object p0

    .line 73
    :cond_3
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-nez p1, :cond_4

    .line 78
    .line 79
    iput-object v1, p0, Lc00/p0;->h:Ljava/lang/Object;

    .line 80
    .line 81
    iput-object v0, p0, Lc00/p0;->i:Ljava/lang/Object;

    .line 82
    .line 83
    iput-boolean v5, p0, Lc00/p0;->e:Z

    .line 84
    .line 85
    iput v4, p0, Lc00/p0;->f:I

    .line 86
    .line 87
    iput v3, p0, Lc00/p0;->g:I

    .line 88
    .line 89
    throw v2

    .line 90
    :cond_4
    new-instance p0, Ljava/lang/ClassCastException;

    .line 91
    .line 92
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :pswitch_0
    iget-object v0, p0, Lc00/p0;->i:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lc00/q0;

    .line 99
    .line 100
    iget-object v6, p0, Lc00/p0;->j:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v6, Lvy0/b0;

    .line 103
    .line 104
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v8, p0, Lc00/p0;->g:I

    .line 107
    .line 108
    if-eqz v8, :cond_7

    .line 109
    .line 110
    if-eq v8, v5, :cond_6

    .line 111
    .line 112
    if-ne v8, v3, :cond_5

    .line 113
    .line 114
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    goto/16 :goto_3

    .line 118
    .line 119
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_6
    iget v4, p0, Lc00/p0;->f:I

    .line 126
    .line 127
    iget-boolean v0, p0, Lc00/p0;->e:Z

    .line 128
    .line 129
    iget-object v1, p0, Lc00/p0;->h:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v1, Lc00/q0;

    .line 132
    .line 133
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    move-object v10, v1

    .line 137
    move v1, v0

    .line 138
    move-object v0, v10

    .line 139
    goto :goto_2

    .line 140
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    check-cast p1, Lc00/n0;

    .line 148
    .line 149
    iget-object p1, p1, Lc00/n0;->b:Ljava/lang/Boolean;

    .line 150
    .line 151
    if-eqz p1, :cond_9

    .line 152
    .line 153
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 154
    .line 155
    .line 156
    move-result p1

    .line 157
    xor-int/2addr p1, v5

    .line 158
    new-instance v1, Lc00/k0;

    .line 159
    .line 160
    invoke-direct {v1, v0, p1, v5}, Lc00/k0;-><init>(Lc00/q0;ZI)V

    .line 161
    .line 162
    .line 163
    invoke-static {v6, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 164
    .line 165
    .line 166
    iget-object v1, v0, Lc00/q0;->l:Llb0/b0;

    .line 167
    .line 168
    iput-object v2, p0, Lc00/p0;->j:Ljava/lang/Object;

    .line 169
    .line 170
    iput-object v0, p0, Lc00/p0;->h:Ljava/lang/Object;

    .line 171
    .line 172
    iput-boolean p1, p0, Lc00/p0;->e:Z

    .line 173
    .line 174
    iput v4, p0, Lc00/p0;->f:I

    .line 175
    .line 176
    iput v5, p0, Lc00/p0;->g:I

    .line 177
    .line 178
    iget-object v6, v1, Llb0/b0;->a:Lkf0/m;

    .line 179
    .line 180
    invoke-static {v6}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 181
    .line 182
    .line 183
    move-result-object v6

    .line 184
    new-instance v8, Llb0/a0;

    .line 185
    .line 186
    invoke-direct {v8, v1, v2, v4}, Llb0/a0;-><init>(Llb0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 187
    .line 188
    .line 189
    invoke-static {v6, v8}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 190
    .line 191
    .line 192
    move-result-object v6

    .line 193
    new-instance v8, Lk70/h;

    .line 194
    .line 195
    const/4 v9, 0x4

    .line 196
    invoke-direct {v8, v1, p1, v2, v9}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 197
    .line 198
    .line 199
    invoke-static {v6, v8}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 200
    .line 201
    .line 202
    move-result-object v6

    .line 203
    iget-object v8, v1, Llb0/b0;->c:Lsf0/a;

    .line 204
    .line 205
    invoke-static {v6, v8, v2}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 206
    .line 207
    .line 208
    move-result-object v6

    .line 209
    new-instance v8, Llb0/a0;

    .line 210
    .line 211
    invoke-direct {v8, v1, v2, v5}, Llb0/a0;-><init>(Llb0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 212
    .line 213
    .line 214
    invoke-static {v8, v6}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    if-ne v1, v7, :cond_8

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_8
    move-object v10, v1

    .line 222
    move v1, p1

    .line 223
    move-object p1, v10

    .line 224
    :goto_2
    check-cast p1, Lyy0/i;

    .line 225
    .line 226
    new-instance v6, Lc00/o0;

    .line 227
    .line 228
    invoke-direct {v6, v0, v1, v5}, Lc00/o0;-><init>(Lc00/q0;ZI)V

    .line 229
    .line 230
    .line 231
    iput-object v2, p0, Lc00/p0;->j:Ljava/lang/Object;

    .line 232
    .line 233
    iput-object v2, p0, Lc00/p0;->h:Ljava/lang/Object;

    .line 234
    .line 235
    iput-boolean v1, p0, Lc00/p0;->e:Z

    .line 236
    .line 237
    iput v4, p0, Lc00/p0;->f:I

    .line 238
    .line 239
    iput v3, p0, Lc00/p0;->g:I

    .line 240
    .line 241
    invoke-interface {p1, v6, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    if-ne p0, v7, :cond_9

    .line 246
    .line 247
    goto :goto_4

    .line 248
    :cond_9
    :goto_3
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 249
    .line 250
    :goto_4
    return-object v7

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
