.class public final Lem0/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lem0/m;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lem0/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lem0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lem0/j;->f:Lem0/m;

    .line 4
    .line 5
    iput-object p2, p0, Lem0/j;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lem0/j;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lem0/j;

    .line 7
    .line 8
    iget-object v0, p0, Lem0/j;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lem0/j;->f:Lem0/m;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lem0/j;-><init>(Lem0/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lem0/j;

    .line 18
    .line 19
    iget-object v0, p0, Lem0/j;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lem0/j;->f:Lem0/m;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lem0/j;-><init>(Lem0/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

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
    iget v0, p0, Lem0/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Lem0/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lem0/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lem0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lem0/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lem0/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lem0/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 9

    .line 1
    iget v0, p0, Lem0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lem0/j;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v3, p0, Lem0/j;->f:Lem0/m;

    .line 13
    .line 14
    const/4 v4, 0x3

    .line 15
    const/4 v5, 0x2

    .line 16
    const/4 v6, 0x1

    .line 17
    if-eqz v1, :cond_4

    .line 18
    .line 19
    if-eq v1, v6, :cond_3

    .line 20
    .line 21
    if-eq v1, v5, :cond_2

    .line 22
    .line 23
    if-ne v1, v4, :cond_1

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    move-object v0, v2

    .line 29
    goto :goto_3

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, v3, Lem0/m;->a:Lti0/a;

    .line 50
    .line 51
    iput v6, p0, Lem0/j;->e:I

    .line 52
    .line 53
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-ne p1, v0, :cond_5

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_5
    :goto_0
    check-cast p1, Lem0/f;

    .line 61
    .line 62
    iput v5, p0, Lem0/j;->e:I

    .line 63
    .line 64
    iget-object v1, p1, Lem0/f;->a:Lla/u;

    .line 65
    .line 66
    new-instance v5, Lac0/r;

    .line 67
    .line 68
    const/4 v7, 0x6

    .line 69
    iget-object v8, p0, Lem0/j;->g:Ljava/lang/String;

    .line 70
    .line 71
    invoke-direct {v5, v8, v7, p1}, Lac0/r;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const/4 p1, 0x0

    .line 75
    invoke-static {p0, v1, v6, p1, v5}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    if-ne p1, v0, :cond_6

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_6
    :goto_1
    check-cast p1, Ljava/util/List;

    .line 83
    .line 84
    iget-object v1, v3, Lem0/m;->c:Lyy0/c2;

    .line 85
    .line 86
    check-cast p1, Ljava/lang/Iterable;

    .line 87
    .line 88
    new-instance v3, Ljava/util/ArrayList;

    .line 89
    .line 90
    const/16 v5, 0xa

    .line 91
    .line 92
    invoke-static {p1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 93
    .line 94
    .line 95
    move-result v5

    .line 96
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 97
    .line 98
    .line 99
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v5

    .line 107
    if-eqz v5, :cond_7

    .line 108
    .line 109
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    check-cast v5, Lem0/g;

    .line 114
    .line 115
    invoke-static {v5}, Lkp/l6;->b(Lem0/g;)Lhm0/b;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_7
    iput v4, p0, Lem0/j;->e:I

    .line 124
    .line 125
    invoke-virtual {v1, v3, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    if-ne v2, v0, :cond_0

    .line 129
    .line 130
    :goto_3
    return-object v0

    .line 131
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 132
    .line 133
    iget v1, p0, Lem0/j;->e:I

    .line 134
    .line 135
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    iget-object v3, p0, Lem0/j;->f:Lem0/m;

    .line 138
    .line 139
    const/4 v4, 0x3

    .line 140
    const/4 v5, 0x2

    .line 141
    const/4 v6, 0x1

    .line 142
    if-eqz v1, :cond_c

    .line 143
    .line 144
    if-eq v1, v6, :cond_b

    .line 145
    .line 146
    if-eq v1, v5, :cond_a

    .line 147
    .line 148
    if-ne v1, v4, :cond_9

    .line 149
    .line 150
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :cond_8
    move-object v0, v2

    .line 154
    goto :goto_7

    .line 155
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 156
    .line 157
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 158
    .line 159
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw p0

    .line 163
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    iget-object p1, v3, Lem0/m;->a:Lti0/a;

    .line 175
    .line 176
    iput v6, p0, Lem0/j;->e:I

    .line 177
    .line 178
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    if-ne p1, v0, :cond_d

    .line 183
    .line 184
    goto :goto_7

    .line 185
    :cond_d
    :goto_4
    check-cast p1, Lem0/f;

    .line 186
    .line 187
    iput v5, p0, Lem0/j;->e:I

    .line 188
    .line 189
    iget-object v1, p1, Lem0/f;->a:Lla/u;

    .line 190
    .line 191
    new-instance v5, Lac0/r;

    .line 192
    .line 193
    const/4 v7, 0x5

    .line 194
    iget-object v8, p0, Lem0/j;->g:Ljava/lang/String;

    .line 195
    .line 196
    invoke-direct {v5, v8, v7, p1}, Lac0/r;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    const/4 p1, 0x0

    .line 200
    invoke-static {p0, v1, v6, p1, v5}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    if-ne p1, v0, :cond_e

    .line 205
    .line 206
    goto :goto_7

    .line 207
    :cond_e
    :goto_5
    check-cast p1, Ljava/util/List;

    .line 208
    .line 209
    iget-object v1, v3, Lem0/m;->c:Lyy0/c2;

    .line 210
    .line 211
    check-cast p1, Ljava/lang/Iterable;

    .line 212
    .line 213
    new-instance v3, Ljava/util/ArrayList;

    .line 214
    .line 215
    const/16 v5, 0xa

    .line 216
    .line 217
    invoke-static {p1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 222
    .line 223
    .line 224
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    :goto_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 229
    .line 230
    .line 231
    move-result v5

    .line 232
    if-eqz v5, :cond_f

    .line 233
    .line 234
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v5

    .line 238
    check-cast v5, Lem0/g;

    .line 239
    .line 240
    invoke-static {v5}, Lkp/l6;->b(Lem0/g;)Lhm0/b;

    .line 241
    .line 242
    .line 243
    move-result-object v5

    .line 244
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    goto :goto_6

    .line 248
    :cond_f
    iput v4, p0, Lem0/j;->e:I

    .line 249
    .line 250
    invoke-virtual {v1, v3, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    if-ne v2, v0, :cond_8

    .line 254
    .line 255
    :goto_7
    return-object v0

    .line 256
    nop

    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
