.class public final Lu50/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lu50/r;


# direct methods
.method public synthetic constructor <init>(Lu50/r;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lu50/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu50/o;->g:Lu50/r;

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
    .locals 2

    .line 1
    iget v0, p0, Lu50/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lu50/o;

    .line 7
    .line 8
    iget-object p0, p0, Lu50/o;->g:Lu50/r;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lu50/o;-><init>(Lu50/r;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lu50/o;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lu50/o;

    .line 18
    .line 19
    iget-object p0, p0, Lu50/o;->g:Lu50/r;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lu50/o;-><init>(Lu50/r;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lu50/o;->f:Ljava/lang/Object;

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
    iget v0, p0, Lu50/o;->d:I

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
    invoke-virtual {p0, p1, p2}, Lu50/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lu50/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lu50/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lu50/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lu50/o;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lu50/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lu50/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu50/o;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lu50/o;->e:I

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x1

    .line 16
    iget-object v5, p0, Lu50/o;->g:Lu50/r;

    .line 17
    .line 18
    if-eqz v2, :cond_2

    .line 19
    .line 20
    if-eq v2, v4, :cond_1

    .line 21
    .line 22
    if-ne v2, v3, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto/16 :goto_1

    .line 28
    .line 29
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, v5, Lu50/r;->h:Lrs0/g;

    .line 45
    .line 46
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    check-cast p1, Lyy0/i;

    .line 51
    .line 52
    iput-object v0, p0, Lu50/o;->f:Ljava/lang/Object;

    .line 53
    .line 54
    iput v4, p0, Lu50/o;->e:I

    .line 55
    .line 56
    invoke-static {p1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-ne p1, v1, :cond_3

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    :goto_0
    check-cast p1, Lss0/d0;

    .line 64
    .line 65
    instance-of v2, p1, Lss0/g;

    .line 66
    .line 67
    const/4 v6, 0x0

    .line 68
    const/4 v7, 0x0

    .line 69
    if-eqz v2, :cond_4

    .line 70
    .line 71
    new-instance p0, Lu2/a;

    .line 72
    .line 73
    check-cast p1, Lss0/g;

    .line 74
    .line 75
    const/4 v1, 0x3

    .line 76
    invoke-direct {p0, p1, v1}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {v7, v0, p0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    check-cast p0, Lu50/p;

    .line 87
    .line 88
    invoke-static {v5}, Lu50/r;->h(Lu50/r;)Lql0/g;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    new-instance p0, Lu50/p;

    .line 96
    .line 97
    invoke-direct {p0, p1, v6}, Lu50/p;-><init>(Lql0/g;Z)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v5, p0}, Lql0/j;->g(Lql0/h;)V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_4
    instance-of v2, p1, Lss0/j0;

    .line 105
    .line 106
    if-eqz v2, :cond_5

    .line 107
    .line 108
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    check-cast v0, Lu50/p;

    .line 113
    .line 114
    iget-object v0, v0, Lu50/p;->b:Lql0/g;

    .line 115
    .line 116
    new-instance v2, Lu50/p;

    .line 117
    .line 118
    invoke-direct {v2, v0, v4}, Lu50/p;-><init>(Lql0/g;Z)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v5, v2}, Lql0/j;->g(Lql0/h;)V

    .line 122
    .line 123
    .line 124
    iget-object v0, v5, Lu50/r;->i:Ls50/o;

    .line 125
    .line 126
    check-cast p1, Lss0/j0;

    .line 127
    .line 128
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 129
    .line 130
    iput-object v7, p0, Lu50/o;->f:Ljava/lang/Object;

    .line 131
    .line 132
    iput v3, p0, Lu50/o;->e:I

    .line 133
    .line 134
    invoke-virtual {v0, p1, p0}, Ls50/o;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    if-ne p0, v1, :cond_6

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_5
    if-nez p1, :cond_7

    .line 142
    .line 143
    new-instance p0, Lu41/u;

    .line 144
    .line 145
    const/4 p1, 0x4

    .line 146
    invoke-direct {p0, p1}, Lu41/u;-><init>(I)V

    .line 147
    .line 148
    .line 149
    invoke-static {v7, v0, p0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    check-cast p0, Lu50/p;

    .line 157
    .line 158
    invoke-static {v5}, Lu50/r;->h(Lu50/r;)Lql0/g;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 163
    .line 164
    .line 165
    new-instance p0, Lu50/p;

    .line 166
    .line 167
    invoke-direct {p0, p1, v6}, Lu50/p;-><init>(Lql0/g;Z)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v5, p0}, Lql0/j;->g(Lql0/h;)V

    .line 171
    .line 172
    .line 173
    :cond_6
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 174
    .line 175
    :goto_2
    return-object v1

    .line 176
    :cond_7
    new-instance p0, La8/r0;

    .line 177
    .line 178
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 179
    .line 180
    .line 181
    throw p0

    .line 182
    :pswitch_0
    iget-object v0, p0, Lu50/o;->f:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast v0, Lvy0/b0;

    .line 185
    .line 186
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 187
    .line 188
    iget v2, p0, Lu50/o;->e:I

    .line 189
    .line 190
    const/4 v3, 0x1

    .line 191
    if-eqz v2, :cond_9

    .line 192
    .line 193
    if-ne v2, v3, :cond_8

    .line 194
    .line 195
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 200
    .line 201
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 202
    .line 203
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    throw p0

    .line 207
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    iget-object p1, p0, Lu50/o;->g:Lu50/r;

    .line 211
    .line 212
    iget-object v2, p1, Lu50/r;->j:Ls50/q;

    .line 213
    .line 214
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    check-cast v2, Lyy0/i;

    .line 219
    .line 220
    new-instance v4, Lqg/l;

    .line 221
    .line 222
    const/16 v5, 0x11

    .line 223
    .line 224
    invoke-direct {v4, v5, p1, v0}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    const/4 p1, 0x0

    .line 228
    iput-object p1, p0, Lu50/o;->f:Ljava/lang/Object;

    .line 229
    .line 230
    iput v3, p0, Lu50/o;->e:I

    .line 231
    .line 232
    invoke-interface {v2, v4, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    if-ne p0, v1, :cond_a

    .line 237
    .line 238
    goto :goto_4

    .line 239
    :cond_a
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    :goto_4
    return-object v1

    .line 242
    nop

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
