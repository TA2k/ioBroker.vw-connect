.class public final Lvy/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lvy/v;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lvy/v;)V
    .locals 0

    .line 1
    iput p1, p0, Lvy/q;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lvy/q;->h:Lvy/v;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lvy/q;->d:I

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
    new-instance v0, Lvy/q;

    .line 11
    .line 12
    iget-object p0, p0, Lvy/q;->h:Lvy/v;

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    invoke-direct {v0, v1, p3, p0}, Lvy/q;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lvy/q;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lvy/q;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lvy/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lvy/q;

    .line 30
    .line 31
    iget-object p0, p0, Lvy/q;->h:Lvy/v;

    .line 32
    .line 33
    const/4 v1, 0x1

    .line 34
    invoke-direct {v0, v1, p3, p0}, Lvy/q;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lvy/q;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lvy/q;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lvy/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    new-instance v0, Lvy/q;

    .line 49
    .line 50
    iget-object p0, p0, Lvy/q;->h:Lvy/v;

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    invoke-direct {v0, v1, p3, p0}, Lvy/q;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 54
    .line 55
    .line 56
    iput-object p1, v0, Lvy/q;->f:Lyy0/j;

    .line 57
    .line 58
    iput-object p2, v0, Lvy/q;->g:Ljava/lang/Object;

    .line 59
    .line 60
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Lvy/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lvy/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lvy/q;->e:I

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
    iget-object p1, p0, Lvy/q;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lvy/q;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lne0/t;

    .line 35
    .line 36
    instance-of v3, v1, Lne0/e;

    .line 37
    .line 38
    if-eqz v3, :cond_2

    .line 39
    .line 40
    check-cast v1, Lne0/e;

    .line 41
    .line 42
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Ljava/util/List;

    .line 45
    .line 46
    iget-object v3, p0, Lvy/q;->h:Lvy/v;

    .line 47
    .line 48
    iget-object v3, v3, Lvy/v;->v:Lty/o;

    .line 49
    .line 50
    invoke-virtual {v3, v1}, Lty/o;->a(Ljava/util/List;)Lyy0/m1;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    goto :goto_0

    .line 55
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 56
    .line 57
    if-eqz v3, :cond_4

    .line 58
    .line 59
    new-instance v3, Lyy0/m;

    .line 60
    .line 61
    const/4 v4, 0x0

    .line 62
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 63
    .line 64
    .line 65
    move-object v1, v3

    .line 66
    :goto_0
    const/4 v3, 0x0

    .line 67
    iput-object v3, p0, Lvy/q;->f:Lyy0/j;

    .line 68
    .line 69
    iput-object v3, p0, Lvy/q;->g:Ljava/lang/Object;

    .line 70
    .line 71
    iput v2, p0, Lvy/q;->e:I

    .line 72
    .line 73
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    if-ne p0, v0, :cond_3

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    :goto_2
    return-object v0

    .line 83
    :cond_4
    new-instance p0, La8/r0;

    .line 84
    .line 85
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 90
    .line 91
    iget v1, p0, Lvy/q;->e:I

    .line 92
    .line 93
    const/4 v2, 0x1

    .line 94
    if-eqz v1, :cond_6

    .line 95
    .line 96
    if-ne v1, v2, :cond_5

    .line 97
    .line 98
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_4

    .line 102
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 103
    .line 104
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 105
    .line 106
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    iget-object p1, p0, Lvy/q;->f:Lyy0/j;

    .line 114
    .line 115
    iget-object v1, p0, Lvy/q;->g:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v1, Lne0/t;

    .line 118
    .line 119
    instance-of v3, v1, Lne0/e;

    .line 120
    .line 121
    const/4 v4, 0x0

    .line 122
    if-eqz v3, :cond_7

    .line 123
    .line 124
    check-cast v1, Lne0/e;

    .line 125
    .line 126
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v1, Luy/b;

    .line 129
    .line 130
    iget-object v3, p0, Lvy/q;->h:Lvy/v;

    .line 131
    .line 132
    iget-object v3, v3, Lvy/v;->p:Lyn0/h;

    .line 133
    .line 134
    iget-object v1, v1, Luy/b;->d:Ljava/util/ArrayList;

    .line 135
    .line 136
    const-string v5, "<this>"

    .line 137
    .line 138
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    new-instance v5, Lh7/z;

    .line 142
    .line 143
    invoke-direct {v5, v3, v1, v4}, Lh7/z;-><init>(Ltr0/c;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 144
    .line 145
    .line 146
    new-instance v1, Lyy0/m1;

    .line 147
    .line 148
    invoke-direct {v1, v5}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 149
    .line 150
    .line 151
    new-instance v3, Lal0/i;

    .line 152
    .line 153
    const/16 v5, 0xd

    .line 154
    .line 155
    invoke-direct {v3, v1, v5}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 156
    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_7
    instance-of v3, v1, Lne0/c;

    .line 160
    .line 161
    if-eqz v3, :cond_9

    .line 162
    .line 163
    new-instance v3, Lyy0/m;

    .line 164
    .line 165
    const/4 v5, 0x0

    .line 166
    invoke-direct {v3, v1, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 167
    .line 168
    .line 169
    :goto_3
    iput-object v4, p0, Lvy/q;->f:Lyy0/j;

    .line 170
    .line 171
    iput-object v4, p0, Lvy/q;->g:Ljava/lang/Object;

    .line 172
    .line 173
    iput v2, p0, Lvy/q;->e:I

    .line 174
    .line 175
    invoke-static {p1, v3, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    if-ne p0, v0, :cond_8

    .line 180
    .line 181
    goto :goto_5

    .line 182
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    :goto_5
    return-object v0

    .line 185
    :cond_9
    new-instance p0, La8/r0;

    .line 186
    .line 187
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 188
    .line 189
    .line 190
    throw p0

    .line 191
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 192
    .line 193
    iget v1, p0, Lvy/q;->e:I

    .line 194
    .line 195
    const/4 v2, 0x1

    .line 196
    if-eqz v1, :cond_b

    .line 197
    .line 198
    if-ne v1, v2, :cond_a

    .line 199
    .line 200
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 205
    .line 206
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 207
    .line 208
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    throw p0

    .line 212
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    iget-object p1, p0, Lvy/q;->f:Lyy0/j;

    .line 216
    .line 217
    iget-object v1, p0, Lvy/q;->g:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v1, Lne0/t;

    .line 220
    .line 221
    iget-object v1, p0, Lvy/q;->h:Lvy/v;

    .line 222
    .line 223
    iget-object v1, v1, Lvy/v;->n:Lty/c;

    .line 224
    .line 225
    new-instance v3, Lty/b;

    .line 226
    .line 227
    const/4 v4, 0x0

    .line 228
    invoke-direct {v3, v4}, Lty/b;-><init>(Z)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v1, v3}, Lty/c;->a(Lty/b;)Lzy0/j;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    const/4 v3, 0x0

    .line 236
    iput-object v3, p0, Lvy/q;->f:Lyy0/j;

    .line 237
    .line 238
    iput-object v3, p0, Lvy/q;->g:Ljava/lang/Object;

    .line 239
    .line 240
    iput v2, p0, Lvy/q;->e:I

    .line 241
    .line 242
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    if-ne p0, v0, :cond_c

    .line 247
    .line 248
    goto :goto_7

    .line 249
    :cond_c
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 250
    .line 251
    :goto_7
    return-object v0

    .line 252
    nop

    .line 253
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
