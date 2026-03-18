.class public final Lc00/t1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lyn0/r;

.field public final i:Lij0/a;

.field public final j:Lkf0/v;

.field public final k:Llb0/p;

.field public final l:Llb0/i;

.field public final m:Ljn0/c;

.field public final n:Lrq0/f;

.field public final o:Lyt0/b;

.field public final p:Llb0/u;

.field public final q:Lcs0/n;

.field public final r:Lqf0/g;


# direct methods
.method public constructor <init>(Lyn0/r;Lij0/a;Lkf0/v;Llb0/p;Llb0/i;Ljn0/c;Lrq0/f;Lyt0/b;Llb0/u;Lcs0/n;Lqf0/g;)V
    .locals 3

    .line 1
    new-instance v0, Lc00/n1;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lc00/n1;-><init>(Ljava/util/List;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lc00/t1;->h:Lyn0/r;

    .line 13
    .line 14
    iput-object p2, p0, Lc00/t1;->i:Lij0/a;

    .line 15
    .line 16
    iput-object p3, p0, Lc00/t1;->j:Lkf0/v;

    .line 17
    .line 18
    iput-object p4, p0, Lc00/t1;->k:Llb0/p;

    .line 19
    .line 20
    iput-object p5, p0, Lc00/t1;->l:Llb0/i;

    .line 21
    .line 22
    iput-object p6, p0, Lc00/t1;->m:Ljn0/c;

    .line 23
    .line 24
    iput-object p7, p0, Lc00/t1;->n:Lrq0/f;

    .line 25
    .line 26
    iput-object p8, p0, Lc00/t1;->o:Lyt0/b;

    .line 27
    .line 28
    iput-object p9, p0, Lc00/t1;->p:Llb0/u;

    .line 29
    .line 30
    iput-object p10, p0, Lc00/t1;->q:Lcs0/n;

    .line 31
    .line 32
    iput-object p11, p0, Lc00/t1;->r:Lqf0/g;

    .line 33
    .line 34
    new-instance p1, La50/a;

    .line 35
    .line 36
    const/16 p2, 0x10

    .line 37
    .line 38
    invoke-direct {p1, p0, v2, p2}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public static final h(Lc00/t1;Lne0/s;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lc00/t1;->i:Lij0/a;

    .line 2
    .line 3
    instance-of v1, p2, Lc00/s1;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lc00/s1;

    .line 9
    .line 10
    iget v2, v1, Lc00/s1;->k:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lc00/s1;->k:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lc00/s1;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lc00/s1;-><init>(Lc00/t1;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lc00/s1;->i:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lc00/s1;->k:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    if-eqz v3, :cond_3

    .line 38
    .line 39
    if-eq v3, v5, :cond_2

    .line 40
    .line 41
    if-ne v3, v4, :cond_1

    .line 42
    .line 43
    iget-boolean p0, v1, Lc00/s1;->h:Z

    .line 44
    .line 45
    iget-object p1, v1, Lc00/s1;->g:Ljava/util/List;

    .line 46
    .line 47
    check-cast p1, Ljava/util/List;

    .line 48
    .line 49
    iget-object v2, v1, Lc00/s1;->f:Lc00/n1;

    .line 50
    .line 51
    iget-object v1, v1, Lc00/s1;->e:Lc00/t1;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_3

    .line 57
    .line 58
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_2
    iget-object p1, v1, Lc00/s1;->e:Lc00/t1;

    .line 67
    .line 68
    iget-object v3, v1, Lc00/s1;->d:Lne0/e;

    .line 69
    .line 70
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    move-object v8, v3

    .line 74
    move-object v3, p1

    .line 75
    move-object p1, v8

    .line 76
    goto :goto_1

    .line 77
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    instance-of p2, p1, Lne0/c;

    .line 81
    .line 82
    if-eqz p2, :cond_4

    .line 83
    .line 84
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    check-cast p1, Lc00/n1;

    .line 89
    .line 90
    invoke-static {p1, v0}, Ljp/fc;->b(Lc00/n1;Lij0/a;)Lc00/n1;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    goto/16 :goto_5

    .line 95
    .line 96
    :cond_4
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 97
    .line 98
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    if-eqz p2, :cond_5

    .line 103
    .line 104
    new-instance p1, Lc00/n1;

    .line 105
    .line 106
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    check-cast p2, Lc00/n1;

    .line 111
    .line 112
    iget-object p2, p2, Lc00/n1;->c:Ljava/util/List;

    .line 113
    .line 114
    const/16 v0, 0xa

    .line 115
    .line 116
    invoke-direct {p1, p2, v0}, Lc00/n1;-><init>(Ljava/util/List;I)V

    .line 117
    .line 118
    .line 119
    goto/16 :goto_5

    .line 120
    .line 121
    :cond_5
    instance-of p2, p1, Lne0/e;

    .line 122
    .line 123
    if-eqz p2, :cond_a

    .line 124
    .line 125
    iget-object p2, p0, Lc00/t1;->r:Lqf0/g;

    .line 126
    .line 127
    move-object v3, p1

    .line 128
    check-cast v3, Lne0/e;

    .line 129
    .line 130
    iput-object v3, v1, Lc00/s1;->d:Lne0/e;

    .line 131
    .line 132
    iput-object p0, v1, Lc00/s1;->e:Lc00/t1;

    .line 133
    .line 134
    iput v5, v1, Lc00/s1;->k:I

    .line 135
    .line 136
    invoke-virtual {p2, v6, v1}, Lqf0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p2

    .line 140
    if-ne p2, v2, :cond_6

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_6
    move-object v3, p0

    .line 144
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    check-cast p1, Lne0/e;

    .line 151
    .line 152
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 153
    .line 154
    move-object v5, p1

    .line 155
    check-cast v5, Lmb0/f;

    .line 156
    .line 157
    iget-object v5, v5, Lmb0/f;->a:Lmb0/e;

    .line 158
    .line 159
    invoke-static {v5}, Ljp/a1;->c(Lmb0/e;)Z

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    if-eqz v5, :cond_9

    .line 164
    .line 165
    check-cast p1, Lmb0/f;

    .line 166
    .line 167
    iget-object v5, p1, Lmb0/f;->m:Ljava/util/List;

    .line 168
    .line 169
    check-cast v5, Ljava/util/Collection;

    .line 170
    .line 171
    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    .line 172
    .line 173
    .line 174
    move-result v5

    .line 175
    if-nez v5, :cond_9

    .line 176
    .line 177
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    check-cast v5, Lc00/n1;

    .line 182
    .line 183
    iget-object v7, p1, Lmb0/f;->m:Ljava/util/List;

    .line 184
    .line 185
    iget-object p1, p1, Lmb0/f;->e:Lqr0/q;

    .line 186
    .line 187
    if-nez p1, :cond_8

    .line 188
    .line 189
    iget-object p0, p0, Lc00/t1;->q:Lcs0/n;

    .line 190
    .line 191
    const/4 p1, 0x0

    .line 192
    iput-object p1, v1, Lc00/s1;->d:Lne0/e;

    .line 193
    .line 194
    iput-object v3, v1, Lc00/s1;->e:Lc00/t1;

    .line 195
    .line 196
    iput-object v5, v1, Lc00/s1;->f:Lc00/n1;

    .line 197
    .line 198
    move-object p1, v7

    .line 199
    check-cast p1, Ljava/util/List;

    .line 200
    .line 201
    iput-object p1, v1, Lc00/s1;->g:Ljava/util/List;

    .line 202
    .line 203
    iput-boolean p2, v1, Lc00/s1;->h:Z

    .line 204
    .line 205
    iput v4, v1, Lc00/s1;->k:I

    .line 206
    .line 207
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 208
    .line 209
    .line 210
    invoke-virtual {p0, v1}, Lcs0/n;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    if-ne p0, v2, :cond_7

    .line 215
    .line 216
    :goto_2
    return-object v2

    .line 217
    :cond_7
    move p1, p2

    .line 218
    move-object p2, p0

    .line 219
    move p0, p1

    .line 220
    move-object v1, v3

    .line 221
    move-object v2, v5

    .line 222
    move-object p1, v7

    .line 223
    :goto_3
    check-cast p2, Lqr0/q;

    .line 224
    .line 225
    move-object v7, p1

    .line 226
    move-object p1, p2

    .line 227
    move-object v5, v2

    .line 228
    move p2, p0

    .line 229
    move-object p0, v1

    .line 230
    goto :goto_4

    .line 231
    :cond_8
    move-object p0, v3

    .line 232
    :goto_4
    invoke-static {v5, v7, p1, v0, p2}, Ljp/fc;->i(Lc00/n1;Ljava/util/List;Lqr0/q;Lij0/a;Z)Lc00/n1;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    goto :goto_5

    .line 237
    :cond_9
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    check-cast p0, Lc00/n1;

    .line 242
    .line 243
    invoke-static {p0, v0}, Ljp/fc;->b(Lc00/n1;Lij0/a;)Lc00/n1;

    .line 244
    .line 245
    .line 246
    move-result-object p1

    .line 247
    move-object p0, v3

    .line 248
    :goto_5
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 249
    .line 250
    .line 251
    return-object v6

    .line 252
    :cond_a
    new-instance p0, La8/r0;

    .line 253
    .line 254
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 255
    .line 256
    .line 257
    throw p0
.end method
