.class public final Lpp0/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lyy0/j;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lpp0/n;

.field public final synthetic h:Lqp0/o;

.field public i:Lyy0/j;

.field public j:Lqp0/p;

.field public k:Lqp0/r;

.field public l:Lnp0/c;

.field public m:I

.field public n:Z


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lpp0/n;Lqp0/o;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lpp0/l;->g:Lpp0/n;

    .line 2
    .line 3
    iput-object p3, p0, Lpp0/l;->h:Lqp0/o;

    .line 4
    .line 5
    const/4 p2, 0x3

    .line 6
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    new-instance v0, Lpp0/l;

    .line 6
    .line 7
    iget-object v1, p0, Lpp0/l;->g:Lpp0/n;

    .line 8
    .line 9
    iget-object p0, p0, Lpp0/l;->h:Lqp0/o;

    .line 10
    .line 11
    invoke-direct {v0, p3, v1, p0}, Lpp0/l;-><init>(Lkotlin/coroutines/Continuation;Lpp0/n;Lqp0/o;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lpp0/l;->e:Lyy0/j;

    .line 15
    .line 16
    iput-object p2, v0, Lpp0/l;->f:Ljava/lang/Object;

    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Lpp0/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lpp0/l;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x1

    .line 8
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    iget-object v6, p0, Lpp0/l;->g:Lpp0/n;

    .line 11
    .line 12
    const/4 v7, 0x0

    .line 13
    if-eqz v1, :cond_3

    .line 14
    .line 15
    if-eq v1, v4, :cond_2

    .line 16
    .line 17
    if-eq v1, v3, :cond_1

    .line 18
    .line 19
    if-ne v1, v2, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object v5

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    iget-boolean v1, p0, Lpp0/l;->n:Z

    .line 34
    .line 35
    iget-object v3, p0, Lpp0/l;->l:Lnp0/c;

    .line 36
    .line 37
    iget-object v4, p0, Lpp0/l;->k:Lqp0/r;

    .line 38
    .line 39
    iget-object v8, p0, Lpp0/l;->j:Lqp0/p;

    .line 40
    .line 41
    iget-object v9, p0, Lpp0/l;->i:Lyy0/j;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    iget v1, p0, Lpp0/l;->m:I

    .line 48
    .line 49
    iget-object v4, p0, Lpp0/l;->k:Lqp0/r;

    .line 50
    .line 51
    iget-object v8, p0, Lpp0/l;->j:Lqp0/p;

    .line 52
    .line 53
    iget-object v9, p0, Lpp0/l;->i:Lyy0/j;

    .line 54
    .line 55
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Lpp0/l;->e:Lyy0/j;

    .line 63
    .line 64
    iget-object v1, p0, Lpp0/l;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v1, Llx0/l;

    .line 67
    .line 68
    iget-object v8, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v8, Lqp0/p;

    .line 71
    .line 72
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Lqp0/r;

    .line 75
    .line 76
    iget-object v9, v6, Lpp0/n;->a:Lkf0/k;

    .line 77
    .line 78
    iput-object v7, p0, Lpp0/l;->e:Lyy0/j;

    .line 79
    .line 80
    iput-object v7, p0, Lpp0/l;->f:Ljava/lang/Object;

    .line 81
    .line 82
    iput-object p1, p0, Lpp0/l;->i:Lyy0/j;

    .line 83
    .line 84
    iput-object v8, p0, Lpp0/l;->j:Lqp0/p;

    .line 85
    .line 86
    iput-object v1, p0, Lpp0/l;->k:Lqp0/r;

    .line 87
    .line 88
    const/4 v10, 0x0

    .line 89
    iput v10, p0, Lpp0/l;->m:I

    .line 90
    .line 91
    iput v4, p0, Lpp0/l;->d:I

    .line 92
    .line 93
    invoke-virtual {v9, p0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    if-ne v4, v0, :cond_4

    .line 98
    .line 99
    goto/16 :goto_4

    .line 100
    .line 101
    :cond_4
    move-object v9, p1

    .line 102
    move-object p1, v4

    .line 103
    move-object v4, v1

    .line 104
    move v1, v10

    .line 105
    :goto_0
    check-cast p1, Lss0/b;

    .line 106
    .line 107
    sget-object v10, Lss0/e;->t:Lss0/e;

    .line 108
    .line 109
    invoke-static {p1, v10}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    iget-object v10, v6, Lpp0/n;->d:Lnp0/c;

    .line 114
    .line 115
    iget-object v11, v6, Lpp0/n;->b:Lkf0/o;

    .line 116
    .line 117
    iput-object v7, p0, Lpp0/l;->e:Lyy0/j;

    .line 118
    .line 119
    iput-object v7, p0, Lpp0/l;->f:Ljava/lang/Object;

    .line 120
    .line 121
    iput-object v9, p0, Lpp0/l;->i:Lyy0/j;

    .line 122
    .line 123
    iput-object v8, p0, Lpp0/l;->j:Lqp0/p;

    .line 124
    .line 125
    iput-object v4, p0, Lpp0/l;->k:Lqp0/r;

    .line 126
    .line 127
    iput-object v10, p0, Lpp0/l;->l:Lnp0/c;

    .line 128
    .line 129
    iput v1, p0, Lpp0/l;->m:I

    .line 130
    .line 131
    iput-boolean p1, p0, Lpp0/l;->n:Z

    .line 132
    .line 133
    iput v3, p0, Lpp0/l;->d:I

    .line 134
    .line 135
    invoke-virtual {v11, v5, p0}, Lkf0/o;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    if-ne v1, v0, :cond_5

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_5
    move-object v3, v1

    .line 143
    move v1, p1

    .line 144
    move-object p1, v3

    .line 145
    move-object v3, v10

    .line 146
    :goto_1
    check-cast p1, Lne0/t;

    .line 147
    .line 148
    instance-of v10, p1, Lne0/c;

    .line 149
    .line 150
    if-eqz v10, :cond_6

    .line 151
    .line 152
    move-object p1, v7

    .line 153
    goto :goto_2

    .line 154
    :cond_6
    instance-of v10, p1, Lne0/e;

    .line 155
    .line 156
    if-eqz v10, :cond_9

    .line 157
    .line 158
    check-cast p1, Lne0/e;

    .line 159
    .line 160
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 161
    .line 162
    :goto_2
    check-cast p1, Lss0/j0;

    .line 163
    .line 164
    if-eqz p1, :cond_7

    .line 165
    .line 166
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_7
    move-object p1, v7

    .line 170
    :goto_3
    iget-object v10, v8, Lqp0/p;->a:Ljava/util/List;

    .line 171
    .line 172
    new-instance v11, Lqp0/s;

    .line 173
    .line 174
    invoke-direct {v11, v4, v1}, Lqp0/s;-><init>(Lqp0/r;Z)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v3, p1, v10, v11}, Lnp0/c;->a(Ljava/lang/String;Ljava/util/List;Lqp0/s;)Lyy0/m1;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    new-instance v1, Lag/t;

    .line 182
    .line 183
    iget-object v3, p0, Lpp0/l;->h:Lqp0/o;

    .line 184
    .line 185
    const/16 v4, 0x9

    .line 186
    .line 187
    invoke-direct {v1, v3, v4}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 188
    .line 189
    .line 190
    invoke-static {p1, v1}, Lbb/j0;->b(Lyy0/i;Lay0/k;)Lne0/k;

    .line 191
    .line 192
    .line 193
    move-result-object p1

    .line 194
    new-instance v1, Lny/f0;

    .line 195
    .line 196
    const/4 v3, 0x7

    .line 197
    invoke-direct {v1, v3, v6, v8, v7}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 198
    .line 199
    .line 200
    invoke-static {v1, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    iput-object v7, p0, Lpp0/l;->e:Lyy0/j;

    .line 205
    .line 206
    iput-object v7, p0, Lpp0/l;->f:Ljava/lang/Object;

    .line 207
    .line 208
    iput-object v7, p0, Lpp0/l;->i:Lyy0/j;

    .line 209
    .line 210
    iput-object v7, p0, Lpp0/l;->j:Lqp0/p;

    .line 211
    .line 212
    iput-object v7, p0, Lpp0/l;->k:Lqp0/r;

    .line 213
    .line 214
    iput-object v7, p0, Lpp0/l;->l:Lnp0/c;

    .line 215
    .line 216
    iput v2, p0, Lpp0/l;->d:I

    .line 217
    .line 218
    invoke-static {v9, p1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    if-ne p0, v0, :cond_8

    .line 223
    .line 224
    :goto_4
    return-object v0

    .line 225
    :cond_8
    return-object v5

    .line 226
    :cond_9
    new-instance p0, La8/r0;

    .line 227
    .line 228
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 229
    .line 230
    .line 231
    throw p0
.end method
