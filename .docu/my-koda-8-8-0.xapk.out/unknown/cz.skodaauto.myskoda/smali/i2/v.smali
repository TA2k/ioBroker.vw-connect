.class public final Li2/v;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Lyy0/j1;

.field public f:Lp3/l;

.field public g:J

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Lvy0/b0;

.field public final synthetic k:Lh2/yb;


# direct methods
.method public constructor <init>(Lvy0/b0;Lh2/yb;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Li2/v;->j:Lvy0/b0;

    .line 2
    .line 3
    iput-object p2, p0, Li2/v;->k:Lh2/yb;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Li2/v;

    .line 2
    .line 3
    iget-object v1, p0, Li2/v;->j:Lvy0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Li2/v;->k:Lh2/yb;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Li2/v;-><init>(Lvy0/b0;Lh2/yb;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Li2/v;->i:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Li2/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Li2/v;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Li2/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Li2/v;->h:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x3

    .line 7
    const/4 v4, 0x1

    .line 8
    const/4 v5, 0x0

    .line 9
    if-eqz v1, :cond_3

    .line 10
    .line 11
    if-eq v1, v4, :cond_2

    .line 12
    .line 13
    if-eq v1, v2, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Li2/v;->i:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lyy0/j1;

    .line 20
    .line 21
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    .line 24
    goto/16 :goto_6

    .line 25
    .line 26
    :catchall_0
    move-exception p1

    .line 27
    goto/16 :goto_7

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
    iget-object v1, p0, Li2/v;->f:Lp3/l;

    .line 38
    .line 39
    iget-object v2, p0, Li2/v;->e:Lyy0/j1;

    .line 40
    .line 41
    iget-object v6, p0, Li2/v;->i:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v6, Lp3/i0;

    .line 44
    .line 45
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Lp3/n; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 46
    .line 47
    .line 48
    goto/16 :goto_3

    .line 49
    .line 50
    :catchall_1
    move-exception p1

    .line 51
    move-object p0, v2

    .line 52
    goto/16 :goto_7

    .line 53
    .line 54
    :catch_0
    move-object v8, v1

    .line 55
    move-object v1, v2

    .line 56
    goto/16 :goto_4

    .line 57
    .line 58
    :cond_2
    iget-wide v6, p0, Li2/v;->g:J

    .line 59
    .line 60
    iget-object v1, p0, Li2/v;->f:Lp3/l;

    .line 61
    .line 62
    iget-object v8, p0, Li2/v;->e:Lyy0/j1;

    .line 63
    .line 64
    iget-object v9, p0, Li2/v;->i:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v9, Lp3/i0;

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    move-object v10, v8

    .line 72
    move-object v8, v1

    .line 73
    move-object v1, v10

    .line 74
    move-wide v11, v6

    .line 75
    move-object v6, v9

    .line 76
    :goto_0
    move-wide v9, v11

    .line 77
    goto :goto_1

    .line 78
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iget-object p1, p0, Li2/v;->i:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p1, Lp3/i0;

    .line 84
    .line 85
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 86
    .line 87
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-virtual {p1}, Lp3/i0;->f()Lw3/h2;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    invoke-interface {v6}, Lw3/h2;->b()J

    .line 96
    .line 97
    .line 98
    move-result-wide v6

    .line 99
    sget-object v8, Lp3/l;->d:Lp3/l;

    .line 100
    .line 101
    iput-object p1, p0, Li2/v;->i:Ljava/lang/Object;

    .line 102
    .line 103
    iput-object v1, p0, Li2/v;->e:Lyy0/j1;

    .line 104
    .line 105
    iput-object v8, p0, Li2/v;->f:Lp3/l;

    .line 106
    .line 107
    iput-wide v6, p0, Li2/v;->g:J

    .line 108
    .line 109
    iput v4, p0, Li2/v;->h:I

    .line 110
    .line 111
    invoke-static {p1, p0, v4}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    if-ne v9, v0, :cond_4

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_4
    move-wide v11, v6

    .line 119
    move-object v6, p1

    .line 120
    move-object p1, v9

    .line 121
    goto :goto_0

    .line 122
    :goto_1
    check-cast p1, Lp3/t;

    .line 123
    .line 124
    iget p1, p1, Lp3/t;->i:I

    .line 125
    .line 126
    if-ne p1, v4, :cond_5

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_5
    if-ne p1, v3, :cond_9

    .line 130
    .line 131
    :goto_2
    :try_start_2
    new-instance p1, Ld6/t0;

    .line 132
    .line 133
    const/4 v7, 0x3

    .line 134
    invoke-direct {p1, v8, v5, v7}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 135
    .line 136
    .line 137
    iput-object v6, p0, Li2/v;->i:Ljava/lang/Object;

    .line 138
    .line 139
    iput-object v1, p0, Li2/v;->e:Lyy0/j1;

    .line 140
    .line 141
    iput-object v8, p0, Li2/v;->f:Lp3/l;

    .line 142
    .line 143
    iput v2, p0, Li2/v;->h:I

    .line 144
    .line 145
    invoke-virtual {v6, v9, v10, p1, p0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p0
    :try_end_2
    .catch Lp3/n; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 149
    if-ne p0, v0, :cond_6

    .line 150
    .line 151
    goto :goto_5

    .line 152
    :cond_6
    move-object v2, v1

    .line 153
    :goto_3
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 154
    .line 155
    check-cast v2, Lyy0/c2;

    .line 156
    .line 157
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v2, v5, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    goto :goto_8

    .line 164
    :catchall_2
    move-exception p1

    .line 165
    move-object p0, v1

    .line 166
    goto :goto_7

    .line 167
    :catch_1
    :goto_4
    :try_start_3
    iget-object p1, p0, Li2/v;->j:Lvy0/b0;

    .line 168
    .line 169
    sget-object v2, Lvy0/c0;->g:Lvy0/c0;

    .line 170
    .line 171
    new-instance v7, Lg1/y2;

    .line 172
    .line 173
    iget-object v9, p0, Li2/v;->k:Lh2/yb;

    .line 174
    .line 175
    const/16 v10, 0x13

    .line 176
    .line 177
    invoke-direct {v7, v10, v1, v9, v5}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 178
    .line 179
    .line 180
    invoke-static {p1, v5, v2, v7, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 181
    .line 182
    .line 183
    iput-object v1, p0, Li2/v;->i:Ljava/lang/Object;

    .line 184
    .line 185
    iput-object v5, p0, Li2/v;->e:Lyy0/j1;

    .line 186
    .line 187
    iput-object v5, p0, Li2/v;->f:Lp3/l;

    .line 188
    .line 189
    iput v3, p0, Li2/v;->h:I

    .line 190
    .line 191
    invoke-static {v6, v8, p0}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 195
    if-ne p1, v0, :cond_7

    .line 196
    .line 197
    :goto_5
    return-object v0

    .line 198
    :cond_7
    move-object p0, v1

    .line 199
    :goto_6
    :try_start_4
    check-cast p1, Lp3/t;

    .line 200
    .line 201
    if-eqz p1, :cond_8

    .line 202
    .line 203
    invoke-virtual {p1}, Lp3/t;->a()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 204
    .line 205
    .line 206
    :cond_8
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 207
    .line 208
    check-cast p0, Lyy0/c2;

    .line 209
    .line 210
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    invoke-virtual {p0, v5, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    goto :goto_8

    .line 217
    :goto_7
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 218
    .line 219
    check-cast p0, Lyy0/c2;

    .line 220
    .line 221
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 222
    .line 223
    .line 224
    invoke-virtual {p0, v5, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    throw p1

    .line 228
    :cond_9
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    return-object p0
.end method
