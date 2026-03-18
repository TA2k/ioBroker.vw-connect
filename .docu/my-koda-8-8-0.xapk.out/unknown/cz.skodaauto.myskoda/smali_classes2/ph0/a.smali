.class public final Lph0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public final synthetic e:Lk21/a;

.field public final synthetic f:J

.field public g:Lcu/b;

.field public h:Lcu/b;

.field public i:I

.field public j:I


# direct methods
.method public constructor <init>(Lk21/a;Lkotlin/coroutines/Continuation;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lph0/a;->e:Lk21/a;

    .line 2
    .line 3
    iput-wide p3, p0, Lph0/a;->f:J

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
    .locals 3

    .line 1
    new-instance p1, Lph0/a;

    .line 2
    .line 3
    iget-object v0, p0, Lph0/a;->e:Lk21/a;

    .line 4
    .line 5
    iget-wide v1, p0, Lph0/a;->f:J

    .line 6
    .line 7
    invoke-direct {p1, v0, p2, v1, v2}, Lph0/a;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;J)V

    .line 8
    .line 9
    .line 10
    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lph0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lph0/a;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lph0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lph0/a;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x1

    .line 8
    if-eqz v1, :cond_3

    .line 9
    .line 10
    if-eq v1, v4, :cond_2

    .line 11
    .line 12
    if-eq v1, v3, :cond_1

    .line 13
    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lph0/a;->h:Lcu/b;

    .line 17
    .line 18
    iget-object p0, p0, Lph0/a;->g:Lcu/b;

    .line 19
    .line 20
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lsr/h; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :catch_0
    move-exception p1

    .line 25
    goto/16 :goto_3

    .line 26
    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    iget v1, p0, Lph0/a;->j:I

    .line 36
    .line 37
    iget v4, p0, Lph0/a;->i:I

    .line 38
    .line 39
    iget-object v5, p0, Lph0/a;->h:Lcu/b;

    .line 40
    .line 41
    iget-object v6, p0, Lph0/a;->g:Lcu/b;

    .line 42
    .line 43
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Lsr/h; {:try_start_1 .. :try_end_1} :catch_1

    .line 44
    .line 45
    .line 46
    move-object p1, v6

    .line 47
    goto/16 :goto_1

    .line 48
    .line 49
    :catch_1
    move-exception p1

    .line 50
    move-object v0, v5

    .line 51
    move-object p0, v6

    .line 52
    goto/16 :goto_3

    .line 53
    .line 54
    :cond_2
    iget v1, p0, Lph0/a;->j:I

    .line 55
    .line 56
    iget v4, p0, Lph0/a;->i:I

    .line 57
    .line 58
    iget-object v5, p0, Lph0/a;->h:Lcu/b;

    .line 59
    .line 60
    iget-object v6, p0, Lph0/a;->g:Lcu/b;

    .line 61
    .line 62
    :try_start_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catch Lsr/h; {:try_start_2 .. :try_end_2} :catch_1

    .line 63
    .line 64
    .line 65
    move-object p1, v6

    .line 66
    goto :goto_0

    .line 67
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    const-class v1, Lcu/j;

    .line 75
    .line 76
    invoke-virtual {p1, v1}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Lcu/j;

    .line 81
    .line 82
    const-string v1, "firebase"

    .line 83
    .line 84
    invoke-virtual {p1, v1}, Lcu/j;->a(Ljava/lang/String;)Lcu/b;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    :try_start_3
    invoke-virtual {p1}, Lcu/b;->d()Laq/t;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    iput-object p1, p0, Lph0/a;->g:Lcu/b;

    .line 93
    .line 94
    iput-object p1, p0, Lph0/a;->h:Lcu/b;

    .line 95
    .line 96
    const/4 v5, 0x0

    .line 97
    iput v5, p0, Lph0/a;->i:I

    .line 98
    .line 99
    iput v5, p0, Lph0/a;->j:I

    .line 100
    .line 101
    iput v4, p0, Lph0/a;->d:I

    .line 102
    .line 103
    invoke-static {v1, p0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v1
    :try_end_3
    .catch Lsr/h; {:try_start_3 .. :try_end_3} :catch_3

    .line 107
    if-ne v1, v0, :cond_4

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    move v1, v5

    .line 111
    move v4, v1

    .line 112
    move-object v5, p1

    .line 113
    :goto_0
    :try_start_4
    iget-wide v6, p0, Lph0/a;->f:J

    .line 114
    .line 115
    sget v8, Lmy0/c;->g:I

    .line 116
    .line 117
    sget-object v8, Lmy0/e;->h:Lmy0/e;

    .line 118
    .line 119
    invoke-static {v6, v7, v8}, Lmy0/c;->n(JLmy0/e;)J

    .line 120
    .line 121
    .line 122
    move-result-wide v6

    .line 123
    iget-object v8, v5, Lcu/b;->g:Ldu/i;

    .line 124
    .line 125
    invoke-virtual {v8, v6, v7}, Ldu/i;->a(J)Laq/t;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    sget-object v7, Lhs/i;->d:Lhs/i;

    .line 130
    .line 131
    new-instance v8, Lc1/y;

    .line 132
    .line 133
    const/16 v9, 0x12

    .line 134
    .line 135
    invoke-direct {v8, v9}, Lc1/y;-><init>(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v6, v7, v8}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    iput-object p1, p0, Lph0/a;->g:Lcu/b;

    .line 143
    .line 144
    iput-object v5, p0, Lph0/a;->h:Lcu/b;

    .line 145
    .line 146
    iput v4, p0, Lph0/a;->i:I

    .line 147
    .line 148
    iput v1, p0, Lph0/a;->j:I

    .line 149
    .line 150
    iput v3, p0, Lph0/a;->d:I

    .line 151
    .line 152
    invoke-static {v6, p0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    if-ne v6, v0, :cond_5

    .line 157
    .line 158
    goto :goto_2

    .line 159
    :cond_5
    :goto_1
    iget-object v6, v5, Lcu/b;->d:Ldu/c;

    .line 160
    .line 161
    invoke-virtual {v6}, Ldu/c;->b()Laq/j;

    .line 162
    .line 163
    .line 164
    move-result-object v6

    .line 165
    iget-object v7, v5, Lcu/b;->e:Ldu/c;

    .line 166
    .line 167
    invoke-virtual {v7}, Ldu/c;->b()Laq/j;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    filled-new-array {v6, v7}, [Laq/j;

    .line 172
    .line 173
    .line 174
    move-result-object v8

    .line 175
    invoke-static {v8}, Ljp/l1;->g([Laq/j;)Laq/t;

    .line 176
    .line 177
    .line 178
    move-result-object v8

    .line 179
    iget-object v9, v5, Lcu/b;->c:Ljava/util/concurrent/Executor;

    .line 180
    .line 181
    new-instance v10, Lbb/i;

    .line 182
    .line 183
    invoke-direct {v10, v5, v6, v7, v3}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v8, v9, v10}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 187
    .line 188
    .line 189
    move-result-object v3

    .line 190
    iput-object p1, p0, Lph0/a;->g:Lcu/b;

    .line 191
    .line 192
    iput-object v5, p0, Lph0/a;->h:Lcu/b;

    .line 193
    .line 194
    iput v4, p0, Lph0/a;->i:I

    .line 195
    .line 196
    iput v1, p0, Lph0/a;->j:I

    .line 197
    .line 198
    iput v2, p0, Lph0/a;->d:I

    .line 199
    .line 200
    invoke-static {v3, p0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p0
    :try_end_4
    .catch Lsr/h; {:try_start_4 .. :try_end_4} :catch_2

    .line 204
    if-ne p0, v0, :cond_6

    .line 205
    .line 206
    :goto_2
    return-object v0

    .line 207
    :cond_6
    return-object p1

    .line 208
    :catch_2
    move-exception p0

    .line 209
    move-object v0, p1

    .line 210
    move-object p1, p0

    .line 211
    move-object p0, v0

    .line 212
    move-object v0, v5

    .line 213
    goto :goto_3

    .line 214
    :catch_3
    move-exception p0

    .line 215
    move-object v0, p1

    .line 216
    move-object p1, p0

    .line 217
    move-object p0, v0

    .line 218
    :goto_3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    new-instance v1, Lep0/f;

    .line 222
    .line 223
    const/16 v2, 0xb

    .line 224
    .line 225
    invoke-direct {v1, p1, v2}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 226
    .line 227
    .line 228
    const/4 p1, 0x0

    .line 229
    invoke-static {p1, v0, v1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 230
    .line 231
    .line 232
    return-object p0
.end method
