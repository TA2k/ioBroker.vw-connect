.class public final Lc80/y;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwq0/i0;

.field public final i:Lwq0/g;

.field public final j:Lwq0/m;

.field public final k:Lwq0/y;

.field public final l:Lij0/a;

.field public final m:Lzd0/a;

.field public n:Lne0/c;


# direct methods
.method public constructor <init>(Lwq0/i0;Lwq0/g;Lwq0/m;Lwq0/y;Lij0/a;Lzd0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lc80/w;

    .line 2
    .line 3
    const/16 v1, 0x3f

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v2, v3, v1}, Lc80/w;-><init>(ZLjava/lang/String;I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lc80/y;->h:Lwq0/i0;

    .line 14
    .line 15
    iput-object p2, p0, Lc80/y;->i:Lwq0/g;

    .line 16
    .line 17
    iput-object p3, p0, Lc80/y;->j:Lwq0/m;

    .line 18
    .line 19
    iput-object p4, p0, Lc80/y;->k:Lwq0/y;

    .line 20
    .line 21
    iput-object p5, p0, Lc80/y;->l:Lij0/a;

    .line 22
    .line 23
    iput-object p6, p0, Lc80/y;->m:Lzd0/a;

    .line 24
    .line 25
    new-instance p1, Lc80/v;

    .line 26
    .line 27
    const/4 p2, 0x0

    .line 28
    invoke-direct {p1, p0, v3, p2}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public static final h(Lc80/y;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lc80/y;->l:Lij0/a;

    .line 6
    .line 7
    instance-of v3, v1, Lc80/x;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lc80/x;

    .line 13
    .line 14
    iget v4, v3, Lc80/x;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lc80/x;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc80/x;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lc80/x;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lc80/x;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc80/x;->g:I

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x1

    .line 39
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    if-eqz v5, :cond_3

    .line 42
    .line 43
    if-eq v5, v7, :cond_2

    .line 44
    .line 45
    if-ne v5, v6, :cond_1

    .line 46
    .line 47
    iget-boolean v3, v3, Lc80/x;->d:Z

    .line 48
    .line 49
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_3

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object v1, v0, Lc80/y;->j:Lwq0/m;

    .line 69
    .line 70
    iput v7, v3, Lc80/x;->g:I

    .line 71
    .line 72
    invoke-virtual {v1, v8, v3}, Lwq0/m;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    if-ne v1, v4, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    :goto_1
    check-cast v1, Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    iget-object v5, v0, Lc80/y;->i:Lwq0/g;

    .line 86
    .line 87
    iput-boolean v1, v3, Lc80/x;->d:Z

    .line 88
    .line 89
    iput v6, v3, Lc80/x;->g:I

    .line 90
    .line 91
    invoke-virtual {v5, v8, v3}, Lwq0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    if-ne v3, v4, :cond_5

    .line 96
    .line 97
    :goto_2
    return-object v4

    .line 98
    :cond_5
    move-object/from16 v16, v3

    .line 99
    .line 100
    move v3, v1

    .line 101
    move-object/from16 v1, v16

    .line 102
    .line 103
    :goto_3
    sget-object v4, Lyq0/a;->a:Lyq0/a;

    .line 104
    .line 105
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v12

    .line 109
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    move-object v9, v1

    .line 114
    check-cast v9, Lc80/w;

    .line 115
    .line 116
    const-string v1, "\n\n"

    .line 117
    .line 118
    const v4, 0x7f121247

    .line 119
    .line 120
    .line 121
    const/4 v5, 0x0

    .line 122
    if-eqz v12, :cond_6

    .line 123
    .line 124
    if-eqz v3, :cond_6

    .line 125
    .line 126
    new-array v3, v5, [Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v2, Ljj0/f;

    .line 129
    .line 130
    invoke-virtual {v2, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    const v4, 0x7f121249

    .line 135
    .line 136
    .line 137
    new-array v5, v5, [Ljava/lang/Object;

    .line 138
    .line 139
    invoke-virtual {v2, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    invoke-static {v3, v1, v2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    :goto_4
    move-object v13, v1

    .line 148
    goto :goto_5

    .line 149
    :cond_6
    if-eqz v12, :cond_7

    .line 150
    .line 151
    if-nez v3, :cond_7

    .line 152
    .line 153
    new-array v3, v5, [Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v2, Ljj0/f;

    .line 156
    .line 157
    invoke-virtual {v2, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    const v4, 0x7f121248

    .line 162
    .line 163
    .line 164
    new-array v5, v5, [Ljava/lang/Object;

    .line 165
    .line 166
    invoke-virtual {v2, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    invoke-static {v3, v1, v2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    goto :goto_4

    .line 175
    :cond_7
    new-array v1, v5, [Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v2, Ljj0/f;

    .line 178
    .line 179
    invoke-virtual {v2, v4, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    goto :goto_4

    .line 184
    :goto_5
    const/4 v14, 0x0

    .line 185
    const/16 v15, 0x30

    .line 186
    .line 187
    const/4 v10, 0x0

    .line 188
    const/4 v11, 0x0

    .line 189
    invoke-static/range {v9 .. v15}, Lc80/w;->a(Lc80/w;Lql0/g;ZZLjava/lang/String;ZI)Lc80/w;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 194
    .line 195
    .line 196
    return-object v8
.end method


# virtual methods
.method public final j()V
    .locals 4

    .line 1
    new-instance v0, Lne0/e;

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc80/y;->m:Lzd0/a;

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Lzd0/a;->a(Lne0/t;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lc80/w;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    const/16 v2, 0x3f

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    invoke-direct {v0, v3, v1, v2}, Lc80/w;-><init>(ZLjava/lang/String;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
