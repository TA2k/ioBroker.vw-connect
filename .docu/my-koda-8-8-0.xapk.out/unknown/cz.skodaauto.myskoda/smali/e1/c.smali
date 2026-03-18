.class public final Le1/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Z

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lg1/z1;

.field public final synthetic h:J

.field public final synthetic i:Li1/l;

.field public final synthetic j:Le1/h;


# direct methods
.method public constructor <init>(Lg1/z1;JLi1/l;Le1/h;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le1/c;->g:Lg1/z1;

    .line 2
    .line 3
    iput-wide p2, p0, Le1/c;->h:J

    .line 4
    .line 5
    iput-object p4, p0, Le1/c;->i:Li1/l;

    .line 6
    .line 7
    iput-object p5, p0, Le1/c;->j:Le1/h;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Le1/c;

    .line 2
    .line 3
    iget-object v4, p0, Le1/c;->i:Li1/l;

    .line 4
    .line 5
    iget-object v5, p0, Le1/c;->j:Le1/h;

    .line 6
    .line 7
    iget-object v1, p0, Le1/c;->g:Lg1/z1;

    .line 8
    .line 9
    iget-wide v2, p0, Le1/c;->h:J

    .line 10
    .line 11
    move-object v6, p2

    .line 12
    invoke-direct/range {v0 .. v6}, Le1/c;-><init>(Lg1/z1;JLi1/l;Le1/h;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Le1/c;->f:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0
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
    invoke-virtual {p0, p1, p2}, Le1/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Le1/c;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Le1/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Le1/c;->e:I

    .line 6
    .line 7
    iget-object v4, v0, Le1/c;->j:Le1/h;

    .line 8
    .line 9
    const/4 v10, 0x5

    .line 10
    const/4 v11, 0x4

    .line 11
    const/4 v12, 0x3

    .line 12
    const/4 v13, 0x2

    .line 13
    const/4 v14, 0x1

    .line 14
    iget-object v15, v0, Le1/c;->i:Li1/l;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    if-eqz v2, :cond_5

    .line 18
    .line 19
    if-eq v2, v14, :cond_4

    .line 20
    .line 21
    if-eq v2, v13, :cond_3

    .line 22
    .line 23
    if-eq v2, v12, :cond_2

    .line 24
    .line 25
    if-eq v2, v11, :cond_1

    .line 26
    .line 27
    if-ne v2, v10, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_1
    :goto_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move-object v10, v3

    .line 42
    goto/16 :goto_6

    .line 43
    .line 44
    :cond_2
    iget-object v2, v0, Le1/c;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v2, Li1/o;

    .line 47
    .line 48
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object v10, v3

    .line 52
    goto/16 :goto_3

    .line 53
    .line 54
    :cond_3
    iget-boolean v2, v0, Le1/c;->d:Z

    .line 55
    .line 56
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    move-object v10, v3

    .line 60
    goto :goto_2

    .line 61
    :cond_4
    iget-object v2, v0, Le1/c;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v2, Lvy0/i1;

    .line 64
    .line 65
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move-object v10, v3

    .line 69
    move-object/from16 v3, p1

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v2, v0, Le1/c;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v2, Lvy0/b0;

    .line 78
    .line 79
    move-object v5, v3

    .line 80
    new-instance v3, Le1/b;

    .line 81
    .line 82
    const/4 v8, 0x0

    .line 83
    const/4 v9, 0x0

    .line 84
    move-object v7, v5

    .line 85
    iget-wide v5, v0, Le1/c;->h:J

    .line 86
    .line 87
    move-object/from16 v16, v7

    .line 88
    .line 89
    iget-object v7, v0, Le1/c;->i:Li1/l;

    .line 90
    .line 91
    move-object/from16 v10, v16

    .line 92
    .line 93
    invoke-direct/range {v3 .. v9}, Le1/b;-><init>(Ljava/lang/Object;JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 94
    .line 95
    .line 96
    invoke-static {v2, v10, v10, v3, v12}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    iput-object v2, v0, Le1/c;->f:Ljava/lang/Object;

    .line 101
    .line 102
    iput v14, v0, Le1/c;->e:I

    .line 103
    .line 104
    iget-object v3, v0, Le1/c;->g:Lg1/z1;

    .line 105
    .line 106
    invoke-virtual {v3, v0}, Lg1/z1;->f(Lrx0/c;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    if-ne v3, v1, :cond_6

    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_6
    :goto_1
    check-cast v3, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    invoke-interface {v2}, Lvy0/i1;->a()Z

    .line 120
    .line 121
    .line 122
    move-result v5

    .line 123
    if-eqz v5, :cond_9

    .line 124
    .line 125
    iput-object v10, v0, Le1/c;->f:Ljava/lang/Object;

    .line 126
    .line 127
    iput-boolean v3, v0, Le1/c;->d:Z

    .line 128
    .line 129
    iput v13, v0, Le1/c;->e:I

    .line 130
    .line 131
    invoke-static {v2, v0}, Lvy0/e0;->m(Lvy0/i1;Lrx0/c;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    if-ne v2, v1, :cond_7

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_7
    move v2, v3

    .line 139
    :goto_2
    if-eqz v2, :cond_b

    .line 140
    .line 141
    new-instance v2, Li1/n;

    .line 142
    .line 143
    iget-wide v5, v0, Le1/c;->h:J

    .line 144
    .line 145
    invoke-direct {v2, v5, v6}, Li1/n;-><init>(J)V

    .line 146
    .line 147
    .line 148
    new-instance v3, Li1/o;

    .line 149
    .line 150
    invoke-direct {v3, v2}, Li1/o;-><init>(Li1/n;)V

    .line 151
    .line 152
    .line 153
    iput-object v3, v0, Le1/c;->f:Ljava/lang/Object;

    .line 154
    .line 155
    iput v12, v0, Le1/c;->e:I

    .line 156
    .line 157
    invoke-virtual {v15, v2, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v2

    .line 161
    if-ne v2, v1, :cond_8

    .line 162
    .line 163
    goto :goto_5

    .line 164
    :cond_8
    move-object v2, v3

    .line 165
    :goto_3
    iput-object v10, v0, Le1/c;->f:Ljava/lang/Object;

    .line 166
    .line 167
    iput v11, v0, Le1/c;->e:I

    .line 168
    .line 169
    invoke-virtual {v15, v2, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    if-ne v0, v1, :cond_b

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_9
    iget-object v2, v4, Le1/h;->E:Li1/n;

    .line 177
    .line 178
    if-eqz v2, :cond_b

    .line 179
    .line 180
    if-eqz v3, :cond_a

    .line 181
    .line 182
    new-instance v3, Li1/o;

    .line 183
    .line 184
    invoke-direct {v3, v2}, Li1/o;-><init>(Li1/n;)V

    .line 185
    .line 186
    .line 187
    goto :goto_4

    .line 188
    :cond_a
    new-instance v3, Li1/m;

    .line 189
    .line 190
    invoke-direct {v3, v2}, Li1/m;-><init>(Li1/n;)V

    .line 191
    .line 192
    .line 193
    :goto_4
    iput-object v10, v0, Le1/c;->f:Ljava/lang/Object;

    .line 194
    .line 195
    const/4 v2, 0x5

    .line 196
    iput v2, v0, Le1/c;->e:I

    .line 197
    .line 198
    invoke-virtual {v15, v3, v0}, Li1/l;->a(Li1/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-ne v0, v1, :cond_b

    .line 203
    .line 204
    :goto_5
    return-object v1

    .line 205
    :cond_b
    :goto_6
    iput-object v10, v4, Le1/h;->E:Li1/n;

    .line 206
    .line 207
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    return-object v0
.end method
