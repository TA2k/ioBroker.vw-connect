.class public final Lr30/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Ljava/util/Iterator;

.field public e:Ljava/util/Iterator;

.field public f:I

.field public final synthetic g:Z

.field public final synthetic h:Lv2/o;

.field public final synthetic i:Ll2/b1;

.field public final synthetic j:Ljava/util/List;

.field public final synthetic k:Lay0/a;


# direct methods
.method public constructor <init>(ZLv2/o;Ll2/b1;Ljava/util/List;Lay0/a;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lr30/f;->g:Z

    .line 2
    .line 3
    iput-object p2, p0, Lr30/f;->h:Lv2/o;

    .line 4
    .line 5
    iput-object p3, p0, Lr30/f;->i:Ll2/b1;

    .line 6
    .line 7
    iput-object p4, p0, Lr30/f;->j:Ljava/util/List;

    .line 8
    .line 9
    iput-object p5, p0, Lr30/f;->k:Lay0/a;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Lr30/f;

    .line 2
    .line 3
    iget-object v4, p0, Lr30/f;->j:Ljava/util/List;

    .line 4
    .line 5
    iget-object v5, p0, Lr30/f;->k:Lay0/a;

    .line 6
    .line 7
    iget-boolean v1, p0, Lr30/f;->g:Z

    .line 8
    .line 9
    iget-object v2, p0, Lr30/f;->h:Lv2/o;

    .line 10
    .line 11
    iget-object v3, p0, Lr30/f;->i:Ll2/b1;

    .line 12
    .line 13
    move-object v6, p2

    .line 14
    invoke-direct/range {v0 .. v6}, Lr30/f;-><init>(ZLv2/o;Ll2/b1;Ljava/util/List;Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 15
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
    invoke-virtual {p0, p1, p2}, Lr30/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lr30/f;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lr30/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lr30/f;->f:I

    .line 6
    .line 7
    const/4 v3, 0x6

    .line 8
    iget-object v8, v0, Lr30/f;->k:Lay0/a;

    .line 9
    .line 10
    const-string v9, " "

    .line 11
    .line 12
    iget-object v10, v0, Lr30/f;->i:Ll2/b1;

    .line 13
    .line 14
    iget-boolean v11, v0, Lr30/f;->g:Z

    .line 15
    .line 16
    const/4 v12, 0x2

    .line 17
    const/4 v13, 0x1

    .line 18
    iget-object v14, v0, Lr30/f;->h:Lv2/o;

    .line 19
    .line 20
    if-eqz v2, :cond_2

    .line 21
    .line 22
    if-eq v2, v13, :cond_1

    .line 23
    .line 24
    if-ne v2, v12, :cond_0

    .line 25
    .line 26
    iget-object v2, v0, Lr30/f;->e:Ljava/util/Iterator;

    .line 27
    .line 28
    iget-object v13, v0, Lr30/f;->d:Ljava/util/Iterator;

    .line 29
    .line 30
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    move-object v4, v13

    .line 34
    goto/16 :goto_4

    .line 35
    .line 36
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v0

    .line 44
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object v2, Lr30/h;->a:Lc1/s;

    .line 52
    .line 53
    if-eqz v11, :cond_3

    .line 54
    .line 55
    const-wide/16 v4, 0x96

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_3
    const-wide/16 v4, 0x0

    .line 59
    .line 60
    :goto_0
    iput v13, v0, Lr30/f;->f:I

    .line 61
    .line 62
    invoke-static {v4, v5, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    if-ne v2, v1, :cond_4

    .line 67
    .line 68
    goto/16 :goto_6

    .line 69
    .line 70
    :cond_4
    :goto_1
    invoke-virtual {v14}, Lv2/o;->clear()V

    .line 71
    .line 72
    .line 73
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Ljava/lang/Boolean;

    .line 78
    .line 79
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    iget-object v4, v0, Lr30/f;->j:Ljava/util/List;

    .line 84
    .line 85
    if-eqz v2, :cond_7

    .line 86
    .line 87
    check-cast v4, Ljava/lang/Iterable;

    .line 88
    .line 89
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    :cond_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-eqz v1, :cond_6

    .line 98
    .line 99
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    check-cast v1, Ljava/lang/String;

    .line 104
    .line 105
    filled-new-array {v9}, [Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    invoke-static {v1, v2, v3}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    check-cast v1, Ljava/lang/Iterable;

    .line 114
    .line 115
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-eqz v2, :cond_5

    .line 124
    .line 125
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    check-cast v2, Ljava/lang/String;

    .line 130
    .line 131
    invoke-virtual {v14, v2}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_6
    invoke-interface {v8}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_7
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-eqz v4, :cond_b

    .line 148
    .line 149
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    check-cast v4, Ljava/lang/String;

    .line 154
    .line 155
    filled-new-array {v9}, [Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v5

    .line 159
    invoke-static {v4, v5, v3}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 160
    .line 161
    .line 162
    move-result-object v4

    .line 163
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    move-object v15, v4

    .line 168
    move-object v4, v2

    .line 169
    move-object v2, v15

    .line 170
    :cond_8
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v5

    .line 174
    if-eqz v5, :cond_a

    .line 175
    .line 176
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v5

    .line 180
    check-cast v5, Ljava/lang/String;

    .line 181
    .line 182
    invoke-virtual {v14, v5}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    sget-object v5, Lr30/h;->a:Lc1/s;

    .line 186
    .line 187
    if-eqz v11, :cond_9

    .line 188
    .line 189
    const-wide/16 v6, 0x96

    .line 190
    .line 191
    goto :goto_5

    .line 192
    :cond_9
    const-wide/16 v6, 0x0

    .line 193
    .line 194
    :goto_5
    iput-object v4, v0, Lr30/f;->d:Ljava/util/Iterator;

    .line 195
    .line 196
    iput-object v2, v0, Lr30/f;->e:Ljava/util/Iterator;

    .line 197
    .line 198
    iput v12, v0, Lr30/f;->f:I

    .line 199
    .line 200
    invoke-static {v6, v7, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v5

    .line 204
    if-ne v5, v1, :cond_8

    .line 205
    .line 206
    :goto_6
    return-object v1

    .line 207
    :cond_a
    move-object v2, v4

    .line 208
    goto :goto_3

    .line 209
    :cond_b
    invoke-interface {v8}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 213
    .line 214
    invoke-interface {v10, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    return-object v0
.end method
