.class public final Lm70/h0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:Lm70/g0;

.field public e:Lm70/f0;

.field public f:Lm70/j0;

.field public g:I

.field public synthetic h:Ljava/util/List;

.field public synthetic i:Ljava/util/List;

.field public synthetic j:Ljava/util/Map;

.field public final synthetic k:Lm70/j0;


# direct methods
.method public constructor <init>(Lm70/j0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm70/h0;->k:Lm70/j0;

    .line 2
    .line 3
    const/4 p1, 0x4

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Ljava/util/List;

    .line 2
    .line 3
    check-cast p2, Ljava/util/List;

    .line 4
    .line 5
    check-cast p3, Ljava/util/Map;

    .line 6
    .line 7
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance v0, Lm70/h0;

    .line 10
    .line 11
    iget-object p0, p0, Lm70/h0;->k:Lm70/j0;

    .line 12
    .line 13
    invoke-direct {v0, p0, p4}, Lm70/h0;-><init>(Lm70/j0;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    check-cast p1, Ljava/util/List;

    .line 17
    .line 18
    iput-object p1, v0, Lm70/h0;->h:Ljava/util/List;

    .line 19
    .line 20
    check-cast p2, Ljava/util/List;

    .line 21
    .line 22
    iput-object p2, v0, Lm70/h0;->i:Ljava/util/List;

    .line 23
    .line 24
    iput-object p3, v0, Lm70/h0;->j:Ljava/util/Map;

    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Lm70/h0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lm70/h0;->k:Lm70/j0;

    .line 4
    .line 5
    iget-object v2, v1, Lm70/j0;->p:Lij0/a;

    .line 6
    .line 7
    iget-object v3, v0, Lm70/h0;->h:Ljava/util/List;

    .line 8
    .line 9
    check-cast v3, Ljava/util/List;

    .line 10
    .line 11
    iget-object v4, v0, Lm70/h0;->i:Ljava/util/List;

    .line 12
    .line 13
    move-object v9, v4

    .line 14
    check-cast v9, Ljava/util/List;

    .line 15
    .line 16
    iget-object v7, v0, Lm70/h0;->j:Ljava/util/Map;

    .line 17
    .line 18
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v5, v0, Lm70/h0;->g:I

    .line 21
    .line 22
    const/4 v6, 0x1

    .line 23
    const/4 v8, 0x0

    .line 24
    if-eqz v5, :cond_1

    .line 25
    .line 26
    if-ne v5, v6, :cond_0

    .line 27
    .line 28
    iget-object v3, v0, Lm70/h0;->f:Lm70/j0;

    .line 29
    .line 30
    iget-object v4, v0, Lm70/h0;->e:Lm70/f0;

    .line 31
    .line 32
    iget-object v0, v0, Lm70/h0;->d:Lm70/g0;

    .line 33
    .line 34
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    move-object v5, v0

    .line 38
    move-object v13, v4

    .line 39
    move-object/from16 v0, p1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0

    .line 50
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    check-cast v5, Lm70/g0;

    .line 58
    .line 59
    new-instance v10, Lm70/f0;

    .line 60
    .line 61
    invoke-direct {v10, v3}, Lm70/f0;-><init>(Ljava/util/List;)V

    .line 62
    .line 63
    .line 64
    iget-object v3, v1, Lm70/j0;->n:Lcs0/l;

    .line 65
    .line 66
    iput-object v8, v0, Lm70/h0;->h:Ljava/util/List;

    .line 67
    .line 68
    move-object v11, v9

    .line 69
    check-cast v11, Ljava/util/List;

    .line 70
    .line 71
    iput-object v11, v0, Lm70/h0;->i:Ljava/util/List;

    .line 72
    .line 73
    iput-object v7, v0, Lm70/h0;->j:Ljava/util/Map;

    .line 74
    .line 75
    iput-object v5, v0, Lm70/h0;->d:Lm70/g0;

    .line 76
    .line 77
    iput-object v10, v0, Lm70/h0;->e:Lm70/f0;

    .line 78
    .line 79
    iput-object v1, v0, Lm70/h0;->f:Lm70/j0;

    .line 80
    .line 81
    iput v6, v0, Lm70/h0;->g:I

    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v3, v0}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    if-ne v0, v4, :cond_2

    .line 91
    .line 92
    return-object v4

    .line 93
    :cond_2
    move-object v3, v1

    .line 94
    move-object v13, v10

    .line 95
    :goto_0
    check-cast v0, Lqr0/s;

    .line 96
    .line 97
    const/16 v18, 0x0

    .line 98
    .line 99
    const/16 v19, 0x1f71

    .line 100
    .line 101
    const/4 v6, 0x0

    .line 102
    const/4 v10, 0x0

    .line 103
    const/4 v11, 0x0

    .line 104
    const/4 v12, 0x0

    .line 105
    const/4 v14, 0x0

    .line 106
    const/4 v15, 0x0

    .line 107
    const/16 v16, 0x0

    .line 108
    .line 109
    const/16 v17, 0x0

    .line 110
    .line 111
    move-object/from16 v20, v8

    .line 112
    .line 113
    move-object v8, v0

    .line 114
    move-object/from16 v0, v20

    .line 115
    .line 116
    invoke-static/range {v5 .. v19}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    invoke-static {v4, v2}, Lip/t;->j(Lm70/g0;Lij0/a;)Lm70/g0;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    invoke-virtual {v3, v4}, Lql0/j;->g(Lql0/h;)V

    .line 125
    .line 126
    .line 127
    new-instance v3, Ll70/y;

    .line 128
    .line 129
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    check-cast v4, Lm70/g0;

    .line 134
    .line 135
    iget-object v4, v4, Lm70/g0;->s:Ll70/v;

    .line 136
    .line 137
    iget-object v4, v4, Ll70/v;->a:Ll70/w;

    .line 138
    .line 139
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 140
    .line 141
    .line 142
    move-result-object v5

    .line 143
    check-cast v5, Lm70/g0;

    .line 144
    .line 145
    iget v5, v5, Lm70/g0;->e:I

    .line 146
    .line 147
    invoke-direct {v3, v4, v5}, Ll70/y;-><init>(Ll70/w;I)V

    .line 148
    .line 149
    .line 150
    invoke-interface {v7, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    instance-of v4, v3, Lne0/c;

    .line 155
    .line 156
    if-eqz v4, :cond_3

    .line 157
    .line 158
    move-object v8, v3

    .line 159
    check-cast v8, Lne0/c;

    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_3
    move-object v8, v0

    .line 163
    :goto_1
    if-eqz v8, :cond_4

    .line 164
    .line 165
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    check-cast v3, Lm70/g0;

    .line 170
    .line 171
    invoke-static {v3, v2}, Lip/t;->h(Lm70/g0;Lij0/a;)Lm70/g0;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    invoke-virtual {v1, v2}, Lql0/j;->g(Lql0/h;)V

    .line 176
    .line 177
    .line 178
    invoke-static {v1}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    new-instance v3, Lm70/i0;

    .line 183
    .line 184
    const/4 v4, 0x1

    .line 185
    invoke-direct {v3, v4, v1, v8, v0}, Lm70/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 186
    .line 187
    .line 188
    const/4 v1, 0x3

    .line 189
    invoke-static {v2, v0, v0, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 190
    .line 191
    .line 192
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    :cond_4
    return-object v0
.end method
