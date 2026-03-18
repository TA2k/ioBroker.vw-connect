.class public final Lpp0/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/k;

.field public final b:Lpp0/c0;


# direct methods
.method public constructor <init>(Lkf0/k;Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/o1;->a:Lkf0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/o1;->b:Lpp0/c0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lpp0/o1;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lpp0/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lpp0/n1;

    .line 7
    .line 8
    iget v1, v0, Lpp0/n1;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lpp0/n1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/n1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lpp0/n1;-><init>(Lpp0/o1;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lpp0/n1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/n1;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lpp0/n1;->d:Lpp0/c0;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto/16 :goto_6

    .line 45
    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput v4, v0, Lpp0/n1;->g:I

    .line 62
    .line 63
    iget-object p1, p0, Lpp0/o1;->a:Lkf0/k;

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v1, :cond_4

    .line 70
    .line 71
    goto/16 :goto_5

    .line 72
    .line 73
    :cond_4
    :goto_1
    check-cast p1, Lss0/b;

    .line 74
    .line 75
    invoke-static {p1}, Ljp/yf;->m(Lss0/b;)I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    new-instance v2, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-direct {v2, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lpp0/o1;->b:Lpp0/c0;

    .line 85
    .line 86
    move-object p1, p0

    .line 87
    check-cast p1, Lnp0/b;

    .line 88
    .line 89
    iget-object v4, p1, Lnp0/b;->h:Lyy0/c2;

    .line 90
    .line 91
    iget-object v5, p1, Lnp0/b;->f:Lyy0/c2;

    .line 92
    .line 93
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    check-cast v5, Lqp0/o;

    .line 98
    .line 99
    if-eqz v5, :cond_8

    .line 100
    .line 101
    iget-object v6, v5, Lqp0/o;->a:Ljava/util/List;

    .line 102
    .line 103
    check-cast v6, Ljava/lang/Iterable;

    .line 104
    .line 105
    new-instance v7, Ljava/util/ArrayList;

    .line 106
    .line 107
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 108
    .line 109
    .line 110
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    :cond_5
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result v8

    .line 118
    if-eqz v8, :cond_6

    .line 119
    .line 120
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    move-object v9, v8

    .line 125
    check-cast v9, Lqp0/b0;

    .line 126
    .line 127
    iget-object v9, v9, Lqp0/b0;->c:Lqp0/t0;

    .line 128
    .line 129
    sget-object v10, Lqp0/g0;->a:Lqp0/g0;

    .line 130
    .line 131
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v9

    .line 135
    if-nez v9, :cond_5

    .line 136
    .line 137
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_6
    new-instance v6, Ljava/util/ArrayList;

    .line 142
    .line 143
    const/16 v8, 0xa

    .line 144
    .line 145
    invoke-static {v7, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 146
    .line 147
    .line 148
    move-result v8

    .line 149
    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 157
    .line 158
    .line 159
    move-result v8

    .line 160
    if-eqz v8, :cond_7

    .line 161
    .line 162
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v8

    .line 166
    check-cast v8, Lqp0/b0;

    .line 167
    .line 168
    new-instance v9, Ljava/security/SecureRandom;

    .line 169
    .line 170
    invoke-direct {v9}, Ljava/security/SecureRandom;-><init>()V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v9}, Ljava/util/Random;->nextInt()I

    .line 174
    .line 175
    .line 176
    move-result v9

    .line 177
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v9

    .line 181
    new-instance v10, Llx0/l;

    .line 182
    .line 183
    invoke-direct {v10, v9, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_7
    iget-boolean v5, v5, Lqp0/o;->h:Z

    .line 191
    .line 192
    new-instance v7, Lqp0/g;

    .line 193
    .line 194
    invoke-direct {v7, v6, v2, v5}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 195
    .line 196
    .line 197
    invoke-static {v7}, Ljp/bg;->e(Lqp0/g;)Lqp0/g;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    goto :goto_4

    .line 202
    :cond_8
    const/4 v2, 0x0

    .line 203
    :goto_4
    invoke-virtual {v4, v2}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    iget-object p1, p1, Lnp0/b;->i:Lyy0/l1;

    .line 207
    .line 208
    iput-object p0, v0, Lpp0/n1;->d:Lpp0/c0;

    .line 209
    .line 210
    iput v3, v0, Lpp0/n1;->g:I

    .line 211
    .line 212
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    if-ne p1, v1, :cond_9

    .line 217
    .line 218
    :goto_5
    return-object v1

    .line 219
    :cond_9
    :goto_6
    check-cast p1, Lqp0/g;

    .line 220
    .line 221
    check-cast p0, Lnp0/b;

    .line 222
    .line 223
    iget-object p0, p0, Lnp0/b;->j:Lyy0/c2;

    .line 224
    .line 225
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    return-object p0
.end method
