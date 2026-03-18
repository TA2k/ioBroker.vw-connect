.class public final Lym/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public final synthetic e:Z

.field public final synthetic f:Lym/g;

.field public final synthetic g:Lum/a;

.field public final synthetic h:I

.field public final synthetic i:F

.field public final synthetic j:Ll2/b1;


# direct methods
.method public constructor <init>(ZLym/g;Lum/a;IFLl2/b1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    .line 1
    sget-object v0, Lym/k;->d:Lym/k;

    .line 2
    .line 3
    iput-boolean p1, p0, Lym/a;->e:Z

    .line 4
    .line 5
    iput-object p2, p0, Lym/a;->f:Lym/g;

    .line 6
    .line 7
    iput-object p3, p0, Lym/a;->g:Lum/a;

    .line 8
    .line 9
    iput p4, p0, Lym/a;->h:I

    .line 10
    .line 11
    iput p5, p0, Lym/a;->i:F

    .line 12
    .line 13
    iput-object p6, p0, Lym/a;->j:Ll2/b1;

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    new-instance v0, Lym/a;

    .line 2
    .line 3
    sget-object p1, Lym/k;->d:Lym/k;

    .line 4
    .line 5
    iget-object v6, p0, Lym/a;->j:Ll2/b1;

    .line 6
    .line 7
    iget-boolean v1, p0, Lym/a;->e:Z

    .line 8
    .line 9
    iget-object v2, p0, Lym/a;->f:Lym/g;

    .line 10
    .line 11
    iget-object v3, p0, Lym/a;->g:Lum/a;

    .line 12
    .line 13
    iget v4, p0, Lym/a;->h:I

    .line 14
    .line 15
    iget v5, p0, Lym/a;->i:F

    .line 16
    .line 17
    move-object v7, p2

    .line 18
    invoke-direct/range {v0 .. v7}, Lym/a;-><init>(ZLym/g;Lum/a;IFLl2/b1;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
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
    invoke-virtual {p0, p1, p2}, Lym/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lym/a;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lym/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lym/a;->d:I

    .line 4
    .line 5
    iget-object v3, p0, Lym/a;->f:Lym/g;

    .line 6
    .line 7
    iget-object v8, p0, Lym/a;->j:Ll2/b1;

    .line 8
    .line 9
    const/4 v9, 0x2

    .line 10
    iget-boolean v10, p0, Lym/a;->e:Z

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    sget-object v11, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    if-eq v1, v2, :cond_1

    .line 18
    .line 19
    if-ne v1, v9, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object v11

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_5

    .line 37
    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    if-eqz v10, :cond_a

    .line 42
    .line 43
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Ljava/lang/Boolean;

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    if-nez p1, :cond_a

    .line 54
    .line 55
    iput v2, p0, Lym/a;->d:I

    .line 56
    .line 57
    iget-object p1, v3, Lym/g;->l:Ll2/j1;

    .line 58
    .line 59
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    check-cast p1, Lum/a;

    .line 64
    .line 65
    iget-object v1, v3, Lym/g;->h:Ll2/j1;

    .line 66
    .line 67
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    if-nez v1, :cond_9

    .line 72
    .line 73
    iget-object v1, v3, Lym/g;->i:Ll2/j1;

    .line 74
    .line 75
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Ljava/lang/Number;

    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    const/4 v4, 0x0

    .line 86
    cmpg-float v1, v1, v4

    .line 87
    .line 88
    if-gez v1, :cond_3

    .line 89
    .line 90
    if-nez p1, :cond_3

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_3
    if-nez p1, :cond_4

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_4
    if-gez v1, :cond_5

    .line 97
    .line 98
    :goto_0
    const/high16 v4, 0x3f800000    # 1.0f

    .line 99
    .line 100
    :cond_5
    :goto_1
    move v5, v4

    .line 101
    iget-object p1, v3, Lym/g;->l:Ll2/j1;

    .line 102
    .line 103
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    move-object v4, p1

    .line 108
    check-cast v4, Lum/a;

    .line 109
    .line 110
    iget-object p1, v3, Lym/g;->n:Ll2/j1;

    .line 111
    .line 112
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    check-cast p1, Ljava/lang/Number;

    .line 117
    .line 118
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    cmpg-float p1, v5, p1

    .line 123
    .line 124
    if-nez p1, :cond_6

    .line 125
    .line 126
    move p1, v2

    .line 127
    goto :goto_2

    .line 128
    :cond_6
    const/4 p1, 0x0

    .line 129
    :goto_2
    xor-int/lit8 v6, p1, 0x1

    .line 130
    .line 131
    iget-object p1, v3, Lym/g;->q:Le1/b1;

    .line 132
    .line 133
    new-instance v2, Lym/f;

    .line 134
    .line 135
    const/4 v7, 0x0

    .line 136
    invoke-direct/range {v2 .. v7}, Lym/f;-><init>(Lym/g;Lum/a;FZLkotlin/coroutines/Continuation;)V

    .line 137
    .line 138
    .line 139
    invoke-static {p1, v2, p0}, Le1/b1;->b(Le1/b1;Lay0/k;Lrx0/i;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    if-ne p1, v0, :cond_7

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_7
    move-object p1, v11

    .line 147
    :goto_3
    if-ne p1, v0, :cond_8

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_8
    move-object p1, v11

    .line 151
    :goto_4
    if-ne p1, v0, :cond_a

    .line 152
    .line 153
    goto :goto_7

    .line 154
    :cond_9
    new-instance p0, Ljava/lang/ClassCastException;

    .line 155
    .line 156
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 157
    .line 158
    .line 159
    throw p0

    .line 160
    :cond_a
    :goto_5
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    invoke-interface {v8, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    if-nez v10, :cond_b

    .line 168
    .line 169
    goto :goto_8

    .line 170
    :cond_b
    iget-object p1, v3, Lym/g;->n:Ll2/j1;

    .line 171
    .line 172
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    check-cast p1, Ljava/lang/Number;

    .line 177
    .line 178
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 179
    .line 180
    .line 181
    move-result v8

    .line 182
    move p1, v9

    .line 183
    sget-object v9, Lym/k;->d:Lym/k;

    .line 184
    .line 185
    iput p1, p0, Lym/a;->d:I

    .line 186
    .line 187
    invoke-virtual {v3}, Lym/g;->d()I

    .line 188
    .line 189
    .line 190
    move-result v4

    .line 191
    iget-object p1, v3, Lym/g;->q:Le1/b1;

    .line 192
    .line 193
    new-instance v2, Lym/c;

    .line 194
    .line 195
    const/4 v10, 0x0

    .line 196
    iget v5, p0, Lym/a;->h:I

    .line 197
    .line 198
    iget v6, p0, Lym/a;->i:F

    .line 199
    .line 200
    iget-object v7, p0, Lym/a;->g:Lum/a;

    .line 201
    .line 202
    invoke-direct/range {v2 .. v10}, Lym/c;-><init>(Lym/g;IIFLum/a;FLym/k;Lkotlin/coroutines/Continuation;)V

    .line 203
    .line 204
    .line 205
    invoke-static {p1, v2, p0}, Le1/b1;->b(Le1/b1;Lay0/k;Lrx0/i;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    if-ne p0, v0, :cond_c

    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_c
    move-object p0, v11

    .line 213
    :goto_6
    if-ne p0, v0, :cond_d

    .line 214
    .line 215
    :goto_7
    return-object v0

    .line 216
    :cond_d
    :goto_8
    return-object v11
.end method
