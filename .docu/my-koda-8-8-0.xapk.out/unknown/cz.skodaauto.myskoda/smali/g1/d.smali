.class public final Lg1/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:I

.field public synthetic e:Lg1/p;

.field public synthetic f:Lg1/z;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lg1/q;

.field public final synthetic i:F

.field public final synthetic j:Lc1/j;

.field public final synthetic k:Lkotlin/jvm/internal/c0;

.field public final synthetic l:Lc1/u;


# direct methods
.method public constructor <init>(Lg1/q;FLc1/j;Lkotlin/jvm/internal/c0;Lc1/u;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/d;->h:Lg1/q;

    .line 2
    .line 3
    iput p2, p0, Lg1/d;->i:F

    .line 4
    .line 5
    iput-object p3, p0, Lg1/d;->j:Lc1/j;

    .line 6
    .line 7
    iput-object p4, p0, Lg1/d;->k:Lkotlin/jvm/internal/c0;

    .line 8
    .line 9
    iput-object p5, p0, Lg1/d;->l:Lc1/u;

    .line 10
    .line 11
    const/4 p1, 0x4

    .line 12
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Lg1/p;

    .line 2
    .line 3
    check-cast p2, Lg1/z;

    .line 4
    .line 5
    move-object v6, p4

    .line 6
    check-cast v6, Lkotlin/coroutines/Continuation;

    .line 7
    .line 8
    new-instance v0, Lg1/d;

    .line 9
    .line 10
    iget-object v4, p0, Lg1/d;->k:Lkotlin/jvm/internal/c0;

    .line 11
    .line 12
    iget-object v5, p0, Lg1/d;->l:Lc1/u;

    .line 13
    .line 14
    iget-object v1, p0, Lg1/d;->h:Lg1/q;

    .line 15
    .line 16
    iget v2, p0, Lg1/d;->i:F

    .line 17
    .line 18
    iget-object v3, p0, Lg1/d;->j:Lc1/j;

    .line 19
    .line 20
    invoke-direct/range {v0 .. v6}, Lg1/d;-><init>(Lg1/q;FLc1/j;Lkotlin/jvm/internal/c0;Lc1/u;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, v0, Lg1/d;->e:Lg1/p;

    .line 24
    .line 25
    iput-object p2, v0, Lg1/d;->f:Lg1/z;

    .line 26
    .line 27
    iput-object p3, v0, Lg1/d;->g:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Lg1/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lg1/d;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x1

    .line 8
    iget-object v9, p0, Lg1/d;->k:Lkotlin/jvm/internal/c0;

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    if-eqz v1, :cond_3

    .line 12
    .line 13
    if-eq v1, v4, :cond_2

    .line 14
    .line 15
    if-eq v1, v3, :cond_1

    .line 16
    .line 17
    if-ne v1, v2, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    move-object p1, v9

    .line 23
    goto/16 :goto_2

    .line 24
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
    goto/16 :goto_6

    .line 37
    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move-object p1, v9

    .line 42
    goto/16 :goto_5

    .line 43
    .line 44
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-object v8, p0, Lg1/d;->e:Lg1/p;

    .line 48
    .line 49
    move-object p1, v9

    .line 50
    iget-object v9, p0, Lg1/d;->f:Lg1/z;

    .line 51
    .line 52
    iget-object v10, p0, Lg1/d;->g:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-virtual {v9, v10}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    invoke-static {v6}, Ljava/lang/Float;->isNaN(F)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-nez v1, :cond_c

    .line 63
    .line 64
    new-instance v7, Lkotlin/jvm/internal/c0;

    .line 65
    .line 66
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lg1/d;->h:Lg1/q;

    .line 70
    .line 71
    iget-object v11, v1, Lg1/q;->i:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v11, Ll2/f1;

    .line 74
    .line 75
    invoke-virtual {v11}, Ll2/f1;->o()F

    .line 76
    .line 77
    .line 78
    move-result v11

    .line 79
    invoke-static {v11}, Ljava/lang/Float;->isNaN(F)Z

    .line 80
    .line 81
    .line 82
    move-result v11

    .line 83
    if-eqz v11, :cond_4

    .line 84
    .line 85
    move v1, v5

    .line 86
    goto :goto_0

    .line 87
    :cond_4
    iget-object v1, v1, Lg1/q;->i:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v1, Ll2/f1;

    .line 90
    .line 91
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    :goto_0
    iput v1, v7, Lkotlin/jvm/internal/c0;->d:F

    .line 96
    .line 97
    cmpg-float v11, v1, v6

    .line 98
    .line 99
    if-nez v11, :cond_5

    .line 100
    .line 101
    goto/16 :goto_6

    .line 102
    .line 103
    :cond_5
    sub-float v11, v6, v1

    .line 104
    .line 105
    move-object v12, v7

    .line 106
    iget v7, p0, Lg1/d;->i:F

    .line 107
    .line 108
    mul-float/2addr v11, v7

    .line 109
    cmpg-float v11, v11, v5

    .line 110
    .line 111
    const/4 v13, 0x0

    .line 112
    if-ltz v11, :cond_6

    .line 113
    .line 114
    cmpg-float v11, v7, v5

    .line 115
    .line 116
    if-nez v11, :cond_7

    .line 117
    .line 118
    :cond_6
    move-object v12, p0

    .line 119
    goto :goto_3

    .line 120
    :cond_7
    iget-object v4, p0, Lg1/d;->l:Lc1/u;

    .line 121
    .line 122
    invoke-static {v4, v1, v7}, Lc1/d;->k(Lc1/u;FF)F

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    iget v7, p0, Lg1/d;->i:F

    .line 127
    .line 128
    cmpl-float v11, v7, v5

    .line 129
    .line 130
    if-lez v11, :cond_8

    .line 131
    .line 132
    cmpl-float v1, v1, v6

    .line 133
    .line 134
    if-ltz v1, :cond_9

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_8
    cmpg-float v1, v1, v6

    .line 138
    .line 139
    if-gtz v1, :cond_9

    .line 140
    .line 141
    :goto_1
    iget v1, v12, Lkotlin/jvm/internal/c0;->d:F

    .line 142
    .line 143
    const/16 v2, 0x1c

    .line 144
    .line 145
    invoke-static {v1, v7, v2}, Lc1/d;->b(FFI)Lc1/k;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    new-instance v5, Lh1/h;

    .line 150
    .line 151
    const/4 v10, 0x2

    .line 152
    move-object v9, p1

    .line 153
    move-object v7, v12

    .line 154
    invoke-direct/range {v5 .. v10}, Lh1/h;-><init>(FLkotlin/jvm/internal/c0;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 155
    .line 156
    .line 157
    iput-object v13, p0, Lg1/d;->e:Lg1/p;

    .line 158
    .line 159
    iput-object v13, p0, Lg1/d;->f:Lg1/z;

    .line 160
    .line 161
    iput v3, p0, Lg1/d;->d:I

    .line 162
    .line 163
    const/4 p1, 0x0

    .line 164
    invoke-static {v1, v4, p1, v5, p0}, Lc1/d;->f(Lc1/k;Lc1/u;ZLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    if-ne p0, v0, :cond_c

    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_9
    iput-object v13, p0, Lg1/d;->e:Lg1/p;

    .line 172
    .line 173
    iput-object v13, p0, Lg1/d;->f:Lg1/z;

    .line 174
    .line 175
    iput v2, p0, Lg1/d;->d:I

    .line 176
    .line 177
    iget-object v6, p0, Lg1/d;->h:Lg1/q;

    .line 178
    .line 179
    iget-object v11, p0, Lg1/d;->j:Lc1/j;

    .line 180
    .line 181
    move-object v12, p0

    .line 182
    invoke-static/range {v6 .. v12}, Landroidx/compose/foundation/gestures/a;->a(Lg1/q;FLg1/p;Lg1/z;Ljava/lang/Object;Lc1/j;Lrx0/i;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    if-ne p0, v0, :cond_a

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_a
    :goto_2
    iput v5, p1, Lkotlin/jvm/internal/c0;->d:F

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :goto_3
    iput-object v13, v12, Lg1/d;->e:Lg1/p;

    .line 193
    .line 194
    iput-object v13, v12, Lg1/d;->f:Lg1/z;

    .line 195
    .line 196
    iput v4, v12, Lg1/d;->d:I

    .line 197
    .line 198
    iget-object v6, v12, Lg1/d;->h:Lg1/q;

    .line 199
    .line 200
    iget-object v11, v12, Lg1/d;->j:Lc1/j;

    .line 201
    .line 202
    invoke-static/range {v6 .. v12}, Landroidx/compose/foundation/gestures/a;->a(Lg1/q;FLg1/p;Lg1/z;Ljava/lang/Object;Lc1/j;Lrx0/i;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    if-ne p0, v0, :cond_b

    .line 207
    .line 208
    :goto_4
    return-object v0

    .line 209
    :cond_b
    :goto_5
    iput v5, p1, Lkotlin/jvm/internal/c0;->d:F

    .line 210
    .line 211
    :cond_c
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 212
    .line 213
    return-object p0
.end method
