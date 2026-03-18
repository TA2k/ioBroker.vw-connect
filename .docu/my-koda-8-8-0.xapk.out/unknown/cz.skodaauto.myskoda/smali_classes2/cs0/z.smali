.class public final Lcs0/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwr0/e;

.field public final b:Lam0/c;

.field public final c:Lbd0/c;


# direct methods
.method public constructor <init>(Lam0/c;Lbd0/c;Lwr0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lcs0/z;->a:Lwr0/e;

    .line 5
    .line 6
    iput-object p1, p0, Lcs0/z;->b:Lam0/c;

    .line 7
    .line 8
    iput-object p2, p0, Lcs0/z;->c:Lbd0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lcs0/z;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p1, Lcs0/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcs0/y;

    .line 7
    .line 8
    iget v1, v0, Lcs0/y;->g:I

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
    iput v1, v0, Lcs0/y;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/y;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcs0/y;-><init>(Lcs0/z;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcs0/y;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/y;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object v0, v0, Lcs0/y;->d:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v4, v0, Lcs0/y;->g:I

    .line 63
    .line 64
    iget-object p1, p0, Lcs0/z;->a:Lwr0/e;

    .line 65
    .line 66
    invoke-virtual {p1, v5, v0}, Lwr0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_4

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    :goto_1
    check-cast p1, Lyr0/e;

    .line 74
    .line 75
    if-eqz p1, :cond_5

    .line 76
    .line 77
    iget-object p1, p1, Lyr0/e;->h:Ljava/lang/String;

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_5
    const/4 p1, 0x0

    .line 81
    :goto_2
    iput-object p1, v0, Lcs0/y;->d:Ljava/lang/String;

    .line 82
    .line 83
    iput v3, v0, Lcs0/y;->g:I

    .line 84
    .line 85
    iget-object v2, p0, Lcs0/z;->b:Lam0/c;

    .line 86
    .line 87
    invoke-virtual {v2, v5, v0}, Lam0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    if-ne v0, v1, :cond_6

    .line 92
    .line 93
    :goto_3
    return-object v1

    .line 94
    :cond_6
    move-object v12, v0

    .line 95
    move-object v0, p1

    .line 96
    move-object p1, v12

    .line 97
    :goto_4
    check-cast p1, Lcm0/b;

    .line 98
    .line 99
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/i5;->c(Lcm0/b;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    new-instance v6, Ld01/z;

    .line 104
    .line 105
    const/4 v1, 0x0

    .line 106
    invoke-direct {v6, v1}, Ld01/z;-><init>(I)V

    .line 107
    .line 108
    .line 109
    const-string v1, "https"

    .line 110
    .line 111
    invoke-virtual {v6, v1}, Ld01/z;->k(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v6, p1}, Ld01/z;->f(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const/4 v10, 0x0

    .line 118
    const/4 v11, 0x0

    .line 119
    const/4 v7, 0x0

    .line 120
    const/16 v8, 0x14

    .line 121
    .line 122
    const-string v9, "terms-and-conditions"

    .line 123
    .line 124
    invoke-virtual/range {v6 .. v11}, Ld01/z;->i(IILjava/lang/String;ZZ)V

    .line 125
    .line 126
    .line 127
    if-eqz v0, :cond_7

    .line 128
    .line 129
    const-string p1, "ui_locale"

    .line 130
    .line 131
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    :cond_7
    invoke-virtual {v6}, Ld01/z;->c()Ld01/a0;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    iget-object p1, p1, Ld01/a0;->i:Ljava/lang/String;

    .line 139
    .line 140
    const/16 v0, 0x1e

    .line 141
    .line 142
    and-int/lit8 v1, v0, 0x2

    .line 143
    .line 144
    const/4 v2, 0x0

    .line 145
    if-eqz v1, :cond_8

    .line 146
    .line 147
    move v8, v4

    .line 148
    goto :goto_5

    .line 149
    :cond_8
    move v8, v2

    .line 150
    :goto_5
    and-int/lit8 v1, v0, 0x4

    .line 151
    .line 152
    if-eqz v1, :cond_9

    .line 153
    .line 154
    move v9, v4

    .line 155
    goto :goto_6

    .line 156
    :cond_9
    move v9, v2

    .line 157
    :goto_6
    and-int/lit8 v1, v0, 0x8

    .line 158
    .line 159
    if-eqz v1, :cond_a

    .line 160
    .line 161
    move v10, v2

    .line 162
    goto :goto_7

    .line 163
    :cond_a
    move v10, v4

    .line 164
    :goto_7
    and-int/lit8 v0, v0, 0x10

    .line 165
    .line 166
    if-eqz v0, :cond_b

    .line 167
    .line 168
    move v11, v2

    .line 169
    goto :goto_8

    .line 170
    :cond_b
    move v11, v4

    .line 171
    :goto_8
    const-string v0, "url"

    .line 172
    .line 173
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    iget-object p0, p0, Lcs0/z;->c:Lbd0/c;

    .line 177
    .line 178
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 179
    .line 180
    new-instance v7, Ljava/net/URL;

    .line 181
    .line 182
    invoke-direct {v7, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    move-object v6, p0

    .line 186
    check-cast v6, Lzc0/b;

    .line 187
    .line 188
    invoke-virtual/range {v6 .. v11}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 189
    .line 190
    .line 191
    return-object v5
.end method
