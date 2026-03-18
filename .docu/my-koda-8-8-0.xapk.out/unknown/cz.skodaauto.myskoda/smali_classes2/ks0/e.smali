.class public final Lks0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lis0/d;

.field public final b:Lsg0/a;

.field public final c:Lwr0/e;

.field public final d:Lag0/b;


# direct methods
.method public constructor <init>(Lis0/d;Lsg0/a;Lwr0/e;Lag0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/e;->a:Lis0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lks0/e;->b:Lsg0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lks0/e;->c:Lwr0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lks0/e;->d:Lag0/b;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lks0/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lks0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lks0/d;

    .line 7
    .line 8
    iget v1, v0, Lks0/d;->j:I

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
    iput v1, v0, Lks0/d;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lks0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lks0/d;-><init>(Lks0/e;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lks0/d;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lks0/d;->j:I

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
    iget-object p0, v0, Lks0/d;->g:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v1, v0, Lks0/d;->f:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v0, v0, Lks0/d;->e:Lis0/d;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    move-object v5, p0

    .line 49
    move-object v4, v0

    .line 50
    move-object v6, v1

    .line 51
    goto/16 :goto_4

    .line 52
    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    iget-object v2, v0, Lks0/d;->d:Ljava/lang/String;

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget-object p1, p0, Lks0/e;->b:Lsg0/a;

    .line 71
    .line 72
    iget-object p1, p1, Lsg0/a;->a:Ljava/lang/String;

    .line 73
    .line 74
    iput-object p1, v0, Lks0/d;->d:Ljava/lang/String;

    .line 75
    .line 76
    iput v4, v0, Lks0/d;->j:I

    .line 77
    .line 78
    iget-object v2, p0, Lks0/e;->c:Lwr0/e;

    .line 79
    .line 80
    iget-object v2, v2, Lwr0/e;->a:Lwr0/g;

    .line 81
    .line 82
    check-cast v2, Lur0/g;

    .line 83
    .line 84
    invoke-virtual {v2, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    if-ne v2, v1, :cond_4

    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_4
    move-object v12, v2

    .line 92
    move-object v2, p1

    .line 93
    move-object p1, v12

    .line 94
    :goto_1
    check-cast p1, Lyr0/e;

    .line 95
    .line 96
    const/4 v4, 0x0

    .line 97
    if-eqz p1, :cond_5

    .line 98
    .line 99
    iget-object p1, p1, Lyr0/e;->a:Ljava/lang/String;

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_5
    move-object p1, v4

    .line 103
    :goto_2
    if-nez v2, :cond_6

    .line 104
    .line 105
    new-instance v5, Lne0/c;

    .line 106
    .line 107
    new-instance v6, Ljava/lang/Exception;

    .line 108
    .line 109
    const-string p0, "No vin was selected for enrollment"

    .line 110
    .line 111
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    const/4 v9, 0x0

    .line 115
    const/16 v10, 0x1e

    .line 116
    .line 117
    const/4 v7, 0x0

    .line 118
    const/4 v8, 0x0

    .line 119
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 120
    .line 121
    .line 122
    new-instance p0, Lyy0/m;

    .line 123
    .line 124
    const/4 p1, 0x0

    .line 125
    invoke-direct {p0, v5, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 126
    .line 127
    .line 128
    return-object p0

    .line 129
    :cond_6
    if-nez p1, :cond_7

    .line 130
    .line 131
    new-instance v6, Lne0/c;

    .line 132
    .line 133
    new-instance v7, Ljava/lang/Exception;

    .line 134
    .line 135
    const-string p0, "User id is not available"

    .line 136
    .line 137
    invoke-direct {v7, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    const/4 v10, 0x0

    .line 141
    const/16 v11, 0x1e

    .line 142
    .line 143
    const/4 v8, 0x0

    .line 144
    const/4 v9, 0x0

    .line 145
    invoke-direct/range {v6 .. v11}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 146
    .line 147
    .line 148
    new-instance p0, Lyy0/m;

    .line 149
    .line 150
    const/4 p1, 0x0

    .line 151
    invoke-direct {p0, v6, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 152
    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_7
    iget-object v5, p0, Lks0/e;->d:Lag0/b;

    .line 156
    .line 157
    invoke-virtual {v5}, Lag0/b;->invoke()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v5

    .line 161
    check-cast v5, Lyy0/i;

    .line 162
    .line 163
    iput-object v4, v0, Lks0/d;->d:Ljava/lang/String;

    .line 164
    .line 165
    iget-object p0, p0, Lks0/e;->a:Lis0/d;

    .line 166
    .line 167
    iput-object p0, v0, Lks0/d;->e:Lis0/d;

    .line 168
    .line 169
    iput-object v2, v0, Lks0/d;->f:Ljava/lang/String;

    .line 170
    .line 171
    iput-object p1, v0, Lks0/d;->g:Ljava/lang/String;

    .line 172
    .line 173
    iput v3, v0, Lks0/d;->j:I

    .line 174
    .line 175
    invoke-static {v5, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    if-ne v0, v1, :cond_8

    .line 180
    .line 181
    :goto_3
    return-object v1

    .line 182
    :cond_8
    move-object v4, p0

    .line 183
    move-object v5, p1

    .line 184
    move-object p1, v0

    .line 185
    move-object v6, v2

    .line 186
    :goto_4
    check-cast p1, Lbg0/c;

    .line 187
    .line 188
    iget-boolean v7, p1, Lbg0/c;->e:Z

    .line 189
    .line 190
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    const-string p0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 194
    .line 195
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    const-string p0, "userId"

    .line 199
    .line 200
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    iget-object p0, v4, Lis0/d;->a:Lxl0/f;

    .line 204
    .line 205
    new-instance v3, Lis0/c;

    .line 206
    .line 207
    const/4 v8, 0x0

    .line 208
    invoke-direct/range {v3 .. v8}, Lis0/c;-><init>(Lis0/d;Ljava/lang/String;Ljava/lang/String;ZLkotlin/coroutines/Continuation;)V

    .line 209
    .line 210
    .line 211
    new-instance p1, Lim0/b;

    .line 212
    .line 213
    const/4 v0, 0x5

    .line 214
    invoke-direct {p1, v0}, Lim0/b;-><init>(I)V

    .line 215
    .line 216
    .line 217
    new-instance v0, Lim0/b;

    .line 218
    .line 219
    const/4 v1, 0x6

    .line 220
    invoke-direct {v0, v1}, Lim0/b;-><init>(I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p0, v3, p1, v0}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    return-object p0
.end method
