.class public final La90/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfj0/b;

.field public final b:Lfj0/a;

.field public final c:Lfj0/k;

.field public final d:La90/q;


# direct methods
.method public constructor <init>(Lfj0/b;Lfj0/a;Lfj0/k;La90/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La90/b;->a:Lfj0/b;

    .line 5
    .line 6
    iput-object p2, p0, La90/b;->b:Lfj0/a;

    .line 7
    .line 8
    iput-object p3, p0, La90/b;->c:Lfj0/k;

    .line 9
    .line 10
    iput-object p4, p0, La90/b;->d:La90/q;

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
    invoke-virtual {p0, p2}, La90/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, La90/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, La90/a;

    .line 7
    .line 8
    iget v1, v0, La90/a;->i:I

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
    iput v1, v0, La90/a;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La90/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, La90/a;-><init>(La90/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, La90/a;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La90/a;->i:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x4

    .line 34
    const/4 v5, 0x3

    .line 35
    const/4 v6, 0x2

    .line 36
    const/4 v7, 0x1

    .line 37
    const/4 v8, 0x0

    .line 38
    if-eqz v2, :cond_5

    .line 39
    .line 40
    if-eq v2, v7, :cond_4

    .line 41
    .line 42
    if-eq v2, v6, :cond_3

    .line 43
    .line 44
    if-eq v2, v5, :cond_2

    .line 45
    .line 46
    if-ne v2, v4, :cond_1

    .line 47
    .line 48
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object v3

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget v2, v0, La90/a;->f:I

    .line 61
    .line 62
    iget-object v5, v0, La90/a;->e:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto/16 :goto_5

    .line 68
    .line 69
    :cond_3
    iget v2, v0, La90/a;->f:I

    .line 70
    .line 71
    iget-object v6, v0, La90/a;->d:Ljava/lang/String;

    .line 72
    .line 73
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, La90/b;->d:La90/q;

    .line 85
    .line 86
    check-cast p1, Ly80/a;

    .line 87
    .line 88
    iget-object p1, p1, Ly80/a;->c:Lyy0/l1;

    .line 89
    .line 90
    iput v7, v0, La90/a;->i:I

    .line 91
    .line 92
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    if-ne p1, v1, :cond_6

    .line 97
    .line 98
    goto/16 :goto_7

    .line 99
    .line 100
    :cond_6
    :goto_1
    instance-of v2, p1, Lne0/e;

    .line 101
    .line 102
    if-eqz v2, :cond_7

    .line 103
    .line 104
    check-cast p1, Lne0/e;

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_7
    move-object p1, v8

    .line 108
    :goto_2
    if-eqz p1, :cond_8

    .line 109
    .line 110
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast p1, Lb90/f;

    .line 113
    .line 114
    if-eqz p1, :cond_8

    .line 115
    .line 116
    iget-object p1, p1, Lb90/f;->a:Ljava/lang/String;

    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_8
    move-object p1, v8

    .line 120
    :goto_3
    if-eqz p1, :cond_c

    .line 121
    .line 122
    const-string v2, "-"

    .line 123
    .line 124
    filled-new-array {v2}, [Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    const/4 v7, 0x6

    .line 129
    invoke-static {p1, v2, v7}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    const/4 v2, 0x0

    .line 134
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    check-cast p1, Ljava/lang/String;

    .line 139
    .line 140
    sget-object v7, Lbj0/a;->a:[Ljava/lang/String;

    .line 141
    .line 142
    invoke-static {p1, v7}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result v7

    .line 146
    if-eqz v7, :cond_c

    .line 147
    .line 148
    iput-object p1, v0, La90/a;->d:Ljava/lang/String;

    .line 149
    .line 150
    iput v2, v0, La90/a;->f:I

    .line 151
    .line 152
    iput v6, v0, La90/a;->i:I

    .line 153
    .line 154
    iget-object v6, p0, La90/b;->a:Lfj0/b;

    .line 155
    .line 156
    iget-object v6, v6, Lfj0/b;->a:Lfj0/e;

    .line 157
    .line 158
    check-cast v6, Ldj0/b;

    .line 159
    .line 160
    iget-object v6, v6, Ldj0/b;->h:Lyy0/l1;

    .line 161
    .line 162
    iget-object v6, v6, Lyy0/l1;->d:Lyy0/a2;

    .line 163
    .line 164
    invoke-interface {v6}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v6

    .line 168
    if-ne v6, v1, :cond_9

    .line 169
    .line 170
    goto :goto_7

    .line 171
    :cond_9
    move-object v9, v6

    .line 172
    move-object v6, p1

    .line 173
    move-object p1, v9

    .line 174
    :goto_4
    check-cast p1, Ljava/util/Locale;

    .line 175
    .line 176
    invoke-virtual {p1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    if-nez v7, :cond_c

    .line 185
    .line 186
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    iput-object v8, v0, La90/a;->d:Ljava/lang/String;

    .line 190
    .line 191
    iput-object v6, v0, La90/a;->e:Ljava/lang/String;

    .line 192
    .line 193
    iput v2, v0, La90/a;->f:I

    .line 194
    .line 195
    iput v5, v0, La90/a;->i:I

    .line 196
    .line 197
    iget-object v5, p0, La90/b;->c:Lfj0/k;

    .line 198
    .line 199
    invoke-virtual {v5, p1, v0}, Lfj0/k;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    if-ne p1, v1, :cond_a

    .line 204
    .line 205
    goto :goto_7

    .line 206
    :cond_a
    move-object v5, v6

    .line 207
    :goto_5
    const-string p1, "language"

    .line 208
    .line 209
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 213
    .line 214
    const/16 v6, 0x24

    .line 215
    .line 216
    if-lt p1, v6, :cond_b

    .line 217
    .line 218
    invoke-static {v5}, Lgj0/a;->b(Ljava/lang/String;)Ljava/util/Locale;

    .line 219
    .line 220
    .line 221
    move-result-object p1

    .line 222
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    goto :goto_6

    .line 226
    :cond_b
    new-instance p1, Ljava/util/Locale;

    .line 227
    .line 228
    invoke-direct {p1, v5}, Ljava/util/Locale;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    :goto_6
    iput-object v8, v0, La90/a;->d:Ljava/lang/String;

    .line 232
    .line 233
    iput-object v8, v0, La90/a;->e:Ljava/lang/String;

    .line 234
    .line 235
    iput v2, v0, La90/a;->f:I

    .line 236
    .line 237
    iput v4, v0, La90/a;->i:I

    .line 238
    .line 239
    iget-object p0, p0, La90/b;->b:Lfj0/a;

    .line 240
    .line 241
    invoke-virtual {p0, p1}, Lfj0/a;->b(Ljava/util/Locale;)V

    .line 242
    .line 243
    .line 244
    if-ne v3, v1, :cond_c

    .line 245
    .line 246
    :goto_7
    return-object v1

    .line 247
    :cond_c
    return-object v3
.end method
