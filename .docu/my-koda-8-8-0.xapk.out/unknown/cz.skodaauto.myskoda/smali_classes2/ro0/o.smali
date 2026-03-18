.class public final Lro0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lro0/t;

.field public final b:Lro0/x;


# direct methods
.method public constructor <init>(Lro0/t;Lro0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lro0/o;->a:Lro0/t;

    .line 5
    .line 6
    iput-object p2, p0, Lro0/o;->b:Lro0/x;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lto0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lro0/o;->b(Lto0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lto0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lro0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lro0/n;

    .line 7
    .line 8
    iget v1, v0, Lro0/n;->g:I

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
    iput v1, v0, Lro0/n;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lro0/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lro0/n;-><init>(Lro0/o;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lro0/n;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lro0/n;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p1, v0, Lro0/n;->d:Lto0/l;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iput-object p1, v0, Lro0/n;->d:Lto0/l;

    .line 56
    .line 57
    iput v4, v0, Lro0/n;->g:I

    .line 58
    .line 59
    iget-object p2, p0, Lro0/o;->b:Lro0/x;

    .line 60
    .line 61
    iget-object p2, p2, Lro0/x;->a:Lro0/w;

    .line 62
    .line 63
    check-cast p2, Lpo0/i;

    .line 64
    .line 65
    iget-object p2, p2, Lpo0/i;->a:Lyy0/c2;

    .line 66
    .line 67
    invoke-virtual {p2, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    if-ne v3, v1, :cond_3

    .line 71
    .line 72
    return-object v1

    .line 73
    :cond_3
    :goto_1
    iget-object p0, p0, Lro0/o;->a:Lro0/t;

    .line 74
    .line 75
    check-cast p0, Liy/b;

    .line 76
    .line 77
    const-string p2, "powerpassFlow"

    .line 78
    .line 79
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    sget-object v5, Lly/b;->T2:Lly/b;

    .line 83
    .line 84
    sget-object p2, Lto0/a;->a:Lto0/a;

    .line 85
    .line 86
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    if-eqz p2, :cond_4

    .line 91
    .line 92
    sget-object p1, Lly/b;->O2:Lly/b;

    .line 93
    .line 94
    :goto_2
    move-object v7, p1

    .line 95
    goto/16 :goto_3

    .line 96
    .line 97
    :cond_4
    sget-object p2, Lto0/b;->a:Lto0/b;

    .line 98
    .line 99
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result p2

    .line 103
    if-eqz p2, :cond_5

    .line 104
    .line 105
    sget-object p1, Lly/b;->P2:Lly/b;

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    sget-object p2, Lto0/c;->a:Lto0/c;

    .line 109
    .line 110
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    if-eqz p2, :cond_6

    .line 115
    .line 116
    sget-object p1, Lly/b;->Q2:Lly/b;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_6
    sget-object p2, Lto0/f;->a:Lto0/f;

    .line 120
    .line 121
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    if-eqz p2, :cond_7

    .line 126
    .line 127
    sget-object p1, Lly/b;->R2:Lly/b;

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_7
    sget-object p2, Lto0/g;->a:Lto0/g;

    .line 131
    .line 132
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result p2

    .line 136
    if-eqz p2, :cond_8

    .line 137
    .line 138
    sget-object p1, Lly/b;->S2:Lly/b;

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_8
    sget-object p2, Lto0/i;->a:Lto0/i;

    .line 142
    .line 143
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    if-eqz p2, :cond_9

    .line 148
    .line 149
    sget-object p1, Lly/b;->U2:Lly/b;

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_9
    sget-object p2, Lto0/j;->a:Lto0/j;

    .line 153
    .line 154
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    if-eqz p2, :cond_a

    .line 159
    .line 160
    sget-object p1, Lly/b;->V2:Lly/b;

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_a
    sget-object p2, Lto0/k;->a:Lto0/k;

    .line 164
    .line 165
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result p2

    .line 169
    if-eqz p2, :cond_b

    .line 170
    .line 171
    sget-object p1, Lly/b;->W2:Lly/b;

    .line 172
    .line 173
    goto :goto_2

    .line 174
    :cond_b
    sget-object p2, Lto0/x;->a:Lto0/x;

    .line 175
    .line 176
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p2

    .line 180
    if-eqz p2, :cond_c

    .line 181
    .line 182
    sget-object p1, Lly/b;->X2:Lly/b;

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_c
    sget-object p2, Lto0/w;->a:Lto0/w;

    .line 186
    .line 187
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result p2

    .line 191
    if-eqz p2, :cond_d

    .line 192
    .line 193
    sget-object p1, Lly/b;->Y2:Lly/b;

    .line 194
    .line 195
    goto :goto_2

    .line 196
    :cond_d
    sget-object p2, Lto0/y;->a:Lto0/y;

    .line 197
    .line 198
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    if-eqz p2, :cond_e

    .line 203
    .line 204
    sget-object p1, Lly/b;->Z2:Lly/b;

    .line 205
    .line 206
    goto :goto_2

    .line 207
    :cond_e
    sget-object p2, Lto0/v;->a:Lto0/v;

    .line 208
    .line 209
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result p1

    .line 213
    if-eqz p1, :cond_f

    .line 214
    .line 215
    sget-object p1, Lly/b;->a3:Lly/b;

    .line 216
    .line 217
    goto :goto_2

    .line 218
    :goto_3
    new-instance v4, Lul0/c;

    .line 219
    .line 220
    const/4 v8, 0x0

    .line 221
    const/16 v9, 0x10

    .line 222
    .line 223
    const/4 v6, 0x1

    .line 224
    invoke-direct/range {v4 .. v9}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p0, v4}, Liy/b;->b(Lul0/e;)V

    .line 228
    .line 229
    .line 230
    return-object v3

    .line 231
    :cond_f
    new-instance p0, La8/r0;

    .line 232
    .line 233
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 234
    .line 235
    .line 236
    throw p0
.end method
