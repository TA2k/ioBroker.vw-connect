.class public final Lkc0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcu0/a;

.field public final b:Lkc0/g;


# direct methods
.method public constructor <init>(Lcu0/a;Lkc0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/b;->a:Lcu0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/b;->b:Lkc0/g;

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
    invoke-virtual {p0, p2}, Lkc0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lkc0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkc0/a;

    .line 7
    .line 8
    iget v1, v0, Lkc0/a;->g:I

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
    iput v1, v0, Lkc0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkc0/a;-><init>(Lkc0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkc0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/a;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lkc0/b;->b:Lkc0/g;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    const/4 v8, 0x0

    .line 39
    if-eqz v2, :cond_4

    .line 40
    .line 41
    if-eq v2, v6, :cond_3

    .line 42
    .line 43
    if-eq v2, v5, :cond_2

    .line 44
    .line 45
    if-ne v2, v4, :cond_1

    .line 46
    .line 47
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto/16 :goto_7

    .line 51
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
    iget-object p0, v0, Lkc0/a;->d:Ljava/lang/String;

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_5

    .line 66
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iput v6, v0, Lkc0/a;->g:I

    .line 74
    .line 75
    iget-object p0, p0, Lkc0/b;->a:Lcu0/a;

    .line 76
    .line 77
    iget-object p0, p0, Lcu0/a;->a:Lcu0/h;

    .line 78
    .line 79
    check-cast p0, Lau0/g;

    .line 80
    .line 81
    const-string p1, "auth"

    .line 82
    .line 83
    invoke-virtual {p0, p1, v0}, Lau0/g;->a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-ne p1, v1, :cond_5

    .line 88
    .line 89
    goto :goto_6

    .line 90
    :cond_5
    :goto_1
    check-cast p1, Lne0/t;

    .line 91
    .line 92
    instance-of p0, p1, Lne0/e;

    .line 93
    .line 94
    if-eqz p0, :cond_c

    .line 95
    .line 96
    check-cast p1, Lne0/e;

    .line 97
    .line 98
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Ljava/util/Map;

    .line 101
    .line 102
    if-eqz p0, :cond_6

    .line 103
    .line 104
    const-string p1, "connect_refresh_token"

    .line 105
    .line 106
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    check-cast p1, Ljava/lang/String;

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_6
    move-object p1, v8

    .line 114
    :goto_2
    if-eqz p0, :cond_7

    .line 115
    .line 116
    const-string v2, "connect_id_token"

    .line 117
    .line 118
    invoke-interface {p0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    check-cast p0, Ljava/lang/String;

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_7
    move-object p0, v8

    .line 126
    :goto_3
    if-eqz p1, :cond_b

    .line 127
    .line 128
    if-eqz p0, :cond_b

    .line 129
    .line 130
    iput-object p0, v0, Lkc0/a;->d:Ljava/lang/String;

    .line 131
    .line 132
    iput v5, v0, Lkc0/a;->g:I

    .line 133
    .line 134
    move-object v2, v3

    .line 135
    check-cast v2, Lic0/p;

    .line 136
    .line 137
    sget-object v5, Lge0/b;->a:Lcz0/e;

    .line 138
    .line 139
    new-instance v6, Lic0/n;

    .line 140
    .line 141
    const/4 v9, 0x0

    .line 142
    invoke-direct {v6, v2, p1, v8, v9}, Lic0/n;-><init>(Lic0/p;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {v5, v6, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    if-ne p1, v1, :cond_8

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_8
    move-object p1, v7

    .line 153
    :goto_4
    if-ne p1, v1, :cond_9

    .line 154
    .line 155
    goto :goto_6

    .line 156
    :cond_9
    :goto_5
    const-string p1, "value"

    .line 157
    .line 158
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    iput-object v8, v0, Lkc0/a;->d:Ljava/lang/String;

    .line 162
    .line 163
    iput v4, v0, Lkc0/a;->g:I

    .line 164
    .line 165
    check-cast v3, Lic0/p;

    .line 166
    .line 167
    iget-object p1, v3, Lic0/p;->f:Lyy0/c2;

    .line 168
    .line 169
    new-instance v0, Llc0/d;

    .line 170
    .line 171
    invoke-direct {v0, p0}, Llc0/d;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    invoke-virtual {p1, v8, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    if-ne v7, v1, :cond_a

    .line 181
    .line 182
    :goto_6
    return-object v1

    .line 183
    :cond_a
    :goto_7
    new-instance p0, Lne0/e;

    .line 184
    .line 185
    invoke-direct {p0, v7}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    return-object p0

    .line 189
    :cond_b
    new-instance v0, Lne0/c;

    .line 190
    .line 191
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 192
    .line 193
    const-string p0, "Unable to apply remote tokens"

    .line 194
    .line 195
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    const/4 v4, 0x0

    .line 199
    const/16 v5, 0x1e

    .line 200
    .line 201
    const/4 v2, 0x0

    .line 202
    const/4 v3, 0x0

    .line 203
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 204
    .line 205
    .line 206
    return-object v0

    .line 207
    :cond_c
    instance-of p0, p1, Lne0/c;

    .line 208
    .line 209
    if-eqz p0, :cond_d

    .line 210
    .line 211
    new-instance v0, Lne0/c;

    .line 212
    .line 213
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 214
    .line 215
    check-cast p1, Lne0/c;

    .line 216
    .line 217
    iget-object p0, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 218
    .line 219
    const-string p1, "Unable to apply wearable refresh token"

    .line 220
    .line 221
    invoke-direct {v1, p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 222
    .line 223
    .line 224
    const/4 v4, 0x0

    .line 225
    const/16 v5, 0x1e

    .line 226
    .line 227
    const/4 v2, 0x0

    .line 228
    const/4 v3, 0x0

    .line 229
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 230
    .line 231
    .line 232
    return-object v0

    .line 233
    :cond_d
    new-instance p0, La8/r0;

    .line 234
    .line 235
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 236
    .line 237
    .line 238
    throw p0
.end method
