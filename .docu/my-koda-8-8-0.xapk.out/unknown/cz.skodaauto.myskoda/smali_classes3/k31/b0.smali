.class public final Lk31/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lk31/n;


# direct methods
.method public constructor <init>(Lk31/n;Li31/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/b0;->a:Lk31/n;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lk31/a0;)Ljava/util/ArrayList;
    .locals 10

    .line 1
    iget-object p1, p1, Lk31/a0;->a:Lz70/d;

    .line 2
    .line 3
    const-string v0, "newRequestStrings"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Li31/o;

    .line 9
    .line 10
    iget-object p1, p1, Lz70/d;->a:Lg1/q;

    .line 11
    .line 12
    iget-object p1, p1, Lg1/q;->k:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Lz70/c;

    .line 15
    .line 16
    iget-object v1, p1, Lz70/c;->a:Lij0/a;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    new-array v3, v2, [Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Ljj0/f;

    .line 22
    .line 23
    const v4, 0x7f12114c

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-direct {v0, v1}, Li31/o;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Li31/r;

    .line 34
    .line 35
    iget-object p1, p1, Lz70/c;->a:Lij0/a;

    .line 36
    .line 37
    new-array v3, v2, [Ljava/lang/Object;

    .line 38
    .line 39
    move-object v4, p1

    .line 40
    check-cast v4, Ljj0/f;

    .line 41
    .line 42
    const v5, 0x7f121151

    .line 43
    .line 44
    .line 45
    invoke-virtual {v4, v5, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-direct {v1, v3}, Li31/r;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v3, Li31/s;

    .line 53
    .line 54
    new-array v4, v2, [Ljava/lang/Object;

    .line 55
    .line 56
    move-object v5, p1

    .line 57
    check-cast v5, Ljj0/f;

    .line 58
    .line 59
    const v6, 0x7f121152

    .line 60
    .line 61
    .line 62
    invoke-virtual {v5, v6, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-direct {v3, v4}, Li31/s;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    new-instance v4, Li31/l;

    .line 70
    .line 71
    new-array v5, v2, [Ljava/lang/Object;

    .line 72
    .line 73
    move-object v6, p1

    .line 74
    check-cast v6, Ljj0/f;

    .line 75
    .line 76
    const v7, 0x7f121148

    .line 77
    .line 78
    .line 79
    invoke-virtual {v6, v7, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    invoke-direct {v4, v5}, Li31/l;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    new-instance v5, Li31/k;

    .line 87
    .line 88
    new-array v6, v2, [Ljava/lang/Object;

    .line 89
    .line 90
    move-object v7, p1

    .line 91
    check-cast v7, Ljj0/f;

    .line 92
    .line 93
    const v8, 0x7f121147

    .line 94
    .line 95
    .line 96
    invoke-virtual {v7, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v6

    .line 100
    invoke-direct {v5, v6}, Li31/k;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    new-instance v6, Li31/q;

    .line 104
    .line 105
    new-array v7, v2, [Ljava/lang/Object;

    .line 106
    .line 107
    move-object v8, p1

    .line 108
    check-cast v8, Ljj0/f;

    .line 109
    .line 110
    const v9, 0x7f121150

    .line 111
    .line 112
    .line 113
    invoke-virtual {v8, v9, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    invoke-direct {v6, v7}, Li31/q;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    new-instance v7, Li31/p;

    .line 121
    .line 122
    new-array v8, v2, [Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p1, Ljj0/f;

    .line 125
    .line 126
    const v9, 0x7f12114e

    .line 127
    .line 128
    .line 129
    invoke-virtual {p1, v9, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-direct {v7, p1}, Li31/p;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const/4 p1, 0x7

    .line 137
    new-array p1, p1, [Li31/u;

    .line 138
    .line 139
    aput-object v0, p1, v2

    .line 140
    .line 141
    const/4 v0, 0x1

    .line 142
    aput-object v1, p1, v0

    .line 143
    .line 144
    const/4 v0, 0x2

    .line 145
    aput-object v3, p1, v0

    .line 146
    .line 147
    const/4 v0, 0x3

    .line 148
    aput-object v4, p1, v0

    .line 149
    .line 150
    const/4 v0, 0x4

    .line 151
    aput-object v5, p1, v0

    .line 152
    .line 153
    const/4 v0, 0x5

    .line 154
    aput-object v6, p1, v0

    .line 155
    .line 156
    const/4 v0, 0x6

    .line 157
    aput-object v7, p1, v0

    .line 158
    .line 159
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    iget-object p0, p0, Lk31/b0;->a:Lk31/n;

    .line 164
    .line 165
    invoke-static {p0}, Lkp/j;->b(Lr41/a;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    check-cast p0, Li31/j;

    .line 170
    .line 171
    if-eqz p0, :cond_0

    .line 172
    .line 173
    iget-boolean v2, p0, Li31/j;->d:Z

    .line 174
    .line 175
    :cond_0
    check-cast p1, Ljava/lang/Iterable;

    .line 176
    .line 177
    new-instance p0, Ljava/util/ArrayList;

    .line 178
    .line 179
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 180
    .line 181
    .line 182
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    :cond_1
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    if-eqz v0, :cond_3

    .line 191
    .line 192
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    move-object v1, v0

    .line 197
    check-cast v1, Li31/u;

    .line 198
    .line 199
    if-eqz v2, :cond_2

    .line 200
    .line 201
    instance-of v1, v1, Li31/p;

    .line 202
    .line 203
    if-nez v1, :cond_1

    .line 204
    .line 205
    :cond_2
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    goto :goto_0

    .line 209
    :cond_3
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lk31/a0;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lk31/b0;->a(Lk31/a0;)Ljava/util/ArrayList;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
