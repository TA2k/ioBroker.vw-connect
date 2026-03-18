.class public final Ljz0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljz0/n;


# instance fields
.field public final a:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "string"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljz0/h;->a:Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a()Lkz0/c;
    .locals 2

    .line 1
    new-instance v0, Lkz0/a;

    .line 2
    .line 3
    iget-object p0, p0, Ljz0/h;->a:Ljava/lang/String;

    .line 4
    .line 5
    const-string v1, "string"

    .line 6
    .line 7
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final b()Llz0/n;
    .locals 8

    .line 1
    iget-object p0, p0, Ljz0/h;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    move-object p0, v1

    .line 12
    goto/16 :goto_9

    .line 13
    .line 14
    :cond_0
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    invoke-static {v3}, Liz0/b;->a(C)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    const-string v4, ""

    .line 28
    .line 29
    const-string v5, "substring(...)"

    .line 30
    .line 31
    if-eqz v3, :cond_5

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    move v6, v2

    .line 38
    :goto_0
    if-ge v6, v3, :cond_2

    .line 39
    .line 40
    invoke-virtual {p0, v6}, Ljava/lang/String;->charAt(I)C

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    invoke-static {v7}, Liz0/b;->a(C)Z

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    if-nez v7, :cond_1

    .line 49
    .line 50
    invoke-virtual {p0, v2, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    add-int/lit8 v6, v6, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    move-object v3, p0

    .line 62
    :goto_1
    new-instance v6, Llz0/b;

    .line 63
    .line 64
    invoke-direct {v6, v3}, Llz0/b;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    new-instance v6, Llz0/g;

    .line 72
    .line 73
    invoke-direct {v6, v3}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0, v6}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    move v6, v2

    .line 84
    :goto_2
    if-ge v6, v3, :cond_4

    .line 85
    .line 86
    invoke-virtual {p0, v6}, Ljava/lang/String;->charAt(I)C

    .line 87
    .line 88
    .line 89
    move-result v7

    .line 90
    invoke-static {v7}, Liz0/b;->a(C)Z

    .line 91
    .line 92
    .line 93
    move-result v7

    .line 94
    if-nez v7, :cond_3

    .line 95
    .line 96
    invoke-virtual {p0, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_4
    move-object p0, v4

    .line 108
    :cond_5
    :goto_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    if-lez v3, :cond_b

    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    add-int/lit8 v3, v3, -0x1

    .line 119
    .line 120
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    invoke-static {v3}, Liz0/b;->a(C)Z

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    if-eqz v3, :cond_a

    .line 129
    .line 130
    invoke-static {p0}, Lly0/p;->F(Ljava/lang/CharSequence;)I

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    :goto_4
    const/4 v6, -0x1

    .line 135
    if-ge v6, v3, :cond_7

    .line 136
    .line 137
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 138
    .line 139
    .line 140
    move-result v7

    .line 141
    invoke-static {v7}, Liz0/b;->a(C)Z

    .line 142
    .line 143
    .line 144
    move-result v7

    .line 145
    if-nez v7, :cond_6

    .line 146
    .line 147
    add-int/lit8 v3, v3, 0x1

    .line 148
    .line 149
    invoke-virtual {p0, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_6
    add-int/lit8 v3, v3, -0x1

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_7
    :goto_5
    new-instance v2, Llz0/o;

    .line 161
    .line 162
    invoke-direct {v2, v4}, Llz0/o;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0, v2}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    invoke-static {p0}, Lly0/p;->F(Ljava/lang/CharSequence;)I

    .line 169
    .line 170
    .line 171
    move-result v2

    .line 172
    :goto_6
    if-ge v6, v2, :cond_9

    .line 173
    .line 174
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 175
    .line 176
    .line 177
    move-result v3

    .line 178
    invoke-static {v3}, Liz0/b;->a(C)Z

    .line 179
    .line 180
    .line 181
    move-result v3

    .line 182
    if-nez v3, :cond_8

    .line 183
    .line 184
    add-int/lit8 v2, v2, 0x1

    .line 185
    .line 186
    invoke-virtual {p0, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    goto :goto_7

    .line 194
    :cond_8
    add-int/lit8 v2, v2, -0x1

    .line 195
    .line 196
    goto :goto_6

    .line 197
    :cond_9
    :goto_7
    new-instance v2, Llz0/b;

    .line 198
    .line 199
    invoke-direct {v2, p0}, Llz0/b;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    new-instance v2, Llz0/g;

    .line 207
    .line 208
    invoke-direct {v2, p0}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v0, v2}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    goto :goto_8

    .line 215
    :cond_a
    new-instance v2, Llz0/o;

    .line 216
    .line 217
    invoke-direct {v2, p0}, Llz0/o;-><init>(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v0, v2}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    :cond_b
    :goto_8
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    :goto_9
    new-instance v0, Llz0/n;

    .line 228
    .line 229
    invoke-direct {v0, p0, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 230
    .line 231
    .line 232
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ljz0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljz0/h;

    .line 6
    .line 7
    iget-object p1, p1, Ljz0/h;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object p0, p0, Ljz0/h;->a:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/h;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ConstantFormatStructure("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Ljz0/h;->a:Ljava/lang/String;

    .line 9
    .line 10
    const/16 v1, 0x29

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
