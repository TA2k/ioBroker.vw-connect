.class public final Lcq/s;
.super Lmo/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbq/b;


# instance fields
.field public final g:I


# direct methods
.method public constructor <init>(Lcom/google/android/gms/common/data/DataHolder;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lmo/b;-><init>(Lcom/google/android/gms/common/data/DataHolder;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcq/s;->g:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final getUri()Landroid/net/Uri;
    .locals 4

    .line 1
    iget-object v0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 2
    .line 3
    iget v1, p0, Lmo/b;->e:I

    .line 4
    .line 5
    const-string v2, "path"

    .line 6
    .line 7
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v3, v0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 11
    .line 12
    iget p0, p0, Lmo/b;->f:I

    .line 13
    .line 14
    aget-object p0, v3, p0

    .line 15
    .line 16
    iget-object v0, v0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 17
    .line 18
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-virtual {p0, v1, v0}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 11

    .line 1
    const-string v0, "DataItem"

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    invoke-virtual {p0}, Lmo/b;->a()[B

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    new-instance v2, Ljava/util/HashMap;

    .line 13
    .line 14
    iget v3, p0, Lcq/s;->g:I

    .line 15
    .line 16
    invoke-direct {v2, v3}, Ljava/util/HashMap;-><init>(I)V

    .line 17
    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    :goto_0
    if-ge v4, v3, :cond_1

    .line 21
    .line 22
    new-instance v5, Lcq/q;

    .line 23
    .line 24
    iget v6, p0, Lmo/b;->e:I

    .line 25
    .line 26
    add-int/2addr v6, v4

    .line 27
    iget-object v7, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 28
    .line 29
    invoke-direct {v5, v7, v6}, Lmo/b;-><init>(Lcom/google/android/gms/common/data/DataHolder;I)V

    .line 30
    .line 31
    .line 32
    iget-object v6, v5, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 33
    .line 34
    iget v7, v5, Lmo/b;->e:I

    .line 35
    .line 36
    const-string v8, "asset_key"

    .line 37
    .line 38
    invoke-virtual {v6, v7, v8}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object v9, v6, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 42
    .line 43
    iget v10, v5, Lmo/b;->f:I

    .line 44
    .line 45
    aget-object v9, v9, v10

    .line 46
    .line 47
    iget-object v10, v6, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 48
    .line 49
    invoke-virtual {v10, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v10

    .line 53
    invoke-virtual {v9, v7, v10}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    if-eqz v7, :cond_0

    .line 58
    .line 59
    iget v7, v5, Lmo/b;->e:I

    .line 60
    .line 61
    invoke-virtual {v6, v7, v8}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object v9, v6, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 65
    .line 66
    iget v10, v5, Lmo/b;->f:I

    .line 67
    .line 68
    aget-object v9, v9, v10

    .line 69
    .line 70
    iget-object v6, v6, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 71
    .line 72
    invoke-virtual {v6, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    move-result v6

    .line 76
    invoke-virtual {v9, v7, v6}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    invoke-virtual {v2, v6, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_1
    new-instance v3, Ljava/lang/StringBuilder;

    .line 87
    .line 88
    const-string v4, "DataItemRef{ "

    .line 89
    .line 90
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0}, Lcq/s;->getUri()Landroid/net/Uri;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const-string v4, "uri="

    .line 102
    .line 103
    invoke-virtual {v4, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    if-nez v1, :cond_2

    .line 111
    .line 112
    const-string p0, "null"

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_2
    array-length p0, v1

    .line 116
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    :goto_1
    const-string v1, ", dataSz="

    .line 121
    .line 122
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v2}, Ljava/util/HashMap;->size()I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    new-instance v1, Ljava/lang/StringBuilder;

    .line 138
    .line 139
    const-string v4, ", numAssets="

    .line 140
    .line 141
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    if-eqz v0, :cond_4

    .line 155
    .line 156
    invoke-virtual {v2}, Ljava/util/HashMap;->isEmpty()Z

    .line 157
    .line 158
    .line 159
    move-result p0

    .line 160
    if-nez p0, :cond_4

    .line 161
    .line 162
    const-string p0, ", assets=["

    .line 163
    .line 164
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    const-string v0, ""

    .line 176
    .line 177
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-eqz v1, :cond_3

    .line 182
    .line 183
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    check-cast v1, Ljava/util/Map$Entry;

    .line 188
    .line 189
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    check-cast v2, Ljava/lang/String;

    .line 194
    .line 195
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    check-cast v1, Lbq/c;

    .line 200
    .line 201
    invoke-interface {v1}, Lbq/c;->getId()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    new-instance v4, Ljava/lang/StringBuilder;

    .line 206
    .line 207
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    const-string v0, ": "

    .line 217
    .line 218
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    const-string v0, ", "

    .line 232
    .line 233
    goto :goto_2

    .line 234
    :cond_3
    const-string p0, "]"

    .line 235
    .line 236
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    :cond_4
    const-string p0, " }"

    .line 240
    .line 241
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    return-object p0
.end method
