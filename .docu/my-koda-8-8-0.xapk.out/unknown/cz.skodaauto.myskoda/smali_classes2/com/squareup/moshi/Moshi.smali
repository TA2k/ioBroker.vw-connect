.class public final Lcom/squareup/moshi/Moshi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/squareup/moshi/Moshi$Builder;,
        Lcom/squareup/moshi/Moshi$LookupChain;,
        Lcom/squareup/moshi/Moshi$Lookup;
    }
.end annotation


# static fields
.field public static final d:Ljava/util/ArrayList;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Ljava/lang/ThreadLocal;

.field public final c:Ljava/util/LinkedHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/squareup/moshi/Moshi;->d:Ljava/util/ArrayList;

    .line 8
    .line 9
    sget-object v1, Lcom/squareup/moshi/StandardJsonAdapters;->a:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    sget-object v1, Lcom/squareup/moshi/CollectionJsonAdapter;->b:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    sget-object v1, Lcom/squareup/moshi/MapJsonAdapter;->c:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    sget-object v1, Lcom/squareup/moshi/ArrayJsonAdapter;->c:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    sget-object v1, Lcom/squareup/moshi/RecordJsonAdapter;->a:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    sget-object v1, Lcom/squareup/moshi/ClassJsonAdapter;->d:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public constructor <init>(Lcom/squareup/moshi/Moshi$Builder;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/squareup/moshi/Moshi;->b:Ljava/lang/ThreadLocal;

    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/squareup/moshi/Moshi;->c:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    iget-object p1, p1, Lcom/squareup/moshi/Moshi$Builder;->a:Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    sget-object v2, Lcom/squareup/moshi/Moshi;->d:Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    add-int/2addr v3, v1

    .line 33
    invoke-direct {v0, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 40
    .line 41
    .line 42
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Lcom/squareup/moshi/Moshi;->a:Ljava/util/List;

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;
    .locals 9

    .line 1
    if-eqz p1, :cond_a

    .line 2
    .line 3
    if-eqz p2, :cond_9

    .line 4
    .line 5
    invoke-static {p1}, Lax/b;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-static {p1}, Lax/b;->g(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    move-object v0, p1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    filled-new-array {p1, p2}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    :goto_0
    iget-object v1, p0, Lcom/squareup/moshi/Moshi;->c:Ljava/util/LinkedHashMap;

    .line 30
    .line 31
    monitor-enter v1

    .line 32
    :try_start_0
    iget-object v2, p0, Lcom/squareup/moshi/Moshi;->c:Ljava/util/LinkedHashMap;

    .line 33
    .line 34
    invoke-virtual {v2, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Lcom/squareup/moshi/JsonAdapter;

    .line 39
    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    monitor-exit v1

    .line 43
    return-object v2

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto/16 :goto_6

    .line 46
    .line 47
    :cond_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    iget-object v1, p0, Lcom/squareup/moshi/Moshi;->b:Ljava/lang/ThreadLocal;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Lcom/squareup/moshi/Moshi$LookupChain;

    .line 55
    .line 56
    if-nez v1, :cond_2

    .line 57
    .line 58
    new-instance v1, Lcom/squareup/moshi/Moshi$LookupChain;

    .line 59
    .line 60
    invoke-direct {v1, p0}, Lcom/squareup/moshi/Moshi$LookupChain;-><init>(Lcom/squareup/moshi/Moshi;)V

    .line 61
    .line 62
    .line 63
    iget-object v2, p0, Lcom/squareup/moshi/Moshi;->b:Ljava/lang/ThreadLocal;

    .line 64
    .line 65
    invoke-virtual {v2, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    :cond_2
    iget-object v2, v1, Lcom/squareup/moshi/Moshi$LookupChain;->b:Ljava/util/ArrayDeque;

    .line 69
    .line 70
    iget-object v3, v1, Lcom/squareup/moshi/Moshi$LookupChain;->a:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    const/4 v5, 0x0

    .line 77
    move v6, v5

    .line 78
    :goto_1
    if-ge v6, v4, :cond_4

    .line 79
    .line 80
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    check-cast v7, Lcom/squareup/moshi/Moshi$Lookup;

    .line 85
    .line 86
    iget-object v8, v7, Lcom/squareup/moshi/Moshi$Lookup;->c:Ljava/lang/Object;

    .line 87
    .line 88
    invoke-virtual {v8, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v8

    .line 92
    if-eqz v8, :cond_3

    .line 93
    .line 94
    invoke-virtual {v2, v7}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    iget-object p3, v7, Lcom/squareup/moshi/Moshi$Lookup;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 98
    .line 99
    if-eqz p3, :cond_5

    .line 100
    .line 101
    move-object v7, p3

    .line 102
    goto :goto_2

    .line 103
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_4
    new-instance v4, Lcom/squareup/moshi/Moshi$Lookup;

    .line 107
    .line 108
    invoke-direct {v4, p1, p3, v0}, Lcom/squareup/moshi/Moshi$Lookup;-><init>(Ljava/lang/reflect/Type;Ljava/lang/String;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    invoke-virtual {v2, v4}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    const/4 v7, 0x0

    .line 118
    :cond_5
    :goto_2
    if-eqz v7, :cond_6

    .line 119
    .line 120
    invoke-virtual {v1, v5}, Lcom/squareup/moshi/Moshi$LookupChain;->b(Z)V

    .line 121
    .line 122
    .line 123
    return-object v7

    .line 124
    :cond_6
    :try_start_1
    iget-object p3, p0, Lcom/squareup/moshi/Moshi;->a:Ljava/util/List;

    .line 125
    .line 126
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 127
    .line 128
    .line 129
    move-result p3

    .line 130
    move v0, v5

    .line 131
    :goto_3
    if-ge v0, p3, :cond_8

    .line 132
    .line 133
    iget-object v2, p0, Lcom/squareup/moshi/Moshi;->a:Ljava/util/List;

    .line 134
    .line 135
    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    check-cast v2, Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 140
    .line 141
    invoke-interface {v2, p1, p2, p0}, Lcom/squareup/moshi/JsonAdapter$Factory;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    if-nez v2, :cond_7

    .line 146
    .line 147
    add-int/lit8 v0, v0, 0x1

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_7
    iget-object p0, v1, Lcom/squareup/moshi/Moshi$LookupChain;->b:Ljava/util/ArrayDeque;

    .line 151
    .line 152
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->getLast()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    check-cast p0, Lcom/squareup/moshi/Moshi$Lookup;

    .line 157
    .line 158
    iput-object v2, p0, Lcom/squareup/moshi/Moshi$Lookup;->d:Lcom/squareup/moshi/JsonAdapter;
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 159
    .line 160
    const/4 p0, 0x1

    .line 161
    invoke-virtual {v1, p0}, Lcom/squareup/moshi/Moshi$LookupChain;->b(Z)V

    .line 162
    .line 163
    .line 164
    return-object v2

    .line 165
    :catchall_1
    move-exception p0

    .line 166
    goto :goto_5

    .line 167
    :catch_0
    move-exception p0

    .line 168
    goto :goto_4

    .line 169
    :cond_8
    :try_start_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 170
    .line 171
    new-instance p3, Ljava/lang/StringBuilder;

    .line 172
    .line 173
    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    .line 174
    .line 175
    .line 176
    const-string v0, "No JsonAdapter for "

    .line 177
    .line 178
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-static {p1, p2}, Lax/b;->j(Ljava/lang/reflect/Type;Ljava/util/Set;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    throw p0
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 196
    :goto_4
    :try_start_3
    invoke-virtual {v1, p0}, Lcom/squareup/moshi/Moshi$LookupChain;->a(Ljava/lang/IllegalArgumentException;)Ljava/lang/IllegalArgumentException;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 201
    :goto_5
    invoke-virtual {v1, v5}, Lcom/squareup/moshi/Moshi$LookupChain;->b(Z)V

    .line 202
    .line 203
    .line 204
    throw p0

    .line 205
    :goto_6
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 206
    throw p0

    .line 207
    :cond_9
    new-instance p0, Ljava/lang/NullPointerException;

    .line 208
    .line 209
    const-string p1, "annotations == null"

    .line 210
    .line 211
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0

    .line 215
    :cond_a
    new-instance p0, Ljava/lang/NullPointerException;

    .line 216
    .line 217
    const-string p1, "type == null"

    .line 218
    .line 219
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    throw p0
.end method

.method public final b(Lcom/squareup/moshi/JsonAdapter$Factory;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/JsonAdapter;
    .locals 3

    .line 1
    if-eqz p3, :cond_3

    .line 2
    .line 3
    invoke-static {p2}, Lax/b;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-static {p2}, Lax/b;->g(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    iget-object v0, p0, Lcom/squareup/moshi/Moshi;->a:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, -0x1

    .line 18
    if-eq v1, v2, :cond_2

    .line 19
    .line 20
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    :goto_0
    if-ge v1, p1, :cond_1

    .line 27
    .line 28
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 33
    .line 34
    invoke-interface {v2, p2, p3, p0}, Lcom/squareup/moshi/JsonAdapter$Factory;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    return-object v2

    .line 41
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 45
    .line 46
    new-instance p1, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    const-string v0, "No next JsonAdapter for "

    .line 49
    .line 50
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p2, p3}, Lax/b;->j(Ljava/lang/reflect/Type;Ljava/util/Set;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 69
    .line 70
    new-instance p2, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    const-string p3, "Unable to skip past unknown factory "

    .line 73
    .line 74
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 89
    .line 90
    const-string p1, "annotations == null"

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0
.end method
