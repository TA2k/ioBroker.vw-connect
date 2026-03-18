.class public final Lcom/google/android/gms/internal/measurement/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lcom/google/android/gms/internal/measurement/o;
.implements Lcom/google/android/gms/internal/measurement/k;


# instance fields
.field public final d:Ljava/util/TreeMap;

.field public final e:Ljava/util/TreeMap;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/TreeMap;

    invoke-direct {v0}, Ljava/util/TreeMap;-><init>()V

    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    new-instance v0, Ljava/util/TreeMap;

    .line 2
    invoke-direct {v0}, Ljava/util/TreeMap;-><init>()V

    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/e;->e:Ljava/util/TreeMap;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 2

    .line 3
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    if-eqz p1, :cond_0

    const/4 v0, 0x0

    .line 4
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_0

    .line 5
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    invoke-virtual {p0, v0, v1}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/o;
    .locals 2

    .line 1
    const-string v0, "length"

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance p1, Lcom/google/android/gms/internal/measurement/h;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    int-to-double v0, p0

    .line 16
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-direct {p1, p0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/e;->i(Ljava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->e:Ljava/util/TreeMap;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Lcom/google/android/gms/internal/measurement/o;

    .line 37
    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_1
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 42
    .line 43
    return-object p0
.end method

.method public final e(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->e:Ljava/util/TreeMap;

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_2

    .line 4
    :cond_0
    instance-of v0, p1, Lcom/google/android/gms/internal/measurement/e;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_1

    .line 9
    :cond_1
    check-cast p1, Lcom/google/android/gms/internal/measurement/e;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eq v0, v1, :cond_2

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_2
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_3

    .line 29
    .line 30
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_3
    invoke-virtual {v0}, Ljava/util/TreeMap;->firstKey()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    :goto_0
    invoke-virtual {v0}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    check-cast v2, Ljava/lang/Integer;

    .line 52
    .line 53
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-gt v1, v2, :cond_5

    .line 58
    .line 59
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-nez v2, :cond_4

    .line 72
    .line 73
    :goto_1
    const/4 p0, 0x0

    .line 74
    return p0

    .line 75
    :cond_4
    add-int/lit8 v1, v1, 0x1

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_5
    :goto_2
    const/4 p0, 0x1

    .line 79
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    mul-int/lit8 p0, p0, 0x1f

    .line 8
    .line 9
    return p0
.end method

.method public final i(Ljava/lang/String;)Z
    .locals 1

    .line 1
    const-string v0, "length"

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->e:Ljava/util/TreeMap;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/d;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/measurement/d;-><init>(Lcom/google/android/gms/internal/measurement/e;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final j()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, ","

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/e;->y(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final k()Ljava/lang/Boolean;
    .locals 0

    .line 1
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Ljava/util/Iterator;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/TreeMap;->keySet()Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/e;->e:Ljava/util/TreeMap;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/TreeMap;->keySet()Ljava/util/Set;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Lcom/google/android/gms/internal/measurement/c;

    .line 22
    .line 23
    invoke-direct {v2, p0, v0, v1}, Lcom/google/android/gms/internal/measurement/c;-><init>(Lcom/google/android/gms/internal/measurement/e;Ljava/util/Iterator;Ljava/util/Iterator;)V

    .line 24
    .line 25
    .line 26
    return-object v2
.end method

.method public final n()Ljava/lang/Double;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/TreeMap;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x1

    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    invoke-virtual {v0}, Ljava/util/TreeMap;->size()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-gtz p0, :cond_1

    .line 25
    .line 26
    const-wide/16 v0, 0x0

    .line 27
    .line 28
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_1
    const-wide/high16 v0, 0x7ff8000000000000L    # Double.NaN

    .line 34
    .line 35
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public final o(Ljava/lang/String;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;)Lcom/google/android/gms/internal/measurement/o;
    .locals 37

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    const-string v4, "concat"

    .line 4
    .line 5
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v5

    .line 9
    const-string v6, "unshift"

    .line 10
    .line 11
    const-string v7, "toString"

    .line 12
    .line 13
    const-string v8, "splice"

    .line 14
    .line 15
    const-string v9, "sort"

    .line 16
    .line 17
    const-string v10, "some"

    .line 18
    .line 19
    const-string v11, "slice"

    .line 20
    .line 21
    const-string v12, "shift"

    .line 22
    .line 23
    const-string v13, "reverse"

    .line 24
    .line 25
    const-string v14, "reduceRight"

    .line 26
    .line 27
    const-string v15, "reduce"

    .line 28
    .line 29
    move/from16 v16, v5

    .line 30
    .line 31
    const-string v5, "push"

    .line 32
    .line 33
    move-object/from16 v17, v4

    .line 34
    .line 35
    const-string v4, "pop"

    .line 36
    .line 37
    const-string v0, "map"

    .line 38
    .line 39
    const-string v2, "lastIndexOf"

    .line 40
    .line 41
    const-string v3, "join"

    .line 42
    .line 43
    move-object/from16 v18, v6

    .line 44
    .line 45
    const-string v6, "indexOf"

    .line 46
    .line 47
    move-object/from16 v19, v7

    .line 48
    .line 49
    const-string v7, "forEach"

    .line 50
    .line 51
    move-object/from16 v20, v8

    .line 52
    .line 53
    const-string v8, "filter"

    .line 54
    .line 55
    move-object/from16 v21, v9

    .line 56
    .line 57
    const-string v9, "every"

    .line 58
    .line 59
    if-nez v16, :cond_4

    .line 60
    .line 61
    invoke-virtual {v9, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v16

    .line 65
    if-nez v16, :cond_4

    .line 66
    .line 67
    invoke-virtual {v8, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v16

    .line 71
    if-nez v16, :cond_4

    .line 72
    .line 73
    invoke-virtual {v7, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v16

    .line 77
    if-nez v16, :cond_4

    .line 78
    .line 79
    invoke-virtual {v6, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v16

    .line 83
    if-nez v16, :cond_4

    .line 84
    .line 85
    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v16

    .line 89
    if-nez v16, :cond_4

    .line 90
    .line 91
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v16

    .line 95
    if-nez v16, :cond_4

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v16

    .line 101
    if-nez v16, :cond_4

    .line 102
    .line 103
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v16

    .line 107
    if-nez v16, :cond_4

    .line 108
    .line 109
    invoke-virtual {v5, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v16

    .line 113
    if-nez v16, :cond_4

    .line 114
    .line 115
    invoke-virtual {v15, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v16

    .line 119
    if-nez v16, :cond_4

    .line 120
    .line 121
    invoke-virtual {v14, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v16

    .line 125
    if-nez v16, :cond_4

    .line 126
    .line 127
    invoke-virtual {v13, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v16

    .line 131
    if-nez v16, :cond_4

    .line 132
    .line 133
    invoke-virtual {v12, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v16

    .line 137
    if-nez v16, :cond_4

    .line 138
    .line 139
    invoke-virtual {v11, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v16

    .line 143
    if-nez v16, :cond_4

    .line 144
    .line 145
    invoke-virtual {v10, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v16

    .line 149
    if-nez v16, :cond_4

    .line 150
    .line 151
    move-object/from16 v16, v8

    .line 152
    .line 153
    move-object/from16 v8, v21

    .line 154
    .line 155
    invoke-virtual {v8, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v21

    .line 159
    if-nez v21, :cond_3

    .line 160
    .line 161
    move-object/from16 v21, v15

    .line 162
    .line 163
    move-object/from16 v15, v20

    .line 164
    .line 165
    invoke-virtual {v15, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v20

    .line 169
    if-nez v20, :cond_2

    .line 170
    .line 171
    move-object/from16 v20, v15

    .line 172
    .line 173
    move-object/from16 v15, v19

    .line 174
    .line 175
    invoke-virtual {v15, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v19

    .line 179
    if-nez v19, :cond_1

    .line 180
    .line 181
    move-object/from16 v19, v15

    .line 182
    .line 183
    move-object/from16 v15, v18

    .line 184
    .line 185
    invoke-virtual {v15, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v18

    .line 189
    if-eqz v18, :cond_0

    .line 190
    .line 191
    move-object/from16 v22, v2

    .line 192
    .line 193
    move-object/from16 v18, v7

    .line 194
    .line 195
    move-object/from16 v23, v15

    .line 196
    .line 197
    move-object/from16 v7, p0

    .line 198
    .line 199
    move-object/from16 v2, p2

    .line 200
    .line 201
    :goto_0
    move-object/from16 v15, p3

    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_0
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 205
    .line 206
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    move-object/from16 v1, p0

    .line 210
    .line 211
    move-object/from16 v2, p2

    .line 212
    .line 213
    move-object/from16 v3, p3

    .line 214
    .line 215
    invoke-static {v1, v0, v2, v3}, Lcom/google/android/gms/internal/measurement/k;->g(Lcom/google/android/gms/internal/measurement/k;Lcom/google/android/gms/internal/measurement/r;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;)Lcom/google/android/gms/internal/measurement/o;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    return-object v0

    .line 220
    :cond_1
    move-object/from16 v22, v2

    .line 221
    .line 222
    move-object/from16 v19, v15

    .line 223
    .line 224
    :goto_1
    move-object/from16 v23, v18

    .line 225
    .line 226
    move-object/from16 v2, p2

    .line 227
    .line 228
    move-object/from16 v15, p3

    .line 229
    .line 230
    move-object/from16 v18, v7

    .line 231
    .line 232
    move-object/from16 v7, p0

    .line 233
    .line 234
    goto :goto_2

    .line 235
    :cond_2
    move-object/from16 v22, v2

    .line 236
    .line 237
    move-object/from16 v20, v15

    .line 238
    .line 239
    goto :goto_1

    .line 240
    :cond_3
    move-object/from16 v22, v2

    .line 241
    .line 242
    move-object/from16 v21, v15

    .line 243
    .line 244
    goto :goto_1

    .line 245
    :cond_4
    move-object/from16 v22, v2

    .line 246
    .line 247
    move-object/from16 v16, v8

    .line 248
    .line 249
    move-object/from16 v23, v18

    .line 250
    .line 251
    move-object/from16 v8, v21

    .line 252
    .line 253
    move-object/from16 v2, p2

    .line 254
    .line 255
    move-object/from16 v18, v7

    .line 256
    .line 257
    move-object/from16 v21, v15

    .line 258
    .line 259
    move-object/from16 v7, p0

    .line 260
    .line 261
    goto :goto_0

    .line 262
    :goto_2
    const-wide/high16 v24, -0x4010000000000000L    # -1.0

    .line 263
    .line 264
    move-object/from16 v26, v0

    .line 265
    .line 266
    invoke-static/range {v24 .. v25}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 271
    .line 272
    .line 273
    move-result v24

    .line 274
    move-object/from16 v25, v4

    .line 275
    .line 276
    const-string v4, ","

    .line 277
    .line 278
    move-object/from16 v30, v4

    .line 279
    .line 280
    iget-object v4, v7, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 281
    .line 282
    sget-object v31, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 283
    .line 284
    move-object/from16 v32, v4

    .line 285
    .line 286
    const-string v4, "Callback should be a method"

    .line 287
    .line 288
    move-object/from16 v33, v3

    .line 289
    .line 290
    move-object/from16 v34, v4

    .line 291
    .line 292
    const-wide/16 v35, 0x0

    .line 293
    .line 294
    const/4 v3, 0x0

    .line 295
    sparse-switch v24, :sswitch_data_0

    .line 296
    .line 297
    .line 298
    goto/16 :goto_20

    .line 299
    .line 300
    :sswitch_0
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v1

    .line 304
    if-eqz v1, :cond_44

    .line 305
    .line 306
    const/4 v1, 0x2

    .line 307
    invoke-static {v1, v6, v15}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 311
    .line 312
    .line 313
    move-result v1

    .line 314
    if-nez v1, :cond_5

    .line 315
    .line 316
    const/4 v1, 0x0

    .line 317
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v1

    .line 321
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 322
    .line 323
    iget-object v3, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 324
    .line 325
    check-cast v3, Lcom/google/android/gms/internal/measurement/u;

    .line 326
    .line 327
    invoke-virtual {v3, v2, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 328
    .line 329
    .line 330
    move-result-object v31

    .line 331
    :cond_5
    move-object/from16 v1, v31

    .line 332
    .line 333
    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    .line 334
    .line 335
    .line 336
    move-result v3

    .line 337
    const/4 v4, 0x1

    .line 338
    if-le v3, v4, :cond_8

    .line 339
    .line 340
    invoke-virtual {v15, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v3

    .line 344
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 345
    .line 346
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 347
    .line 348
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 349
    .line 350
    invoke-virtual {v4, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 351
    .line 352
    .line 353
    move-result-object v2

    .line 354
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 359
    .line 360
    .line 361
    move-result-wide v2

    .line 362
    invoke-static {v2, v3}, Ljp/wd;->i(D)D

    .line 363
    .line 364
    .line 365
    move-result-wide v2

    .line 366
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 367
    .line 368
    .line 369
    move-result v4

    .line 370
    int-to-double v4, v4

    .line 371
    cmpl-double v4, v2, v4

    .line 372
    .line 373
    if-ltz v4, :cond_6

    .line 374
    .line 375
    new-instance v1, Lcom/google/android/gms/internal/measurement/h;

    .line 376
    .line 377
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 378
    .line 379
    .line 380
    return-object v1

    .line 381
    :cond_6
    cmpg-double v4, v2, v35

    .line 382
    .line 383
    if-gez v4, :cond_7

    .line 384
    .line 385
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 386
    .line 387
    .line 388
    move-result v4

    .line 389
    int-to-double v4, v4

    .line 390
    add-double v3, v4, v2

    .line 391
    .line 392
    goto :goto_3

    .line 393
    :cond_7
    move-wide v3, v2

    .line 394
    goto :goto_3

    .line 395
    :cond_8
    move-wide/from16 v3, v35

    .line 396
    .line 397
    :goto_3
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 398
    .line 399
    .line 400
    move-result-object v2

    .line 401
    :cond_9
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 402
    .line 403
    .line 404
    move-result v5

    .line 405
    if-eqz v5, :cond_a

    .line 406
    .line 407
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v5

    .line 411
    check-cast v5, Ljava/lang/Integer;

    .line 412
    .line 413
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 414
    .line 415
    .line 416
    move-result v5

    .line 417
    int-to-double v8, v5

    .line 418
    cmpg-double v6, v8, v3

    .line 419
    .line 420
    if-ltz v6, :cond_9

    .line 421
    .line 422
    invoke-virtual {v7, v5}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 423
    .line 424
    .line 425
    move-result-object v5

    .line 426
    invoke-static {v5, v1}, Ljp/wd;->g(Lcom/google/android/gms/internal/measurement/o;Lcom/google/android/gms/internal/measurement/o;)Z

    .line 427
    .line 428
    .line 429
    move-result v5

    .line 430
    if-eqz v5, :cond_9

    .line 431
    .line 432
    new-instance v0, Lcom/google/android/gms/internal/measurement/h;

    .line 433
    .line 434
    invoke-static {v8, v9}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 435
    .line 436
    .line 437
    move-result-object v1

    .line 438
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 439
    .line 440
    .line 441
    return-object v0

    .line 442
    :cond_a
    new-instance v1, Lcom/google/android/gms/internal/measurement/h;

    .line 443
    .line 444
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 445
    .line 446
    .line 447
    return-object v1

    .line 448
    :sswitch_1
    invoke-virtual {v1, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 449
    .line 450
    .line 451
    move-result v0

    .line 452
    if-eqz v0, :cond_44

    .line 453
    .line 454
    const/4 v1, 0x0

    .line 455
    invoke-static {v1, v13, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 459
    .line 460
    .line 461
    move-result v0

    .line 462
    if-eqz v0, :cond_17

    .line 463
    .line 464
    const/4 v4, 0x0

    .line 465
    :goto_4
    div-int/lit8 v1, v0, 0x2

    .line 466
    .line 467
    if-ge v4, v1, :cond_17

    .line 468
    .line 469
    invoke-virtual {v7, v4}, Lcom/google/android/gms/internal/measurement/e;->w(I)Z

    .line 470
    .line 471
    .line 472
    move-result v1

    .line 473
    if-eqz v1, :cond_c

    .line 474
    .line 475
    invoke-virtual {v7, v4}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 476
    .line 477
    .line 478
    move-result-object v1

    .line 479
    invoke-virtual {v7, v4, v3}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 480
    .line 481
    .line 482
    add-int/lit8 v2, v0, -0x1

    .line 483
    .line 484
    sub-int/2addr v2, v4

    .line 485
    invoke-virtual {v7, v2}, Lcom/google/android/gms/internal/measurement/e;->w(I)Z

    .line 486
    .line 487
    .line 488
    move-result v5

    .line 489
    if-eqz v5, :cond_b

    .line 490
    .line 491
    invoke-virtual {v7, v2}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 492
    .line 493
    .line 494
    move-result-object v5

    .line 495
    invoke-virtual {v7, v4, v5}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 496
    .line 497
    .line 498
    :cond_b
    invoke-virtual {v7, v2, v1}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 499
    .line 500
    .line 501
    :cond_c
    add-int/lit8 v4, v4, 0x1

    .line 502
    .line 503
    goto :goto_4

    .line 504
    :sswitch_2
    invoke-virtual {v1, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 505
    .line 506
    .line 507
    move-result v0

    .line 508
    if-eqz v0, :cond_44

    .line 509
    .line 510
    const/4 v1, 0x0

    .line 511
    invoke-static {v7, v2, v15, v1}, Ljp/td;->b(Lcom/google/android/gms/internal/measurement/e;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;Z)Lcom/google/android/gms/internal/measurement/o;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    return-object v0

    .line 516
    :sswitch_3
    invoke-virtual {v1, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 517
    .line 518
    .line 519
    move-result v0

    .line 520
    if-eqz v0, :cond_44

    .line 521
    .line 522
    const/4 v1, 0x2

    .line 523
    invoke-static {v1, v11, v15}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 527
    .line 528
    .line 529
    move-result v0

    .line 530
    if-eqz v0, :cond_d

    .line 531
    .line 532
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->p()Lcom/google/android/gms/internal/measurement/o;

    .line 533
    .line 534
    .line 535
    move-result-object v0

    .line 536
    return-object v0

    .line 537
    :cond_d
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 538
    .line 539
    .line 540
    move-result v0

    .line 541
    int-to-double v0, v0

    .line 542
    const/4 v3, 0x0

    .line 543
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 544
    .line 545
    .line 546
    move-result-object v3

    .line 547
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 548
    .line 549
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 550
    .line 551
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 552
    .line 553
    invoke-virtual {v4, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 554
    .line 555
    .line 556
    move-result-object v3

    .line 557
    invoke-interface {v3}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 558
    .line 559
    .line 560
    move-result-object v3

    .line 561
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 562
    .line 563
    .line 564
    move-result-wide v3

    .line 565
    invoke-static {v3, v4}, Ljp/wd;->i(D)D

    .line 566
    .line 567
    .line 568
    move-result-wide v3

    .line 569
    cmpg-double v5, v3, v35

    .line 570
    .line 571
    if-gez v5, :cond_e

    .line 572
    .line 573
    add-double/2addr v3, v0

    .line 574
    move-wide/from16 v5, v35

    .line 575
    .line 576
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->max(DD)D

    .line 577
    .line 578
    .line 579
    move-result-wide v3

    .line 580
    goto :goto_5

    .line 581
    :cond_e
    invoke-static {v3, v4, v0, v1}, Ljava/lang/Math;->min(DD)D

    .line 582
    .line 583
    .line 584
    move-result-wide v3

    .line 585
    :goto_5
    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    .line 586
    .line 587
    .line 588
    move-result v5

    .line 589
    const/4 v6, 0x2

    .line 590
    if-ne v5, v6, :cond_10

    .line 591
    .line 592
    const/4 v5, 0x1

    .line 593
    invoke-virtual {v15, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 594
    .line 595
    .line 596
    move-result-object v5

    .line 597
    check-cast v5, Lcom/google/android/gms/internal/measurement/o;

    .line 598
    .line 599
    iget-object v6, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 600
    .line 601
    check-cast v6, Lcom/google/android/gms/internal/measurement/u;

    .line 602
    .line 603
    invoke-virtual {v6, v2, v5}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 604
    .line 605
    .line 606
    move-result-object v2

    .line 607
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 608
    .line 609
    .line 610
    move-result-object v2

    .line 611
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 612
    .line 613
    .line 614
    move-result-wide v5

    .line 615
    invoke-static {v5, v6}, Ljp/wd;->i(D)D

    .line 616
    .line 617
    .line 618
    move-result-wide v5

    .line 619
    const-wide/16 v8, 0x0

    .line 620
    .line 621
    cmpg-double v2, v5, v8

    .line 622
    .line 623
    if-gez v2, :cond_f

    .line 624
    .line 625
    add-double/2addr v0, v5

    .line 626
    invoke-static {v0, v1, v8, v9}, Ljava/lang/Math;->max(DD)D

    .line 627
    .line 628
    .line 629
    move-result-wide v0

    .line 630
    goto :goto_6

    .line 631
    :cond_f
    invoke-static {v0, v1, v5, v6}, Ljava/lang/Math;->min(DD)D

    .line 632
    .line 633
    .line 634
    move-result-wide v0

    .line 635
    :cond_10
    :goto_6
    new-instance v2, Lcom/google/android/gms/internal/measurement/e;

    .line 636
    .line 637
    invoke-direct {v2}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 638
    .line 639
    .line 640
    double-to-int v3, v3

    .line 641
    :goto_7
    int-to-double v4, v3

    .line 642
    cmpg-double v4, v4, v0

    .line 643
    .line 644
    if-gez v4, :cond_11

    .line 645
    .line 646
    invoke-virtual {v7, v3}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 647
    .line 648
    .line 649
    move-result-object v4

    .line 650
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 651
    .line 652
    .line 653
    move-result v5

    .line 654
    invoke-virtual {v2, v5, v4}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 655
    .line 656
    .line 657
    add-int/lit8 v3, v3, 0x1

    .line 658
    .line 659
    goto :goto_7

    .line 660
    :cond_11
    return-object v2

    .line 661
    :sswitch_4
    invoke-virtual {v1, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 662
    .line 663
    .line 664
    move-result v0

    .line 665
    if-eqz v0, :cond_44

    .line 666
    .line 667
    const/4 v3, 0x0

    .line 668
    invoke-static {v3, v12, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 669
    .line 670
    .line 671
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 672
    .line 673
    .line 674
    move-result v0

    .line 675
    if-nez v0, :cond_12

    .line 676
    .line 677
    goto/16 :goto_16

    .line 678
    .line 679
    :cond_12
    invoke-virtual {v7, v3}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 680
    .line 681
    .line 682
    move-result-object v0

    .line 683
    invoke-virtual {v7, v3}, Lcom/google/android/gms/internal/measurement/e;->x(I)V

    .line 684
    .line 685
    .line 686
    return-object v0

    .line 687
    :sswitch_5
    const/4 v3, 0x0

    .line 688
    invoke-virtual {v1, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 689
    .line 690
    .line 691
    move-result v0

    .line 692
    if-eqz v0, :cond_44

    .line 693
    .line 694
    const/4 v4, 0x1

    .line 695
    invoke-static {v4, v9, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 696
    .line 697
    .line 698
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 699
    .line 700
    .line 701
    move-result-object v0

    .line 702
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 703
    .line 704
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 705
    .line 706
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 707
    .line 708
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 709
    .line 710
    .line 711
    move-result-object v0

    .line 712
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/n;

    .line 713
    .line 714
    if-eqz v1, :cond_14

    .line 715
    .line 716
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 717
    .line 718
    .line 719
    move-result v1

    .line 720
    if-nez v1, :cond_13

    .line 721
    .line 722
    goto/16 :goto_a

    .line 723
    .line 724
    :cond_13
    check-cast v0, Lcom/google/android/gms/internal/measurement/n;

    .line 725
    .line 726
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 727
    .line 728
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 729
    .line 730
    invoke-static {v7, v2, v0, v1, v3}, Ljp/td;->c(Lcom/google/android/gms/internal/measurement/e;Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/n;Ljava/lang/Boolean;Ljava/lang/Boolean;)Lcom/google/android/gms/internal/measurement/e;

    .line 731
    .line 732
    .line 733
    move-result-object v0

    .line 734
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 735
    .line 736
    .line 737
    move-result v0

    .line 738
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 739
    .line 740
    .line 741
    move-result v1

    .line 742
    if-eq v0, v1, :cond_1a

    .line 743
    .line 744
    goto/16 :goto_b

    .line 745
    .line 746
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 747
    .line 748
    move-object/from16 v4, v34

    .line 749
    .line 750
    invoke-direct {v0, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 751
    .line 752
    .line 753
    throw v0

    .line 754
    :sswitch_6
    invoke-virtual {v1, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 755
    .line 756
    .line 757
    move-result v0

    .line 758
    if-eqz v0, :cond_44

    .line 759
    .line 760
    const/4 v4, 0x1

    .line 761
    invoke-static {v4, v8, v15}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 762
    .line 763
    .line 764
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 765
    .line 766
    .line 767
    move-result v0

    .line 768
    const/4 v1, 0x2

    .line 769
    if-lt v0, v1, :cond_17

    .line 770
    .line 771
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->r()Ljava/util/List;

    .line 772
    .line 773
    .line 774
    move-result-object v0

    .line 775
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 776
    .line 777
    .line 778
    move-result v1

    .line 779
    if-nez v1, :cond_16

    .line 780
    .line 781
    const/4 v1, 0x0

    .line 782
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 783
    .line 784
    .line 785
    move-result-object v3

    .line 786
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 787
    .line 788
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 789
    .line 790
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 791
    .line 792
    invoke-virtual {v1, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 793
    .line 794
    .line 795
    move-result-object v1

    .line 796
    instance-of v3, v1, Lcom/google/android/gms/internal/measurement/i;

    .line 797
    .line 798
    if-eqz v3, :cond_15

    .line 799
    .line 800
    move-object v3, v1

    .line 801
    check-cast v3, Lcom/google/android/gms/internal/measurement/i;

    .line 802
    .line 803
    goto :goto_8

    .line 804
    :cond_15
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 805
    .line 806
    const-string v1, "Comparator should be a method"

    .line 807
    .line 808
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 809
    .line 810
    .line 811
    throw v0

    .line 812
    :cond_16
    :goto_8
    new-instance v1, Lcom/google/android/gms/internal/measurement/v;

    .line 813
    .line 814
    invoke-direct {v1, v3, v2}, Lcom/google/android/gms/internal/measurement/v;-><init>(Lcom/google/android/gms/internal/measurement/i;Lcom/google/firebase/messaging/w;)V

    .line 815
    .line 816
    .line 817
    invoke-static {v0, v1}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 818
    .line 819
    .line 820
    invoke-virtual/range {v32 .. v32}, Ljava/util/TreeMap;->clear()V

    .line 821
    .line 822
    .line 823
    check-cast v0, Ljava/util/ArrayList;

    .line 824
    .line 825
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 826
    .line 827
    .line 828
    move-result-object v0

    .line 829
    const/4 v4, 0x0

    .line 830
    :goto_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 831
    .line 832
    .line 833
    move-result v1

    .line 834
    if-eqz v1, :cond_17

    .line 835
    .line 836
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v1

    .line 840
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 841
    .line 842
    add-int/lit8 v2, v4, 0x1

    .line 843
    .line 844
    invoke-virtual {v7, v4, v1}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 845
    .line 846
    .line 847
    move v4, v2

    .line 848
    goto :goto_9

    .line 849
    :cond_17
    return-object v7

    .line 850
    :sswitch_7
    move-object/from16 v4, v34

    .line 851
    .line 852
    invoke-virtual {v1, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 853
    .line 854
    .line 855
    move-result v0

    .line 856
    if-eqz v0, :cond_44

    .line 857
    .line 858
    const/4 v5, 0x1

    .line 859
    invoke-static {v5, v10, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 860
    .line 861
    .line 862
    const/4 v1, 0x0

    .line 863
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 864
    .line 865
    .line 866
    move-result-object v0

    .line 867
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 868
    .line 869
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 870
    .line 871
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 872
    .line 873
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 874
    .line 875
    .line 876
    move-result-object v0

    .line 877
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/i;

    .line 878
    .line 879
    if-eqz v1, :cond_1c

    .line 880
    .line 881
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 882
    .line 883
    .line 884
    move-result v1

    .line 885
    if-nez v1, :cond_18

    .line 886
    .line 887
    goto :goto_b

    .line 888
    :cond_18
    check-cast v0, Lcom/google/android/gms/internal/measurement/i;

    .line 889
    .line 890
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 891
    .line 892
    .line 893
    move-result-object v1

    .line 894
    :cond_19
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 895
    .line 896
    .line 897
    move-result v3

    .line 898
    if-eqz v3, :cond_1b

    .line 899
    .line 900
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 901
    .line 902
    .line 903
    move-result-object v3

    .line 904
    check-cast v3, Ljava/lang/Integer;

    .line 905
    .line 906
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 907
    .line 908
    .line 909
    move-result v3

    .line 910
    invoke-virtual {v7, v3}, Lcom/google/android/gms/internal/measurement/e;->w(I)Z

    .line 911
    .line 912
    .line 913
    move-result v4

    .line 914
    if-eqz v4, :cond_19

    .line 915
    .line 916
    invoke-virtual {v7, v3}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 917
    .line 918
    .line 919
    move-result-object v4

    .line 920
    int-to-double v5, v3

    .line 921
    new-instance v3, Lcom/google/android/gms/internal/measurement/h;

    .line 922
    .line 923
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 924
    .line 925
    .line 926
    move-result-object v5

    .line 927
    invoke-direct {v3, v5}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 928
    .line 929
    .line 930
    const/4 v5, 0x3

    .line 931
    new-array v5, v5, [Lcom/google/android/gms/internal/measurement/o;

    .line 932
    .line 933
    const/16 v27, 0x0

    .line 934
    .line 935
    aput-object v4, v5, v27

    .line 936
    .line 937
    const/16 v28, 0x1

    .line 938
    .line 939
    aput-object v3, v5, v28

    .line 940
    .line 941
    const/16 v29, 0x2

    .line 942
    .line 943
    aput-object v7, v5, v29

    .line 944
    .line 945
    invoke-static {v5}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 946
    .line 947
    .line 948
    move-result-object v3

    .line 949
    invoke-virtual {v0, v2, v3}, Lcom/google/android/gms/internal/measurement/i;->a(Lcom/google/firebase/messaging/w;Ljava/util/List;)Lcom/google/android/gms/internal/measurement/o;

    .line 950
    .line 951
    .line 952
    move-result-object v3

    .line 953
    invoke-interface {v3}, Lcom/google/android/gms/internal/measurement/o;->k()Ljava/lang/Boolean;

    .line 954
    .line 955
    .line 956
    move-result-object v3

    .line 957
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 958
    .line 959
    .line 960
    move-result v3

    .line 961
    if-eqz v3, :cond_19

    .line 962
    .line 963
    :cond_1a
    :goto_a
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->r0:Lcom/google/android/gms/internal/measurement/f;

    .line 964
    .line 965
    return-object v0

    .line 966
    :cond_1b
    :goto_b
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->s0:Lcom/google/android/gms/internal/measurement/f;

    .line 967
    .line 968
    return-object v0

    .line 969
    :cond_1c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 970
    .line 971
    invoke-direct {v0, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 972
    .line 973
    .line 974
    throw v0

    .line 975
    :sswitch_8
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 976
    .line 977
    .line 978
    move-result v0

    .line 979
    if-eqz v0, :cond_44

    .line 980
    .line 981
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 982
    .line 983
    .line 984
    move-result v0

    .line 985
    if-nez v0, :cond_1d

    .line 986
    .line 987
    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 988
    .line 989
    .line 990
    move-result-object v0

    .line 991
    :goto_c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 992
    .line 993
    .line 994
    move-result v1

    .line 995
    if-eqz v1, :cond_1d

    .line 996
    .line 997
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 998
    .line 999
    .line 1000
    move-result-object v1

    .line 1001
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 1002
    .line 1003
    iget-object v3, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1004
    .line 1005
    check-cast v3, Lcom/google/android/gms/internal/measurement/u;

    .line 1006
    .line 1007
    invoke-virtual {v3, v2, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v1

    .line 1011
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1012
    .line 1013
    .line 1014
    move-result v3

    .line 1015
    invoke-virtual {v7, v3, v1}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1016
    .line 1017
    .line 1018
    goto :goto_c

    .line 1019
    :cond_1d
    new-instance v0, Lcom/google/android/gms/internal/measurement/h;

    .line 1020
    .line 1021
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1022
    .line 1023
    .line 1024
    move-result v1

    .line 1025
    int-to-double v1, v1

    .line 1026
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v1

    .line 1030
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1031
    .line 1032
    .line 1033
    return-object v0

    .line 1034
    :sswitch_9
    move-object/from16 v0, v33

    .line 1035
    .line 1036
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1037
    .line 1038
    .line 1039
    move-result v1

    .line 1040
    if-eqz v1, :cond_44

    .line 1041
    .line 1042
    const/4 v4, 0x1

    .line 1043
    invoke-static {v4, v0, v15}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 1044
    .line 1045
    .line 1046
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1047
    .line 1048
    .line 1049
    move-result v0

    .line 1050
    if-nez v0, :cond_1e

    .line 1051
    .line 1052
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->t0:Lcom/google/android/gms/internal/measurement/r;

    .line 1053
    .line 1054
    return-object v0

    .line 1055
    :cond_1e
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1056
    .line 1057
    .line 1058
    move-result v0

    .line 1059
    if-nez v0, :cond_21

    .line 1060
    .line 1061
    const/4 v1, 0x0

    .line 1062
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v0

    .line 1066
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1067
    .line 1068
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1069
    .line 1070
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1071
    .line 1072
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1073
    .line 1074
    .line 1075
    move-result-object v0

    .line 1076
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/m;

    .line 1077
    .line 1078
    if-nez v1, :cond_20

    .line 1079
    .line 1080
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/s;

    .line 1081
    .line 1082
    if-eqz v1, :cond_1f

    .line 1083
    .line 1084
    goto :goto_d

    .line 1085
    :cond_1f
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 1086
    .line 1087
    .line 1088
    move-result-object v4

    .line 1089
    goto :goto_e

    .line 1090
    :cond_20
    :goto_d
    const-string v4, ""

    .line 1091
    .line 1092
    goto :goto_e

    .line 1093
    :cond_21
    move-object/from16 v4, v30

    .line 1094
    .line 1095
    :goto_e
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1096
    .line 1097
    invoke-virtual {v7, v4}, Lcom/google/android/gms/internal/measurement/e;->y(Ljava/lang/String;)Ljava/lang/String;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v1

    .line 1101
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1102
    .line 1103
    .line 1104
    return-object v0

    .line 1105
    :sswitch_a
    move-object/from16 v0, v25

    .line 1106
    .line 1107
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1108
    .line 1109
    .line 1110
    move-result v1

    .line 1111
    if-eqz v1, :cond_44

    .line 1112
    .line 1113
    const/4 v1, 0x0

    .line 1114
    invoke-static {v1, v0, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1115
    .line 1116
    .line 1117
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1118
    .line 1119
    .line 1120
    move-result v0

    .line 1121
    if-nez v0, :cond_22

    .line 1122
    .line 1123
    goto/16 :goto_16

    .line 1124
    .line 1125
    :cond_22
    add-int/lit8 v0, v0, -0x1

    .line 1126
    .line 1127
    invoke-virtual {v7, v0}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v1

    .line 1131
    invoke-virtual {v7, v0}, Lcom/google/android/gms/internal/measurement/e;->x(I)V

    .line 1132
    .line 1133
    .line 1134
    return-object v1

    .line 1135
    :sswitch_b
    move-object/from16 v0, v26

    .line 1136
    .line 1137
    move-object/from16 v4, v34

    .line 1138
    .line 1139
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1140
    .line 1141
    .line 1142
    move-result v1

    .line 1143
    if-eqz v1, :cond_44

    .line 1144
    .line 1145
    const/4 v5, 0x1

    .line 1146
    invoke-static {v5, v0, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1147
    .line 1148
    .line 1149
    const/4 v1, 0x0

    .line 1150
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v0

    .line 1154
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1155
    .line 1156
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1157
    .line 1158
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1159
    .line 1160
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1161
    .line 1162
    .line 1163
    move-result-object v0

    .line 1164
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/n;

    .line 1165
    .line 1166
    if-eqz v1, :cond_24

    .line 1167
    .line 1168
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1169
    .line 1170
    .line 1171
    move-result v1

    .line 1172
    if-nez v1, :cond_23

    .line 1173
    .line 1174
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 1175
    .line 1176
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 1177
    .line 1178
    .line 1179
    return-object v0

    .line 1180
    :cond_23
    check-cast v0, Lcom/google/android/gms/internal/measurement/n;

    .line 1181
    .line 1182
    invoke-static {v7, v2, v0, v3, v3}, Ljp/td;->c(Lcom/google/android/gms/internal/measurement/e;Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/n;Ljava/lang/Boolean;Ljava/lang/Boolean;)Lcom/google/android/gms/internal/measurement/e;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v0

    .line 1186
    return-object v0

    .line 1187
    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1188
    .line 1189
    invoke-direct {v0, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1190
    .line 1191
    .line 1192
    throw v0

    .line 1193
    :sswitch_c
    move-object/from16 v0, v23

    .line 1194
    .line 1195
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1196
    .line 1197
    .line 1198
    move-result v0

    .line 1199
    if-eqz v0, :cond_44

    .line 1200
    .line 1201
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1202
    .line 1203
    .line 1204
    move-result v0

    .line 1205
    if-nez v0, :cond_28

    .line 1206
    .line 1207
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 1208
    .line 1209
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 1210
    .line 1211
    .line 1212
    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1213
    .line 1214
    .line 1215
    move-result-object v1

    .line 1216
    :goto_f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1217
    .line 1218
    .line 1219
    move-result v3

    .line 1220
    if-eqz v3, :cond_26

    .line 1221
    .line 1222
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1223
    .line 1224
    .line 1225
    move-result-object v3

    .line 1226
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 1227
    .line 1228
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1229
    .line 1230
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 1231
    .line 1232
    invoke-virtual {v4, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v3

    .line 1236
    instance-of v4, v3, Lcom/google/android/gms/internal/measurement/g;

    .line 1237
    .line 1238
    if-nez v4, :cond_25

    .line 1239
    .line 1240
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1241
    .line 1242
    .line 1243
    move-result v4

    .line 1244
    invoke-virtual {v0, v4, v3}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1245
    .line 1246
    .line 1247
    goto :goto_f

    .line 1248
    :cond_25
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1249
    .line 1250
    const-string v1, "Argument evaluation failed"

    .line 1251
    .line 1252
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1253
    .line 1254
    .line 1255
    throw v0

    .line 1256
    :cond_26
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1257
    .line 1258
    .line 1259
    move-result v1

    .line 1260
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 1261
    .line 1262
    .line 1263
    move-result-object v2

    .line 1264
    :goto_10
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1265
    .line 1266
    .line 1267
    move-result v3

    .line 1268
    if-eqz v3, :cond_27

    .line 1269
    .line 1270
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v3

    .line 1274
    check-cast v3, Ljava/lang/Integer;

    .line 1275
    .line 1276
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1277
    .line 1278
    .line 1279
    move-result v4

    .line 1280
    add-int/2addr v4, v1

    .line 1281
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1282
    .line 1283
    .line 1284
    move-result v3

    .line 1285
    invoke-virtual {v7, v3}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1286
    .line 1287
    .line 1288
    move-result-object v3

    .line 1289
    invoke-virtual {v0, v4, v3}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1290
    .line 1291
    .line 1292
    goto :goto_10

    .line 1293
    :cond_27
    invoke-virtual/range {v32 .. v32}, Ljava/util/TreeMap;->clear()V

    .line 1294
    .line 1295
    .line 1296
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 1297
    .line 1298
    .line 1299
    move-result-object v1

    .line 1300
    :goto_11
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1301
    .line 1302
    .line 1303
    move-result v2

    .line 1304
    if-eqz v2, :cond_28

    .line 1305
    .line 1306
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v2

    .line 1310
    check-cast v2, Ljava/lang/Integer;

    .line 1311
    .line 1312
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1313
    .line 1314
    .line 1315
    move-result v3

    .line 1316
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1317
    .line 1318
    .line 1319
    move-result v2

    .line 1320
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v2

    .line 1324
    invoke-virtual {v7, v3, v2}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1325
    .line 1326
    .line 1327
    goto :goto_11

    .line 1328
    :cond_28
    new-instance v0, Lcom/google/android/gms/internal/measurement/h;

    .line 1329
    .line 1330
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1331
    .line 1332
    .line 1333
    move-result v1

    .line 1334
    int-to-double v1, v1

    .line 1335
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v1

    .line 1339
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1340
    .line 1341
    .line 1342
    return-object v0

    .line 1343
    :sswitch_d
    move-object/from16 v3, v22

    .line 1344
    .line 1345
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1346
    .line 1347
    .line 1348
    move-result v1

    .line 1349
    if-eqz v1, :cond_44

    .line 1350
    .line 1351
    const/4 v1, 0x2

    .line 1352
    invoke-static {v1, v3, v15}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 1353
    .line 1354
    .line 1355
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1356
    .line 1357
    .line 1358
    move-result v1

    .line 1359
    if-nez v1, :cond_29

    .line 1360
    .line 1361
    const/4 v1, 0x0

    .line 1362
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v1

    .line 1366
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 1367
    .line 1368
    iget-object v3, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1369
    .line 1370
    check-cast v3, Lcom/google/android/gms/internal/measurement/u;

    .line 1371
    .line 1372
    invoke-virtual {v3, v2, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v31

    .line 1376
    :cond_29
    move-object/from16 v1, v31

    .line 1377
    .line 1378
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1379
    .line 1380
    .line 1381
    move-result v3

    .line 1382
    add-int/lit8 v3, v3, -0x1

    .line 1383
    .line 1384
    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    .line 1385
    .line 1386
    .line 1387
    move-result v4

    .line 1388
    const/4 v5, 0x1

    .line 1389
    if-le v4, v5, :cond_2b

    .line 1390
    .line 1391
    invoke-virtual {v15, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1392
    .line 1393
    .line 1394
    move-result-object v3

    .line 1395
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 1396
    .line 1397
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1398
    .line 1399
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 1400
    .line 1401
    invoke-virtual {v4, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1402
    .line 1403
    .line 1404
    move-result-object v2

    .line 1405
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1406
    .line 1407
    .line 1408
    move-result-object v3

    .line 1409
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 1410
    .line 1411
    .line 1412
    move-result-wide v3

    .line 1413
    invoke-static {v3, v4}, Ljava/lang/Double;->isNaN(D)Z

    .line 1414
    .line 1415
    .line 1416
    move-result v3

    .line 1417
    if-eqz v3, :cond_2a

    .line 1418
    .line 1419
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1420
    .line 1421
    .line 1422
    move-result v2

    .line 1423
    add-int/lit8 v2, v2, -0x1

    .line 1424
    .line 1425
    int-to-double v2, v2

    .line 1426
    :goto_12
    const-wide/16 v35, 0x0

    .line 1427
    .line 1428
    goto :goto_13

    .line 1429
    :cond_2a
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1430
    .line 1431
    .line 1432
    move-result-object v2

    .line 1433
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 1434
    .line 1435
    .line 1436
    move-result-wide v2

    .line 1437
    invoke-static {v2, v3}, Ljp/wd;->i(D)D

    .line 1438
    .line 1439
    .line 1440
    move-result-wide v2

    .line 1441
    goto :goto_12

    .line 1442
    :goto_13
    cmpg-double v4, v2, v35

    .line 1443
    .line 1444
    if-gez v4, :cond_2c

    .line 1445
    .line 1446
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1447
    .line 1448
    .line 1449
    move-result v4

    .line 1450
    int-to-double v4, v4

    .line 1451
    add-double/2addr v2, v4

    .line 1452
    goto :goto_14

    .line 1453
    :cond_2b
    const-wide/16 v35, 0x0

    .line 1454
    .line 1455
    int-to-double v2, v3

    .line 1456
    :cond_2c
    :goto_14
    cmpg-double v4, v2, v35

    .line 1457
    .line 1458
    if-gez v4, :cond_2d

    .line 1459
    .line 1460
    new-instance v1, Lcom/google/android/gms/internal/measurement/h;

    .line 1461
    .line 1462
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1463
    .line 1464
    .line 1465
    return-object v1

    .line 1466
    :cond_2d
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1467
    .line 1468
    .line 1469
    move-result v4

    .line 1470
    int-to-double v4, v4

    .line 1471
    invoke-static {v4, v5, v2, v3}, Ljava/lang/Math;->min(DD)D

    .line 1472
    .line 1473
    .line 1474
    move-result-wide v2

    .line 1475
    double-to-int v2, v2

    .line 1476
    :goto_15
    if-ltz v2, :cond_2f

    .line 1477
    .line 1478
    invoke-virtual {v7, v2}, Lcom/google/android/gms/internal/measurement/e;->w(I)Z

    .line 1479
    .line 1480
    .line 1481
    move-result v3

    .line 1482
    if-eqz v3, :cond_2e

    .line 1483
    .line 1484
    invoke-virtual {v7, v2}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1485
    .line 1486
    .line 1487
    move-result-object v3

    .line 1488
    invoke-static {v3, v1}, Ljp/wd;->g(Lcom/google/android/gms/internal/measurement/o;Lcom/google/android/gms/internal/measurement/o;)Z

    .line 1489
    .line 1490
    .line 1491
    move-result v3

    .line 1492
    if-eqz v3, :cond_2e

    .line 1493
    .line 1494
    int-to-double v0, v2

    .line 1495
    new-instance v2, Lcom/google/android/gms/internal/measurement/h;

    .line 1496
    .line 1497
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1498
    .line 1499
    .line 1500
    move-result-object v0

    .line 1501
    invoke-direct {v2, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1502
    .line 1503
    .line 1504
    return-object v2

    .line 1505
    :cond_2e
    add-int/lit8 v2, v2, -0x1

    .line 1506
    .line 1507
    goto :goto_15

    .line 1508
    :cond_2f
    new-instance v1, Lcom/google/android/gms/internal/measurement/h;

    .line 1509
    .line 1510
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1511
    .line 1512
    .line 1513
    return-object v1

    .line 1514
    :sswitch_e
    move-object/from16 v0, v18

    .line 1515
    .line 1516
    move-object/from16 v4, v34

    .line 1517
    .line 1518
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1519
    .line 1520
    .line 1521
    move-result v1

    .line 1522
    if-eqz v1, :cond_44

    .line 1523
    .line 1524
    const/4 v5, 0x1

    .line 1525
    invoke-static {v5, v0, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1526
    .line 1527
    .line 1528
    const/4 v1, 0x0

    .line 1529
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1530
    .line 1531
    .line 1532
    move-result-object v0

    .line 1533
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1534
    .line 1535
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1536
    .line 1537
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1538
    .line 1539
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1540
    .line 1541
    .line 1542
    move-result-object v0

    .line 1543
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/n;

    .line 1544
    .line 1545
    if-eqz v1, :cond_31

    .line 1546
    .line 1547
    invoke-virtual/range {v32 .. v32}, Ljava/util/TreeMap;->size()I

    .line 1548
    .line 1549
    .line 1550
    move-result v1

    .line 1551
    if-nez v1, :cond_30

    .line 1552
    .line 1553
    :goto_16
    return-object v31

    .line 1554
    :cond_30
    check-cast v0, Lcom/google/android/gms/internal/measurement/n;

    .line 1555
    .line 1556
    invoke-static {v7, v2, v0, v3, v3}, Ljp/td;->c(Lcom/google/android/gms/internal/measurement/e;Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/n;Ljava/lang/Boolean;Ljava/lang/Boolean;)Lcom/google/android/gms/internal/measurement/e;

    .line 1557
    .line 1558
    .line 1559
    return-object v31

    .line 1560
    :cond_31
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1561
    .line 1562
    invoke-direct {v0, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1563
    .line 1564
    .line 1565
    throw v0

    .line 1566
    :sswitch_f
    move-object/from16 v0, v20

    .line 1567
    .line 1568
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1569
    .line 1570
    .line 1571
    move-result v0

    .line 1572
    if-eqz v0, :cond_44

    .line 1573
    .line 1574
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1575
    .line 1576
    .line 1577
    move-result v0

    .line 1578
    if-eqz v0, :cond_32

    .line 1579
    .line 1580
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 1581
    .line 1582
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 1583
    .line 1584
    .line 1585
    return-object v0

    .line 1586
    :cond_32
    const/4 v1, 0x0

    .line 1587
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v0

    .line 1591
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1592
    .line 1593
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1594
    .line 1595
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1596
    .line 1597
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1598
    .line 1599
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 1600
    .line 1601
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v0

    .line 1605
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1606
    .line 1607
    .line 1608
    move-result-object v0

    .line 1609
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 1610
    .line 1611
    .line 1612
    move-result-wide v0

    .line 1613
    invoke-static {v0, v1}, Ljp/wd;->i(D)D

    .line 1614
    .line 1615
    .line 1616
    move-result-wide v0

    .line 1617
    double-to-int v0, v0

    .line 1618
    if-gez v0, :cond_33

    .line 1619
    .line 1620
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1621
    .line 1622
    .line 1623
    move-result v1

    .line 1624
    add-int/2addr v1, v0

    .line 1625
    const/4 v0, 0x0

    .line 1626
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 1627
    .line 1628
    .line 1629
    move-result v1

    .line 1630
    move v0, v1

    .line 1631
    goto :goto_17

    .line 1632
    :cond_33
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1633
    .line 1634
    .line 1635
    move-result v1

    .line 1636
    if-le v0, v1, :cond_34

    .line 1637
    .line 1638
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1639
    .line 1640
    .line 1641
    move-result v0

    .line 1642
    :cond_34
    :goto_17
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1643
    .line 1644
    .line 1645
    move-result v1

    .line 1646
    new-instance v5, Lcom/google/android/gms/internal/measurement/e;

    .line 1647
    .line 1648
    invoke-direct {v5}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 1649
    .line 1650
    .line 1651
    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    .line 1652
    .line 1653
    .line 1654
    move-result v6

    .line 1655
    const/4 v8, 0x1

    .line 1656
    if-le v6, v8, :cond_3b

    .line 1657
    .line 1658
    invoke-virtual {v15, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1659
    .line 1660
    .line 1661
    move-result-object v3

    .line 1662
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 1663
    .line 1664
    invoke-virtual {v4, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1665
    .line 1666
    .line 1667
    move-result-object v3

    .line 1668
    invoke-interface {v3}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1669
    .line 1670
    .line 1671
    move-result-object v3

    .line 1672
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 1673
    .line 1674
    .line 1675
    move-result-wide v8

    .line 1676
    invoke-static {v8, v9}, Ljp/wd;->i(D)D

    .line 1677
    .line 1678
    .line 1679
    move-result-wide v8

    .line 1680
    double-to-int v3, v8

    .line 1681
    const/4 v6, 0x0

    .line 1682
    invoke-static {v6, v3}, Ljava/lang/Math;->max(II)I

    .line 1683
    .line 1684
    .line 1685
    move-result v3

    .line 1686
    if-lez v3, :cond_35

    .line 1687
    .line 1688
    move v6, v0

    .line 1689
    :goto_18
    add-int v8, v0, v3

    .line 1690
    .line 1691
    invoke-static {v1, v8}, Ljava/lang/Math;->min(II)I

    .line 1692
    .line 1693
    .line 1694
    move-result v8

    .line 1695
    if-ge v6, v8, :cond_35

    .line 1696
    .line 1697
    invoke-virtual {v7, v0}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1698
    .line 1699
    .line 1700
    move-result-object v8

    .line 1701
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1702
    .line 1703
    .line 1704
    move-result v9

    .line 1705
    invoke-virtual {v5, v9, v8}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1706
    .line 1707
    .line 1708
    invoke-virtual {v7, v0}, Lcom/google/android/gms/internal/measurement/e;->x(I)V

    .line 1709
    .line 1710
    .line 1711
    add-int/lit8 v6, v6, 0x1

    .line 1712
    .line 1713
    goto :goto_18

    .line 1714
    :cond_35
    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    .line 1715
    .line 1716
    .line 1717
    move-result v1

    .line 1718
    const/4 v6, 0x2

    .line 1719
    if-le v1, v6, :cond_3c

    .line 1720
    .line 1721
    :goto_19
    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    .line 1722
    .line 1723
    .line 1724
    move-result v1

    .line 1725
    if-ge v6, v1, :cond_3c

    .line 1726
    .line 1727
    invoke-virtual {v15, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1728
    .line 1729
    .line 1730
    move-result-object v1

    .line 1731
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 1732
    .line 1733
    invoke-virtual {v4, v2, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1734
    .line 1735
    .line 1736
    move-result-object v1

    .line 1737
    instance-of v3, v1, Lcom/google/android/gms/internal/measurement/g;

    .line 1738
    .line 1739
    if-nez v3, :cond_3a

    .line 1740
    .line 1741
    add-int v3, v0, v6

    .line 1742
    .line 1743
    add-int/lit8 v3, v3, -0x2

    .line 1744
    .line 1745
    if-ltz v3, :cond_39

    .line 1746
    .line 1747
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1748
    .line 1749
    .line 1750
    move-result v8

    .line 1751
    if-lt v3, v8, :cond_36

    .line 1752
    .line 1753
    invoke-virtual {v7, v3, v1}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1754
    .line 1755
    .line 1756
    move-object/from16 v10, v32

    .line 1757
    .line 1758
    goto :goto_1b

    .line 1759
    :cond_36
    invoke-virtual/range {v32 .. v32}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 1760
    .line 1761
    .line 1762
    move-result-object v8

    .line 1763
    check-cast v8, Ljava/lang/Integer;

    .line 1764
    .line 1765
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 1766
    .line 1767
    .line 1768
    move-result v8

    .line 1769
    :goto_1a
    if-lt v8, v3, :cond_38

    .line 1770
    .line 1771
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1772
    .line 1773
    .line 1774
    move-result-object v9

    .line 1775
    move-object/from16 v10, v32

    .line 1776
    .line 1777
    invoke-virtual {v10, v9}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1778
    .line 1779
    .line 1780
    move-result-object v11

    .line 1781
    check-cast v11, Lcom/google/android/gms/internal/measurement/o;

    .line 1782
    .line 1783
    if-eqz v11, :cond_37

    .line 1784
    .line 1785
    add-int/lit8 v12, v8, 0x1

    .line 1786
    .line 1787
    invoke-virtual {v7, v12, v11}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1788
    .line 1789
    .line 1790
    invoke-virtual {v10, v9}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1791
    .line 1792
    .line 1793
    :cond_37
    add-int/lit8 v8, v8, -0x1

    .line 1794
    .line 1795
    move-object/from16 v32, v10

    .line 1796
    .line 1797
    goto :goto_1a

    .line 1798
    :cond_38
    move-object/from16 v10, v32

    .line 1799
    .line 1800
    invoke-virtual {v7, v3, v1}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1801
    .line 1802
    .line 1803
    :goto_1b
    add-int/lit8 v6, v6, 0x1

    .line 1804
    .line 1805
    move-object/from16 v32, v10

    .line 1806
    .line 1807
    goto :goto_19

    .line 1808
    :cond_39
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1809
    .line 1810
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 1811
    .line 1812
    .line 1813
    move-result-object v1

    .line 1814
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 1815
    .line 1816
    .line 1817
    move-result v1

    .line 1818
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1819
    .line 1820
    add-int/lit8 v1, v1, 0x15

    .line 1821
    .line 1822
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 1823
    .line 1824
    .line 1825
    const-string v1, "Invalid value index: "

    .line 1826
    .line 1827
    invoke-static {v3, v1, v2}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 1828
    .line 1829
    .line 1830
    move-result-object v1

    .line 1831
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1832
    .line 1833
    .line 1834
    throw v0

    .line 1835
    :cond_3a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1836
    .line 1837
    const-string v1, "Failed to parse elements to add"

    .line 1838
    .line 1839
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1840
    .line 1841
    .line 1842
    throw v0

    .line 1843
    :cond_3b
    :goto_1c
    if-ge v0, v1, :cond_3c

    .line 1844
    .line 1845
    invoke-virtual {v7, v0}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1846
    .line 1847
    .line 1848
    move-result-object v2

    .line 1849
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1850
    .line 1851
    .line 1852
    move-result v4

    .line 1853
    invoke-virtual {v5, v4, v2}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1854
    .line 1855
    .line 1856
    invoke-virtual {v7, v0, v3}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1857
    .line 1858
    .line 1859
    add-int/lit8 v0, v0, 0x1

    .line 1860
    .line 1861
    goto :goto_1c

    .line 1862
    :cond_3c
    return-object v5

    .line 1863
    :sswitch_10
    move-object/from16 v0, v21

    .line 1864
    .line 1865
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1866
    .line 1867
    .line 1868
    move-result v0

    .line 1869
    if-eqz v0, :cond_44

    .line 1870
    .line 1871
    const/4 v5, 0x1

    .line 1872
    invoke-static {v7, v2, v15, v5}, Ljp/td;->b(Lcom/google/android/gms/internal/measurement/e;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;Z)Lcom/google/android/gms/internal/measurement/o;

    .line 1873
    .line 1874
    .line 1875
    move-result-object v0

    .line 1876
    return-object v0

    .line 1877
    :sswitch_11
    move-object/from16 v0, v16

    .line 1878
    .line 1879
    move-object/from16 v10, v32

    .line 1880
    .line 1881
    move-object/from16 v4, v34

    .line 1882
    .line 1883
    const/4 v5, 0x1

    .line 1884
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1885
    .line 1886
    .line 1887
    move-result v1

    .line 1888
    if-eqz v1, :cond_44

    .line 1889
    .line 1890
    invoke-static {v5, v0, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1891
    .line 1892
    .line 1893
    const/4 v1, 0x0

    .line 1894
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1895
    .line 1896
    .line 1897
    move-result-object v0

    .line 1898
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1899
    .line 1900
    iget-object v1, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1901
    .line 1902
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1903
    .line 1904
    invoke-virtual {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1905
    .line 1906
    .line 1907
    move-result-object v0

    .line 1908
    instance-of v1, v0, Lcom/google/android/gms/internal/measurement/n;

    .line 1909
    .line 1910
    if-eqz v1, :cond_3f

    .line 1911
    .line 1912
    invoke-virtual {v10}, Ljava/util/TreeMap;->size()I

    .line 1913
    .line 1914
    .line 1915
    move-result v1

    .line 1916
    if-nez v1, :cond_3d

    .line 1917
    .line 1918
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 1919
    .line 1920
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 1921
    .line 1922
    .line 1923
    return-object v0

    .line 1924
    :cond_3d
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->p()Lcom/google/android/gms/internal/measurement/o;

    .line 1925
    .line 1926
    .line 1927
    move-result-object v1

    .line 1928
    check-cast v1, Lcom/google/android/gms/internal/measurement/e;

    .line 1929
    .line 1930
    check-cast v0, Lcom/google/android/gms/internal/measurement/n;

    .line 1931
    .line 1932
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1933
    .line 1934
    invoke-static {v7, v2, v0, v3, v4}, Ljp/td;->c(Lcom/google/android/gms/internal/measurement/e;Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/n;Ljava/lang/Boolean;Ljava/lang/Boolean;)Lcom/google/android/gms/internal/measurement/e;

    .line 1935
    .line 1936
    .line 1937
    move-result-object v0

    .line 1938
    new-instance v2, Lcom/google/android/gms/internal/measurement/e;

    .line 1939
    .line 1940
    invoke-direct {v2}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 1941
    .line 1942
    .line 1943
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 1944
    .line 1945
    .line 1946
    move-result-object v0

    .line 1947
    :goto_1d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1948
    .line 1949
    .line 1950
    move-result v3

    .line 1951
    if-eqz v3, :cond_3e

    .line 1952
    .line 1953
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1954
    .line 1955
    .line 1956
    move-result-object v3

    .line 1957
    check-cast v3, Ljava/lang/Integer;

    .line 1958
    .line 1959
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1960
    .line 1961
    .line 1962
    move-result v3

    .line 1963
    invoke-virtual {v1, v3}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 1964
    .line 1965
    .line 1966
    move-result-object v3

    .line 1967
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 1968
    .line 1969
    .line 1970
    move-result v4

    .line 1971
    invoke-virtual {v2, v4, v3}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 1972
    .line 1973
    .line 1974
    goto :goto_1d

    .line 1975
    :cond_3e
    return-object v2

    .line 1976
    :cond_3f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1977
    .line 1978
    invoke-direct {v0, v4}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1979
    .line 1980
    .line 1981
    throw v0

    .line 1982
    :sswitch_12
    move-object/from16 v0, v17

    .line 1983
    .line 1984
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1985
    .line 1986
    .line 1987
    move-result v0

    .line 1988
    if-eqz v0, :cond_44

    .line 1989
    .line 1990
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e;->p()Lcom/google/android/gms/internal/measurement/o;

    .line 1991
    .line 1992
    .line 1993
    move-result-object v0

    .line 1994
    check-cast v0, Lcom/google/android/gms/internal/measurement/e;

    .line 1995
    .line 1996
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1997
    .line 1998
    .line 1999
    move-result v1

    .line 2000
    if-nez v1, :cond_43

    .line 2001
    .line 2002
    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2003
    .line 2004
    .line 2005
    move-result-object v1

    .line 2006
    :cond_40
    :goto_1e
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 2007
    .line 2008
    .line 2009
    move-result v3

    .line 2010
    if-eqz v3, :cond_43

    .line 2011
    .line 2012
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2013
    .line 2014
    .line 2015
    move-result-object v3

    .line 2016
    check-cast v3, Lcom/google/android/gms/internal/measurement/o;

    .line 2017
    .line 2018
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2019
    .line 2020
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 2021
    .line 2022
    invoke-virtual {v4, v2, v3}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 2023
    .line 2024
    .line 2025
    move-result-object v3

    .line 2026
    instance-of v4, v3, Lcom/google/android/gms/internal/measurement/g;

    .line 2027
    .line 2028
    if-nez v4, :cond_42

    .line 2029
    .line 2030
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 2031
    .line 2032
    .line 2033
    move-result v4

    .line 2034
    instance-of v5, v3, Lcom/google/android/gms/internal/measurement/e;

    .line 2035
    .line 2036
    if-eqz v5, :cond_41

    .line 2037
    .line 2038
    check-cast v3, Lcom/google/android/gms/internal/measurement/e;

    .line 2039
    .line 2040
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 2041
    .line 2042
    .line 2043
    move-result-object v5

    .line 2044
    :goto_1f
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 2045
    .line 2046
    .line 2047
    move-result v6

    .line 2048
    if-eqz v6, :cond_40

    .line 2049
    .line 2050
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2051
    .line 2052
    .line 2053
    move-result-object v6

    .line 2054
    check-cast v6, Ljava/lang/Integer;

    .line 2055
    .line 2056
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 2057
    .line 2058
    .line 2059
    move-result v7

    .line 2060
    add-int/2addr v7, v4

    .line 2061
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 2062
    .line 2063
    .line 2064
    move-result v6

    .line 2065
    invoke-virtual {v3, v6}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 2066
    .line 2067
    .line 2068
    move-result-object v6

    .line 2069
    invoke-virtual {v0, v7, v6}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 2070
    .line 2071
    .line 2072
    goto :goto_1f

    .line 2073
    :cond_41
    invoke-virtual {v0, v4, v3}, Lcom/google/android/gms/internal/measurement/e;->v(ILcom/google/android/gms/internal/measurement/o;)V

    .line 2074
    .line 2075
    .line 2076
    goto :goto_1e

    .line 2077
    :cond_42
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2078
    .line 2079
    const-string v1, "Failed evaluation of arguments"

    .line 2080
    .line 2081
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2082
    .line 2083
    .line 2084
    throw v0

    .line 2085
    :cond_43
    return-object v0

    .line 2086
    :sswitch_13
    move-object/from16 v0, v19

    .line 2087
    .line 2088
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2089
    .line 2090
    .line 2091
    move-result v1

    .line 2092
    if-eqz v1, :cond_44

    .line 2093
    .line 2094
    const/4 v1, 0x0

    .line 2095
    invoke-static {v1, v0, v15}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 2096
    .line 2097
    .line 2098
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 2099
    .line 2100
    move-object/from16 v1, v30

    .line 2101
    .line 2102
    invoke-virtual {v7, v1}, Lcom/google/android/gms/internal/measurement/e;->y(Ljava/lang/String;)Ljava/lang/String;

    .line 2103
    .line 2104
    .line 2105
    move-result-object v1

    .line 2106
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 2107
    .line 2108
    .line 2109
    return-object v0

    .line 2110
    :cond_44
    :goto_20
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2111
    .line 2112
    const-string v1, "Command not supported"

    .line 2113
    .line 2114
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2115
    .line 2116
    .line 2117
    throw v0

    .line 2118
    nop

    .line 2119
    :sswitch_data_0
    .sparse-switch
        -0x69e9ad94 -> :sswitch_13
        -0x50c088ec -> :sswitch_12
        -0x4bf73488 -> :sswitch_11
        -0x37b90a9a -> :sswitch_10
        -0x3565b984 -> :sswitch_f
        -0x28732996 -> :sswitch_e
        -0x1bdda92d -> :sswitch_d
        -0x108c6a77 -> :sswitch_c
        0x1a55c -> :sswitch_b
        0x1b251 -> :sswitch_a
        0x31dd2a -> :sswitch_9
        0x34af1a -> :sswitch_8
        0x35f4f4 -> :sswitch_7
        0x35f59e -> :sswitch_6
        0x5c6731b -> :sswitch_5
        0x6856c82 -> :sswitch_4
        0x6873d92 -> :sswitch_3
        0x398d4c56 -> :sswitch_2
        0x418e52e2 -> :sswitch_1
        0x73d44649 -> :sswitch_0
    .end sparse-switch
.end method

.method public final p()Lcom/google/android/gms/internal/measurement/o;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Ljava/util/Map$Entry;

    .line 27
    .line 28
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    instance-of v2, v2, Lcom/google/android/gms/internal/measurement/k;

    .line 33
    .line 34
    iget-object v3, v0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 35
    .line 36
    if-eqz v2, :cond_0

    .line 37
    .line 38
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 49
    .line 50
    invoke-virtual {v3, v2, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 65
    .line 66
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->p()Lcom/google/android/gms/internal/measurement/o;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-virtual {v3, v2, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    return-object v0
.end method

.method public final r()Ljava/util/List;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-ge v1, v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-object v0
.end method

.method public final s()Ljava/util/Iterator;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/TreeMap;->keySet()Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final t()I
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    invoke-virtual {p0}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Integer;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    add-int/lit8 p0, p0, 0x1

    .line 22
    .line 23
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, ","

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/e;->y(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final u(I)Lcom/google/android/gms/internal/measurement/o;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ge p1, v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/e;->w(I)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 14
    .line 15
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lcom/google/android/gms/internal/measurement/o;

    .line 24
    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 32
    .line 33
    const-string p1, "Attempting to get element outside of current array"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public final v(ILcom/google/android/gms/internal/measurement/o;)V
    .locals 1

    .line 1
    const/16 v0, 0x7ed4

    .line 2
    .line 3
    if-gt p1, v0, :cond_2

    .line 4
    .line 5
    if-ltz p1, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 8
    .line 9
    if-nez p2, :cond_0

    .line 10
    .line 11
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1, p2}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 28
    .line 29
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    new-instance v0, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    add-int/lit8 p2, p2, 0x15

    .line 40
    .line 41
    invoke-direct {v0, p2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 42
    .line 43
    .line 44
    const-string p2, "Out of bounds index: "

    .line 45
    .line 46
    invoke-static {p1, p2, v0}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string p1, "Array too large"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0
.end method

.method public final w(I)Z
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-gt p1, v0, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 27
    .line 28
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    new-instance v1, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    add-int/lit8 v0, v0, 0x15

    .line 39
    .line 40
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 41
    .line 42
    .line 43
    const-string v0, "Out of bounds index: "

    .line 44
    .line 45
    invoke-static {p1, v0, v1}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0
.end method

.method public final x(I)V
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-gt p1, v0, :cond_2

    .line 14
    .line 15
    if-gez p1, :cond_0

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p0, v1}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    if-ne p1, v0, :cond_1

    .line 26
    .line 27
    add-int/lit8 p1, p1, -0x1

    .line 28
    .line 29
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {p0, v0}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-nez v1, :cond_2

    .line 38
    .line 39
    if-ltz p1, :cond_2

    .line 40
    .line 41
    sget-object p1, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 42
    .line 43
    invoke-virtual {p0, v0, p1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    :goto_0
    add-int/lit8 p1, p1, 0x1

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/util/TreeMap;->lastKey()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, Ljava/lang/Integer;

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-gt p1, v0, :cond_2

    .line 60
    .line 61
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-virtual {p0, v0}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 70
    .line 71
    if-eqz v1, :cond_1

    .line 72
    .line 73
    add-int/lit8 v2, p1, -0x1

    .line 74
    .line 75
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-virtual {p0, v2, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, v0}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_2
    :goto_1
    return-void
.end method

.method public final y(Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/e;->d:Ljava/util/TreeMap;

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-nez v1, :cond_3

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    move v2, v1

    .line 16
    :goto_0
    if-nez p1, :cond_0

    .line 17
    .line 18
    const-string v3, ""

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    move-object v3, p1

    .line 22
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e;->t()I

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-ge v2, v4, :cond_2

    .line 27
    .line 28
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    instance-of v3, v4, Lcom/google/android/gms/internal/measurement/s;

    .line 36
    .line 37
    if-nez v3, :cond_1

    .line 38
    .line 39
    instance-of v3, v4, Lcom/google/android/gms/internal/measurement/m;

    .line 40
    .line 41
    if-nez v3, :cond_1

    .line 42
    .line 43
    invoke-interface {v4}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-virtual {v0, v1, p0}, Ljava/lang/StringBuilder;->delete(II)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    :cond_3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0
.end method
