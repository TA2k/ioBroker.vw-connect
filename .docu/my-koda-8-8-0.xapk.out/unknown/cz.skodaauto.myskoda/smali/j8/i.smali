.class public final Lj8/i;
.super Lt7/u0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final D:Lj8/i;


# instance fields
.field public final A:Z

.field public final B:Landroid/util/SparseArray;

.field public final C:Landroid/util/SparseBooleanArray;

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z

.field public final z:Z


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lj8/h;

    .line 2
    .line 3
    invoke-direct {v0}, Lj8/h;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lj8/i;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Lj8/i;-><init>(Lj8/h;)V

    .line 9
    .line 10
    .line 11
    sput-object v1, Lj8/i;->D:Lj8/i;

    .line 12
    .line 13
    const/16 v0, 0x3eb

    .line 14
    .line 15
    const/16 v1, 0x3ec

    .line 16
    .line 17
    const/16 v2, 0x3e8

    .line 18
    .line 19
    const/16 v3, 0x3e9

    .line 20
    .line 21
    const/16 v4, 0x3ea

    .line 22
    .line 23
    invoke-static {v2, v3, v4, v0, v1}, Lp3/m;->w(IIIII)V

    .line 24
    .line 25
    .line 26
    const/16 v0, 0x3f0

    .line 27
    .line 28
    const/16 v1, 0x3f1

    .line 29
    .line 30
    const/16 v2, 0x3ed

    .line 31
    .line 32
    const/16 v3, 0x3ee

    .line 33
    .line 34
    const/16 v4, 0x3ef

    .line 35
    .line 36
    invoke-static {v2, v3, v4, v0, v1}, Lp3/m;->w(IIIII)V

    .line 37
    .line 38
    .line 39
    const/16 v0, 0x3f5

    .line 40
    .line 41
    const/16 v1, 0x3f6

    .line 42
    .line 43
    const/16 v2, 0x3f2

    .line 44
    .line 45
    const/16 v3, 0x3f3

    .line 46
    .line 47
    const/16 v4, 0x3f4

    .line 48
    .line 49
    invoke-static {v2, v3, v4, v0, v1}, Lp3/m;->w(IIIII)V

    .line 50
    .line 51
    .line 52
    const/16 v0, 0x3f7

    .line 53
    .line 54
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 55
    .line 56
    .line 57
    const/16 v0, 0x3f8

    .line 58
    .line 59
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 60
    .line 61
    .line 62
    const/16 v0, 0x3f9

    .line 63
    .line 64
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 65
    .line 66
    .line 67
    const/16 v0, 0x3fa

    .line 68
    .line 69
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public constructor <init>(Lj8/h;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lt7/u0;-><init>(Lt7/t0;)V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p1, Lj8/h;->u:Z

    .line 5
    .line 6
    iput-boolean v0, p0, Lj8/i;->u:Z

    .line 7
    .line 8
    iget-boolean v0, p1, Lj8/h;->v:Z

    .line 9
    .line 10
    iput-boolean v0, p0, Lj8/i;->v:Z

    .line 11
    .line 12
    iget-boolean v0, p1, Lj8/h;->w:Z

    .line 13
    .line 14
    iput-boolean v0, p0, Lj8/i;->w:Z

    .line 15
    .line 16
    iget-boolean v0, p1, Lj8/h;->x:Z

    .line 17
    .line 18
    iput-boolean v0, p0, Lj8/i;->x:Z

    .line 19
    .line 20
    iget-boolean v0, p1, Lj8/h;->y:Z

    .line 21
    .line 22
    iput-boolean v0, p0, Lj8/i;->y:Z

    .line 23
    .line 24
    iget-boolean v0, p1, Lj8/h;->z:Z

    .line 25
    .line 26
    iput-boolean v0, p0, Lj8/i;->z:Z

    .line 27
    .line 28
    iget-boolean v0, p1, Lj8/h;->A:Z

    .line 29
    .line 30
    iput-boolean v0, p0, Lj8/i;->A:Z

    .line 31
    .line 32
    iget-object v0, p1, Lj8/h;->B:Landroid/util/SparseArray;

    .line 33
    .line 34
    iput-object v0, p0, Lj8/i;->B:Landroid/util/SparseArray;

    .line 35
    .line 36
    iget-object p1, p1, Lj8/h;->C:Landroid/util/SparseBooleanArray;

    .line 37
    .line 38
    iput-object p1, p0, Lj8/i;->C:Landroid/util/SparseBooleanArray;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final a()Lt7/t0;
    .locals 1

    .line 1
    new-instance v0, Lj8/h;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lj8/h;-><init>(Lj8/i;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 8

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_2

    .line 4
    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    if-eqz p1, :cond_a

    .line 7
    .line 8
    const-class v1, Lj8/i;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-eq v1, v2, :cond_1

    .line 15
    .line 16
    goto/16 :goto_3

    .line 17
    .line 18
    :cond_1
    check-cast p1, Lj8/i;

    .line 19
    .line 20
    invoke-super {p0, p1}, Lt7/u0;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_a

    .line 25
    .line 26
    iget-boolean v1, p0, Lj8/i;->u:Z

    .line 27
    .line 28
    iget-boolean v2, p1, Lj8/i;->u:Z

    .line 29
    .line 30
    if-ne v1, v2, :cond_a

    .line 31
    .line 32
    iget-boolean v1, p0, Lj8/i;->v:Z

    .line 33
    .line 34
    iget-boolean v2, p1, Lj8/i;->v:Z

    .line 35
    .line 36
    if-ne v1, v2, :cond_a

    .line 37
    .line 38
    iget-boolean v1, p0, Lj8/i;->w:Z

    .line 39
    .line 40
    iget-boolean v2, p1, Lj8/i;->w:Z

    .line 41
    .line 42
    if-ne v1, v2, :cond_a

    .line 43
    .line 44
    iget-boolean v1, p0, Lj8/i;->x:Z

    .line 45
    .line 46
    iget-boolean v2, p1, Lj8/i;->x:Z

    .line 47
    .line 48
    if-ne v1, v2, :cond_a

    .line 49
    .line 50
    iget-boolean v1, p0, Lj8/i;->y:Z

    .line 51
    .line 52
    iget-boolean v2, p1, Lj8/i;->y:Z

    .line 53
    .line 54
    if-ne v1, v2, :cond_a

    .line 55
    .line 56
    iget-boolean v1, p0, Lj8/i;->z:Z

    .line 57
    .line 58
    iget-boolean v2, p1, Lj8/i;->z:Z

    .line 59
    .line 60
    if-ne v1, v2, :cond_a

    .line 61
    .line 62
    iget-boolean v1, p0, Lj8/i;->A:Z

    .line 63
    .line 64
    iget-boolean v2, p1, Lj8/i;->A:Z

    .line 65
    .line 66
    if-ne v1, v2, :cond_a

    .line 67
    .line 68
    iget-object v1, p1, Lj8/i;->C:Landroid/util/SparseBooleanArray;

    .line 69
    .line 70
    iget-object v2, p0, Lj8/i;->C:Landroid/util/SparseBooleanArray;

    .line 71
    .line 72
    invoke-virtual {v2}, Landroid/util/SparseBooleanArray;->size()I

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    invoke-virtual {v1}, Landroid/util/SparseBooleanArray;->size()I

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eq v4, v3, :cond_2

    .line 81
    .line 82
    goto/16 :goto_3

    .line 83
    .line 84
    :cond_2
    move v4, v0

    .line 85
    :goto_0
    if-ge v4, v3, :cond_4

    .line 86
    .line 87
    invoke-virtual {v2, v4}, Landroid/util/SparseBooleanArray;->keyAt(I)I

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    invoke-virtual {v1, v5}, Landroid/util/SparseBooleanArray;->indexOfKey(I)I

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    if-gez v5, :cond_3

    .line 96
    .line 97
    goto/16 :goto_3

    .line 98
    .line 99
    :cond_3
    add-int/lit8 v4, v4, 0x1

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_4
    iget-object p1, p1, Lj8/i;->B:Landroid/util/SparseArray;

    .line 103
    .line 104
    iget-object p0, p0, Lj8/i;->B:Landroid/util/SparseArray;

    .line 105
    .line 106
    invoke-virtual {p0}, Landroid/util/SparseArray;->size()I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-eq v2, v1, :cond_5

    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_5
    move v2, v0

    .line 118
    :goto_1
    if-ge v2, v1, :cond_9

    .line 119
    .line 120
    invoke-virtual {p0, v2}, Landroid/util/SparseArray;->keyAt(I)I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    invoke-virtual {p1, v3}, Landroid/util/SparseArray;->indexOfKey(I)I

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    if-ltz v3, :cond_a

    .line 129
    .line 130
    invoke-virtual {p0, v2}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    check-cast v4, Ljava/util/Map;

    .line 135
    .line 136
    invoke-virtual {p1, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    check-cast v3, Ljava/util/Map;

    .line 141
    .line 142
    invoke-interface {v4}, Ljava/util/Map;->size()I

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    invoke-interface {v3}, Ljava/util/Map;->size()I

    .line 147
    .line 148
    .line 149
    move-result v6

    .line 150
    if-eq v6, v5, :cond_6

    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_6
    invoke-interface {v4}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    :cond_7
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 162
    .line 163
    .line 164
    move-result v5

    .line 165
    if-eqz v5, :cond_8

    .line 166
    .line 167
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    check-cast v5, Ljava/util/Map$Entry;

    .line 172
    .line 173
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v6

    .line 177
    check-cast v6, Lh8/e1;

    .line 178
    .line 179
    invoke-interface {v3, v6}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v7

    .line 183
    if-eqz v7, :cond_a

    .line 184
    .line 185
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    invoke-interface {v3, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v6

    .line 193
    invoke-static {v5, v6}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v5

    .line 197
    if-nez v5, :cond_7

    .line 198
    .line 199
    goto :goto_3

    .line 200
    :cond_8
    add-int/lit8 v2, v2, 0x1

    .line 201
    .line 202
    goto :goto_1

    .line 203
    :cond_9
    :goto_2
    const/4 p0, 0x1

    .line 204
    return p0

    .line 205
    :cond_a
    :goto_3
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    invoke-super {p0}, Lt7/u0;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x1f

    .line 6
    .line 7
    add-int/2addr v0, v1

    .line 8
    mul-int/2addr v0, v1

    .line 9
    iget-boolean v2, p0, Lj8/i;->u:Z

    .line 10
    .line 11
    add-int/2addr v0, v2

    .line 12
    mul-int/lit16 v0, v0, 0x3c1

    .line 13
    .line 14
    iget-boolean v2, p0, Lj8/i;->v:Z

    .line 15
    .line 16
    add-int/2addr v0, v2

    .line 17
    mul-int/lit16 v0, v0, 0x3c1

    .line 18
    .line 19
    iget-boolean v2, p0, Lj8/i;->w:Z

    .line 20
    .line 21
    add-int/2addr v0, v2

    .line 22
    const v2, 0x1b4d89f

    .line 23
    .line 24
    .line 25
    mul-int/2addr v0, v2

    .line 26
    iget-boolean v2, p0, Lj8/i;->x:Z

    .line 27
    .line 28
    add-int/2addr v0, v2

    .line 29
    mul-int/2addr v0, v1

    .line 30
    iget-boolean v2, p0, Lj8/i;->y:Z

    .line 31
    .line 32
    add-int/2addr v0, v2

    .line 33
    mul-int/2addr v0, v1

    .line 34
    iget-boolean v2, p0, Lj8/i;->z:Z

    .line 35
    .line 36
    add-int/2addr v0, v2

    .line 37
    mul-int/lit16 v0, v0, 0x3c1

    .line 38
    .line 39
    iget-boolean p0, p0, Lj8/i;->A:Z

    .line 40
    .line 41
    add-int/2addr v0, p0

    .line 42
    mul-int/2addr v0, v1

    .line 43
    return v0
.end method
