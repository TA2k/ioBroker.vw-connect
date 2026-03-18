.class public final Landroidx/collection/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lby0/f;
.implements Ljava/util/Set;
.implements Lby0/a;


# instance fields
.field public final d:Landroidx/collection/m0;

.field public final e:Landroidx/collection/m0;


# direct methods
.method public constructor <init>(Landroidx/collection/m0;)V
    .locals 1

    .line 1
    const-string v0, "parent"

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
    iput-object p1, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 10
    .line 11
    iput-object p1, p0, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final add(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/collection/m0;->a(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 12

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Iterable;

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget v0, p0, Landroidx/collection/m0;->g:I

    .line 14
    .line 15
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {p0, v1}, Landroidx/collection/m0;->d(Ljava/lang/Object;)I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    iget-object v3, p0, Landroidx/collection/m0;->b:[Ljava/lang/Object;

    .line 34
    .line 35
    aput-object v1, v3, v2

    .line 36
    .line 37
    iget-object v1, p0, Landroidx/collection/m0;->c:[J

    .line 38
    .line 39
    iget v3, p0, Landroidx/collection/m0;->d:I

    .line 40
    .line 41
    int-to-long v4, v3

    .line 42
    const-wide/32 v6, 0x7fffffff

    .line 43
    .line 44
    .line 45
    and-long/2addr v4, v6

    .line 46
    const-wide v8, 0x3fffffff80000000L    # 1.9999995231628418

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    or-long/2addr v4, v8

    .line 52
    aput-wide v4, v1, v2

    .line 53
    .line 54
    const v4, 0x7fffffff

    .line 55
    .line 56
    .line 57
    if-eq v3, v4, :cond_1

    .line 58
    .line 59
    aget-wide v8, v1, v3

    .line 60
    .line 61
    const-wide v10, -0x3fffffff80000001L    # -2.000000953674316

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr v8, v10

    .line 67
    int-to-long v10, v2

    .line 68
    and-long v5, v10, v6

    .line 69
    .line 70
    const/16 v7, 0x1f

    .line 71
    .line 72
    shl-long/2addr v5, v7

    .line 73
    or-long/2addr v5, v8

    .line 74
    aput-wide v5, v1, v3

    .line 75
    .line 76
    :cond_1
    iput v2, p0, Landroidx/collection/m0;->d:I

    .line 77
    .line 78
    iget v1, p0, Landroidx/collection/m0;->e:I

    .line 79
    .line 80
    if-ne v1, v4, :cond_0

    .line 81
    .line 82
    iput v2, p0, Landroidx/collection/m0;->e:I

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_2
    iget p0, p0, Landroidx/collection/m0;->g:I

    .line 86
    .line 87
    if-eq v0, p0, :cond_3

    .line 88
    .line 89
    const/4 p0, 0x1

    .line 90
    return p0

    .line 91
    :cond_3
    const/4 p0, 0x0

    .line 92
    return p0
.end method

.method public final clear()V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/collection/m0;->b()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/collection/m0;->c(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 2

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Iterable;

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iget-object v1, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 23
    .line 24
    invoke-virtual {v1, v0}, Landroidx/collection/m0;->c(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return p0

    .line 32
    :cond_1
    const/4 p0, 0x1

    .line 33
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    if-eqz p1, :cond_2

    .line 6
    .line 7
    const-class v0, Landroidx/collection/p0;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    check-cast p1, Landroidx/collection/p0;

    .line 17
    .line 18
    iget-object p0, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 19
    .line 20
    iget-object p1, p1, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 21
    .line 22
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 28
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/collection/m0;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 2
    .line 3
    iget p0, p0, Landroidx/collection/m0;->g:I

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Landroidx/collection/o0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Landroidx/collection/o0;-><init>(Landroidx/collection/p0;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/collection/m0;->g(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    const-string v1, "elements"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    check-cast v0, Ljava/lang/Iterable;

    .line 9
    .line 10
    move-object/from16 v1, p0

    .line 11
    .line 12
    iget-object v1, v1, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget v2, v1, Landroidx/collection/m0;->g:I

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    const/4 v4, 0x1

    .line 28
    const/4 v5, 0x0

    .line 29
    if-eqz v3, :cond_5

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move v6, v5

    .line 43
    :goto_1
    const v7, -0x3361d2af    # -8.2930312E7f

    .line 44
    .line 45
    .line 46
    mul-int/2addr v6, v7

    .line 47
    shl-int/lit8 v7, v6, 0x10

    .line 48
    .line 49
    xor-int/2addr v6, v7

    .line 50
    and-int/lit8 v7, v6, 0x7f

    .line 51
    .line 52
    iget v8, v1, Landroidx/collection/m0;->f:I

    .line 53
    .line 54
    ushr-int/lit8 v6, v6, 0x7

    .line 55
    .line 56
    and-int/2addr v6, v8

    .line 57
    :goto_2
    iget-object v9, v1, Landroidx/collection/m0;->a:[J

    .line 58
    .line 59
    shr-int/lit8 v10, v6, 0x3

    .line 60
    .line 61
    and-int/lit8 v11, v6, 0x7

    .line 62
    .line 63
    shl-int/lit8 v11, v11, 0x3

    .line 64
    .line 65
    aget-wide v12, v9, v10

    .line 66
    .line 67
    ushr-long/2addr v12, v11

    .line 68
    add-int/2addr v10, v4

    .line 69
    aget-wide v9, v9, v10

    .line 70
    .line 71
    rsub-int/lit8 v14, v11, 0x40

    .line 72
    .line 73
    shl-long/2addr v9, v14

    .line 74
    int-to-long v14, v11

    .line 75
    neg-long v14, v14

    .line 76
    const/16 v11, 0x3f

    .line 77
    .line 78
    shr-long/2addr v14, v11

    .line 79
    and-long/2addr v9, v14

    .line 80
    or-long/2addr v9, v12

    .line 81
    int-to-long v11, v7

    .line 82
    const-wide v13, 0x101010101010101L

    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    mul-long/2addr v11, v13

    .line 88
    xor-long/2addr v11, v9

    .line 89
    sub-long v13, v11, v13

    .line 90
    .line 91
    not-long v11, v11

    .line 92
    and-long/2addr v11, v13

    .line 93
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    and-long/2addr v11, v13

    .line 99
    :goto_3
    const-wide/16 v15, 0x0

    .line 100
    .line 101
    cmp-long v17, v11, v15

    .line 102
    .line 103
    if-eqz v17, :cond_3

    .line 104
    .line 105
    invoke-static {v11, v12}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 106
    .line 107
    .line 108
    move-result v15

    .line 109
    shr-int/lit8 v15, v15, 0x3

    .line 110
    .line 111
    add-int/2addr v15, v6

    .line 112
    and-int/2addr v15, v8

    .line 113
    move/from16 p0, v4

    .line 114
    .line 115
    iget-object v4, v1, Landroidx/collection/m0;->b:[Ljava/lang/Object;

    .line 116
    .line 117
    aget-object v4, v4, v15

    .line 118
    .line 119
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    if-eqz v4, :cond_2

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_2
    const-wide/16 v15, 0x1

    .line 127
    .line 128
    sub-long v15, v11, v15

    .line 129
    .line 130
    and-long/2addr v11, v15

    .line 131
    move/from16 v4, p0

    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_3
    move/from16 p0, v4

    .line 135
    .line 136
    not-long v11, v9

    .line 137
    const/4 v4, 0x6

    .line 138
    shl-long/2addr v11, v4

    .line 139
    and-long/2addr v9, v11

    .line 140
    and-long/2addr v9, v13

    .line 141
    cmp-long v4, v9, v15

    .line 142
    .line 143
    if-eqz v4, :cond_4

    .line 144
    .line 145
    const/4 v15, -0x1

    .line 146
    :goto_4
    if-ltz v15, :cond_0

    .line 147
    .line 148
    invoke-virtual {v1, v15}, Landroidx/collection/m0;->h(I)V

    .line 149
    .line 150
    .line 151
    goto/16 :goto_0

    .line 152
    .line 153
    :cond_4
    add-int/lit8 v5, v5, 0x8

    .line 154
    .line 155
    add-int/2addr v6, v5

    .line 156
    and-int/2addr v6, v8

    .line 157
    move/from16 v4, p0

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_5
    move/from16 p0, v4

    .line 161
    .line 162
    iget v0, v1, Landroidx/collection/m0;->g:I

    .line 163
    .line 164
    if-eq v2, v0, :cond_6

    .line 165
    .line 166
    return p0

    .line 167
    :cond_6
    return v5
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Landroidx/collection/m0;->i(Ljava/util/Collection;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 2
    .line 3
    iget p0, p0, Landroidx/collection/m0;->g:I

    .line 4
    .line 5
    return p0
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/l;->a(Ljava/util/Collection;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 1

    .line 2
    const-string v0, "array"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Lkotlin/jvm/internal/l;->b(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/p0;->d:Landroidx/collection/m0;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/collection/m0;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
