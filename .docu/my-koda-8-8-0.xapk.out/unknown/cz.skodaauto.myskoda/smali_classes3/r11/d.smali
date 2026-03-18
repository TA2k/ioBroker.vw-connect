.class public final Lr11/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:[Lr11/y;

.field public final e:[Lr11/w;

.field public final f:I

.field public final g:I


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, v2, :cond_4

    .line 21
    .line 22
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    instance-of v6, v5, Lr11/d;

    .line 27
    .line 28
    if-eqz v6, :cond_0

    .line 29
    .line 30
    check-cast v5, Lr11/d;

    .line 31
    .line 32
    iget-object v5, v5, Lr11/d;->d:[Lr11/y;

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    move v6, v3

    .line 37
    :goto_1
    array-length v7, v5

    .line 38
    if-ge v6, v7, :cond_1

    .line 39
    .line 40
    aget-object v7, v5, v6

    .line 41
    .line 42
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    add-int/lit8 v6, v6, 0x1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_0
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    :cond_1
    add-int/lit8 v5, v4, 0x1

    .line 52
    .line 53
    invoke-virtual {p1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    instance-of v6, v5, Lr11/d;

    .line 58
    .line 59
    if-eqz v6, :cond_2

    .line 60
    .line 61
    check-cast v5, Lr11/d;

    .line 62
    .line 63
    iget-object v5, v5, Lr11/d;->e:[Lr11/w;

    .line 64
    .line 65
    if-eqz v5, :cond_3

    .line 66
    .line 67
    move v6, v3

    .line 68
    :goto_2
    array-length v7, v5

    .line 69
    if-ge v6, v7, :cond_3

    .line 70
    .line 71
    aget-object v7, v5, v6

    .line 72
    .line 73
    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    add-int/lit8 v6, v6, 0x1

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_2
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    :cond_3
    add-int/lit8 v4, v4, 0x2

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_4
    const/4 p1, 0x0

    .line 86
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-nez v2, :cond_7

    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    if-eqz v2, :cond_5

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    new-array v4, v2, [Lr11/y;

    .line 104
    .line 105
    iput-object v4, p0, Lr11/d;->d:[Lr11/y;

    .line 106
    .line 107
    move v4, v3

    .line 108
    move v5, v4

    .line 109
    :goto_3
    if-ge v4, v2, :cond_6

    .line 110
    .line 111
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    check-cast v6, Lr11/y;

    .line 116
    .line 117
    invoke-interface {v6}, Lr11/y;->e()I

    .line 118
    .line 119
    .line 120
    move-result v7

    .line 121
    add-int/2addr v5, v7

    .line 122
    iget-object v7, p0, Lr11/d;->d:[Lr11/y;

    .line 123
    .line 124
    aput-object v6, v7, v4

    .line 125
    .line 126
    add-int/lit8 v4, v4, 0x1

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_6
    iput v5, p0, Lr11/d;->f:I

    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_7
    :goto_4
    iput-object p1, p0, Lr11/d;->d:[Lr11/y;

    .line 133
    .line 134
    iput v3, p0, Lr11/d;->f:I

    .line 135
    .line 136
    :goto_5
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    if-nez v0, :cond_a

    .line 141
    .line 142
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    if-eqz v0, :cond_8

    .line 147
    .line 148
    goto :goto_7

    .line 149
    :cond_8
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    new-array v0, p1, [Lr11/w;

    .line 154
    .line 155
    iput-object v0, p0, Lr11/d;->e:[Lr11/w;

    .line 156
    .line 157
    move v0, v3

    .line 158
    :goto_6
    if-ge v3, p1, :cond_9

    .line 159
    .line 160
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    check-cast v2, Lr11/w;

    .line 165
    .line 166
    invoke-interface {v2}, Lr11/w;->a()I

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    add-int/2addr v0, v4

    .line 171
    iget-object v4, p0, Lr11/d;->e:[Lr11/w;

    .line 172
    .line 173
    aput-object v2, v4, v3

    .line 174
    .line 175
    add-int/lit8 v3, v3, 0x1

    .line 176
    .line 177
    goto :goto_6

    .line 178
    :cond_9
    iput v0, p0, Lr11/d;->g:I

    .line 179
    .line 180
    return-void

    .line 181
    :cond_a
    :goto_7
    iput-object p1, p0, Lr11/d;->e:[Lr11/w;

    .line 182
    .line 183
    iput v3, p0, Lr11/d;->g:I

    .line 184
    .line 185
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/d;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 10

    .line 1
    iget-object p0, p0, Lr11/d;->d:[Lr11/y;

    .line 2
    .line 3
    if-eqz p0, :cond_2

    .line 4
    .line 5
    if-nez p7, :cond_0

    .line 6
    .line 7
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    move-object v8, v0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object/from16 v8, p7

    .line 14
    .line 15
    :goto_0
    array-length v0, p0

    .line 16
    const/4 v1, 0x0

    .line 17
    move v9, v1

    .line 18
    :goto_1
    if-ge v9, v0, :cond_1

    .line 19
    .line 20
    aget-object v1, p0, v9

    .line 21
    .line 22
    move-object v2, p1

    .line 23
    move-wide v3, p2

    .line 24
    move-object v5, p4

    .line 25
    move v6, p5

    .line 26
    move-object/from16 v7, p6

    .line 27
    .line 28
    invoke-interface/range {v1 .. v8}, Lr11/y;->b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V

    .line 29
    .line 30
    .line 31
    add-int/lit8 v9, v9, 0x1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    return-void

    .line 35
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lr11/d;->d:[Lr11/y;

    .line 2
    .line 3
    if-eqz p0, :cond_2

    .line 4
    .line 5
    if-nez p3, :cond_0

    .line 6
    .line 7
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 8
    .line 9
    .line 10
    move-result-object p3

    .line 11
    :cond_0
    array-length v0, p0

    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    if-ge v1, v0, :cond_1

    .line 14
    .line 15
    aget-object v2, p0, v1

    .line 16
    .line 17
    invoke-interface {v2, p1, p2, p3}, Lr11/y;->c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    return-void

    .line 24
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 3

    .line 1
    iget-object p0, p0, Lr11/d;->e:[Lr11/w;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    array-length v0, p0

    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    if-ge v1, v0, :cond_0

    .line 8
    .line 9
    if-ltz p3, :cond_0

    .line 10
    .line 11
    aget-object v2, p0, v1

    .line 12
    .line 13
    invoke-interface {v2, p1, p2, p3}, Lr11/w;->d(Lr11/s;Ljava/lang/CharSequence;I)I

    .line 14
    .line 15
    .line 16
    move-result p3

    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    return p3

    .line 21
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public final e()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/d;->f:I

    .line 2
    .line 3
    return p0
.end method
