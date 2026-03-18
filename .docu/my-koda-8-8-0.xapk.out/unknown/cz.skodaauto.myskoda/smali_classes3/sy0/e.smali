.class public Lsy0/e;
.super Lq2/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lsy0/d;

.field public i:Ljava/lang/Object;

.field public j:Z

.field public k:I


# direct methods
.method public constructor <init>(Lsy0/d;[Lq2/j;)V
    .locals 1

    .line 1
    const-string v0, "builder"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lsy0/d;->f:Lsy0/j;

    .line 7
    .line 8
    invoke-direct {p0, v0, p2}, Lq2/c;-><init>(Lsy0/j;[Lq2/j;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lsy0/e;->h:Lsy0/d;

    .line 12
    .line 13
    iget p1, p1, Lsy0/d;->h:I

    .line 14
    .line 15
    iput p1, p0, Lsy0/e;->k:I

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final e(ILsy0/j;Ljava/lang/Object;IIZ)V
    .locals 8

    .line 1
    iget-object v0, p0, Lq2/c;->g:[Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [Lq2/j;

    .line 4
    .line 5
    mul-int/lit8 v1, p4, 0x5

    .line 6
    .line 7
    const/16 v2, 0x1e

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x2

    .line 11
    if-le v1, v2, :cond_1

    .line 12
    .line 13
    aget-object p1, v0, p4

    .line 14
    .line 15
    iget-object p2, p2, Lsy0/j;->d:[Ljava/lang/Object;

    .line 16
    .line 17
    array-length p5, p2

    .line 18
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    iput-object p2, p1, Lq2/j;->e:[Ljava/lang/Object;

    .line 22
    .line 23
    iput p5, p1, Lq2/j;->f:I

    .line 24
    .line 25
    iput v3, p1, Lq2/j;->g:I

    .line 26
    .line 27
    :goto_0
    aget-object p1, v0, p4

    .line 28
    .line 29
    iget-object p2, p1, Lq2/j;->e:[Ljava/lang/Object;

    .line 30
    .line 31
    iget p1, p1, Lq2/j;->g:I

    .line 32
    .line 33
    aget-object p1, p2, p1

    .line 34
    .line 35
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_0

    .line 40
    .line 41
    aget-object p1, v0, p4

    .line 42
    .line 43
    iget p2, p1, Lq2/j;->g:I

    .line 44
    .line 45
    add-int/2addr p2, v4

    .line 46
    iput p2, p1, Lq2/j;->g:I

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    iput p4, p0, Lq2/c;->e:I

    .line 50
    .line 51
    return-void

    .line 52
    :cond_1
    invoke-static {p1, v1}, Lkp/v8;->d(II)I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    const/4 v5, 0x1

    .line 57
    shl-int v2, v5, v2

    .line 58
    .line 59
    invoke-virtual {p2, v2}, Lsy0/j;->i(I)Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    const-string v7, "buffer"

    .line 64
    .line 65
    if-eqz v6, :cond_4

    .line 66
    .line 67
    invoke-virtual {p2, v2}, Lsy0/j;->f(I)I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p6, :cond_2

    .line 72
    .line 73
    invoke-static {p5, v1}, Lkp/v8;->d(II)I

    .line 74
    .line 75
    .line 76
    move-result p3

    .line 77
    shl-int p3, v5, p3

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_2
    move p3, v3

    .line 81
    :goto_1
    if-ne v2, p3, :cond_3

    .line 82
    .line 83
    iget p3, p0, Lq2/c;->e:I

    .line 84
    .line 85
    if-ge p4, p3, :cond_3

    .line 86
    .line 87
    aget-object p0, v0, p3

    .line 88
    .line 89
    iget-object p2, p2, Lsy0/j;->d:[Ljava/lang/Object;

    .line 90
    .line 91
    aget-object p3, p2, p1

    .line 92
    .line 93
    add-int/2addr p1, v5

    .line 94
    aget-object p1, p2, p1

    .line 95
    .line 96
    filled-new-array {p3, p1}, [Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    iput-object p1, p0, Lq2/j;->e:[Ljava/lang/Object;

    .line 104
    .line 105
    iput v4, p0, Lq2/j;->f:I

    .line 106
    .line 107
    iput v3, p0, Lq2/j;->g:I

    .line 108
    .line 109
    return-void

    .line 110
    :cond_3
    aget-object p3, v0, p4

    .line 111
    .line 112
    iget-object p5, p2, Lsy0/j;->d:[Ljava/lang/Object;

    .line 113
    .line 114
    iget p2, p2, Lsy0/j;->a:I

    .line 115
    .line 116
    invoke-static {p2}, Ljava/lang/Integer;->bitCount(I)I

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    mul-int/2addr p2, v4

    .line 121
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    invoke-static {p5, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    iput-object p5, p3, Lq2/j;->e:[Ljava/lang/Object;

    .line 128
    .line 129
    iput p2, p3, Lq2/j;->f:I

    .line 130
    .line 131
    iput p1, p3, Lq2/j;->g:I

    .line 132
    .line 133
    iput p4, p0, Lq2/c;->e:I

    .line 134
    .line 135
    return-void

    .line 136
    :cond_4
    invoke-virtual {p2, v2}, Lsy0/j;->t(I)I

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    move-object v2, p2

    .line 141
    invoke-virtual {v2, v1}, Lsy0/j;->s(I)Lsy0/j;

    .line 142
    .line 143
    .line 144
    move-result-object p2

    .line 145
    aget-object v0, v0, p4

    .line 146
    .line 147
    iget-object v3, v2, Lsy0/j;->d:[Ljava/lang/Object;

    .line 148
    .line 149
    iget v2, v2, Lsy0/j;->a:I

    .line 150
    .line 151
    invoke-static {v2}, Ljava/lang/Integer;->bitCount(I)I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    mul-int/2addr v2, v4

    .line 156
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    iput-object v3, v0, Lq2/j;->e:[Ljava/lang/Object;

    .line 163
    .line 164
    iput v2, v0, Lq2/j;->f:I

    .line 165
    .line 166
    iput v1, v0, Lq2/j;->g:I

    .line 167
    .line 168
    add-int/2addr p4, v5

    .line 169
    invoke-virtual/range {p0 .. p6}, Lsy0/e;->e(ILsy0/j;Ljava/lang/Object;IIZ)V

    .line 170
    .line 171
    .line 172
    return-void
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lsy0/e;->h:Lsy0/d;

    .line 2
    .line 3
    iget v0, v0, Lsy0/d;->h:I

    .line 4
    .line 5
    iget v1, p0, Lsy0/e;->k:I

    .line 6
    .line 7
    if-ne v0, v1, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Lq2/c;->f:Z

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lq2/c;->g:[Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, [Lq2/j;

    .line 16
    .line 17
    iget v1, p0, Lq2/c;->e:I

    .line 18
    .line 19
    aget-object v0, v0, v1

    .line 20
    .line 21
    iget-object v1, v0, Lq2/j;->e:[Ljava/lang/Object;

    .line 22
    .line 23
    iget v0, v0, Lq2/j;->g:I

    .line 24
    .line 25
    aget-object v0, v1, v0

    .line 26
    .line 27
    iput-object v0, p0, Lsy0/e;->i:Ljava/lang/Object;

    .line 28
    .line 29
    const/4 v0, 0x1

    .line 30
    iput-boolean v0, p0, Lsy0/e;->j:Z

    .line 31
    .line 32
    invoke-super {p0}, Lq2/c;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 38
    .line 39
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 44
    .line 45
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0
.end method

.method public final remove()V
    .locals 11

    .line 1
    iget-boolean v0, p0, Lsy0/e;->j:Z

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    iget-boolean v0, p0, Lq2/c;->f:Z

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iget-object v2, p0, Lsy0/e;->h:Lsy0/d;

    .line 9
    .line 10
    if-eqz v0, :cond_3

    .line 11
    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    iget-object v0, p0, Lq2/c;->g:[Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, [Lq2/j;

    .line 17
    .line 18
    iget v3, p0, Lq2/c;->e:I

    .line 19
    .line 20
    aget-object v0, v0, v3

    .line 21
    .line 22
    iget-object v3, v0, Lq2/j;->e:[Ljava/lang/Object;

    .line 23
    .line 24
    iget v0, v0, Lq2/j;->g:I

    .line 25
    .line 26
    aget-object v7, v3, v0

    .line 27
    .line 28
    iget-object v0, p0, Lsy0/e;->i:Ljava/lang/Object;

    .line 29
    .line 30
    invoke-static {v2}, Lkotlin/jvm/internal/j0;->c(Ljava/lang/Object;)Ljava/util/Map;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-interface {v3, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    if-eqz v7, :cond_0

    .line 38
    .line 39
    invoke-virtual {v7}, Ljava/lang/Object;->hashCode()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    move v5, v0

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    move v5, v1

    .line 46
    :goto_0
    iget-object v6, v2, Lsy0/d;->f:Lsy0/j;

    .line 47
    .line 48
    iget-object v0, p0, Lsy0/e;->i:Ljava/lang/Object;

    .line 49
    .line 50
    if-eqz v0, :cond_1

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    move v9, v0

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    move v9, v1

    .line 59
    :goto_1
    const/4 v10, 0x1

    .line 60
    const/4 v8, 0x0

    .line 61
    move-object v4, p0

    .line 62
    invoke-virtual/range {v4 .. v10}, Lsy0/e;->e(ILsy0/j;Ljava/lang/Object;IIZ)V

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_2
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 67
    .line 68
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_3
    move-object v4, p0

    .line 73
    iget-object p0, v4, Lsy0/e;->i:Ljava/lang/Object;

    .line 74
    .line 75
    invoke-static {v2}, Lkotlin/jvm/internal/j0;->c(Ljava/lang/Object;)Ljava/util/Map;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v0, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    :goto_2
    const/4 p0, 0x0

    .line 83
    iput-object p0, v4, Lsy0/e;->i:Ljava/lang/Object;

    .line 84
    .line 85
    iput-boolean v1, v4, Lsy0/e;->j:Z

    .line 86
    .line 87
    iget p0, v2, Lsy0/d;->h:I

    .line 88
    .line 89
    iput p0, v4, Lsy0/e;->k:I

    .line 90
    .line 91
    return-void

    .line 92
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 95
    .line 96
    .line 97
    throw p0
.end method
