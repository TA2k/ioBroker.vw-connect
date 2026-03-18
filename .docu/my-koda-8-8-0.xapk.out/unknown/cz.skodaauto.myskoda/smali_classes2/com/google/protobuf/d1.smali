.class public final Lcom/google/protobuf/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lcom/google/protobuf/d1;


# instance fields
.field public a:I

.field public b:[I

.field public c:[Ljava/lang/Object;

.field public d:I

.field public e:Z


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/google/protobuf/d1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [I

    .line 5
    .line 6
    new-array v3, v1, [Ljava/lang/Object;

    .line 7
    .line 8
    invoke-direct {v0, v1, v2, v3, v1}, Lcom/google/protobuf/d1;-><init>(I[I[Ljava/lang/Object;Z)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lcom/google/protobuf/d1;->f:Lcom/google/protobuf/d1;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(I[I[Ljava/lang/Object;Z)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lcom/google/protobuf/d1;->d:I

    .line 6
    .line 7
    iput p1, p0, Lcom/google/protobuf/d1;->a:I

    .line 8
    .line 9
    iput-object p2, p0, Lcom/google/protobuf/d1;->b:[I

    .line 10
    .line 11
    iput-object p3, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 12
    .line 13
    iput-boolean p4, p0, Lcom/google/protobuf/d1;->e:Z

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 6

    .line 1
    iget v0, p0, Lcom/google/protobuf/d1;->d:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-eq v0, v1, :cond_0

    .line 5
    .line 6
    return v0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    move v1, v0

    .line 9
    :goto_0
    iget v2, p0, Lcom/google/protobuf/d1;->a:I

    .line 10
    .line 11
    if-ge v0, v2, :cond_6

    .line 12
    .line 13
    iget-object v2, p0, Lcom/google/protobuf/d1;->b:[I

    .line 14
    .line 15
    aget v2, v2, v0

    .line 16
    .line 17
    ushr-int/lit8 v3, v2, 0x3

    .line 18
    .line 19
    and-int/lit8 v2, v2, 0x7

    .line 20
    .line 21
    if-eqz v2, :cond_5

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v2, v4, :cond_4

    .line 25
    .line 26
    const/4 v4, 0x2

    .line 27
    if-eq v2, v4, :cond_3

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    if-eq v2, v5, :cond_2

    .line 31
    .line 32
    const/4 v4, 0x5

    .line 33
    if-ne v2, v4, :cond_1

    .line 34
    .line 35
    iget-object v2, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 36
    .line 37
    aget-object v2, v2, v0

    .line 38
    .line 39
    check-cast v2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-static {v3}, Lcom/google/protobuf/f;->f(I)I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    add-int/lit8 v2, v2, 0x4

    .line 49
    .line 50
    :goto_1
    add-int/2addr v2, v1

    .line 51
    move v1, v2

    .line 52
    goto :goto_3

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    sget v0, Lcom/google/protobuf/w;->d:I

    .line 56
    .line 57
    new-instance v0, Lcom/google/protobuf/v;

    .line 58
    .line 59
    const-string v1, "Protocol message tag had invalid wire type."

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_2
    invoke-static {v3}, Lcom/google/protobuf/f;->f(I)I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    mul-int/2addr v2, v4

    .line 73
    iget-object v3, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 74
    .line 75
    aget-object v3, v3, v0

    .line 76
    .line 77
    check-cast v3, Lcom/google/protobuf/d1;

    .line 78
    .line 79
    invoke-virtual {v3}, Lcom/google/protobuf/d1;->a()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    :goto_2
    add-int/2addr v3, v2

    .line 84
    add-int/2addr v3, v1

    .line 85
    move v1, v3

    .line 86
    goto :goto_3

    .line 87
    :cond_3
    iget-object v2, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 88
    .line 89
    aget-object v2, v2, v0

    .line 90
    .line 91
    check-cast v2, Lcom/google/protobuf/e;

    .line 92
    .line 93
    invoke-static {v3}, Lcom/google/protobuf/f;->f(I)I

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    invoke-virtual {v2}, Lcom/google/protobuf/e;->size()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    invoke-static {v2, v2, v3, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    goto :goto_3

    .line 106
    :cond_4
    iget-object v2, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 107
    .line 108
    aget-object v2, v2, v0

    .line 109
    .line 110
    check-cast v2, Ljava/lang/Long;

    .line 111
    .line 112
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    invoke-static {v3}, Lcom/google/protobuf/f;->f(I)I

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    add-int/lit8 v2, v2, 0x8

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_5
    iget-object v2, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 123
    .line 124
    aget-object v2, v2, v0

    .line 125
    .line 126
    check-cast v2, Ljava/lang/Long;

    .line 127
    .line 128
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 129
    .line 130
    .line 131
    move-result-wide v4

    .line 132
    invoke-static {v3}, Lcom/google/protobuf/f;->f(I)I

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    invoke-static {v4, v5}, Lcom/google/protobuf/f;->h(J)I

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    goto :goto_2

    .line 141
    :goto_3
    add-int/lit8 v0, v0, 0x1

    .line 142
    .line 143
    goto/16 :goto_0

    .line 144
    .line 145
    :cond_6
    iput v1, p0, Lcom/google/protobuf/d1;->d:I

    .line 146
    .line 147
    return v1
.end method

.method public final b(Lcom/google/protobuf/f0;)V
    .locals 6

    .line 1
    iget v0, p0, Lcom/google/protobuf/d1;->a:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_2

    .line 6
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget-object v0, p1, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Lcom/google/protobuf/f;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    :goto_0
    iget v2, p0, Lcom/google/protobuf/d1;->a:I

    .line 15
    .line 16
    if-ge v1, v2, :cond_6

    .line 17
    .line 18
    iget-object v2, p0, Lcom/google/protobuf/d1;->b:[I

    .line 19
    .line 20
    aget v2, v2, v1

    .line 21
    .line 22
    iget-object v3, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 23
    .line 24
    aget-object v3, v3, v1

    .line 25
    .line 26
    ushr-int/lit8 v4, v2, 0x3

    .line 27
    .line 28
    and-int/lit8 v2, v2, 0x7

    .line 29
    .line 30
    if-eqz v2, :cond_5

    .line 31
    .line 32
    const/4 v5, 0x1

    .line 33
    if-eq v2, v5, :cond_4

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    if-eq v2, v5, :cond_3

    .line 37
    .line 38
    const/4 v5, 0x3

    .line 39
    if-eq v2, v5, :cond_2

    .line 40
    .line 41
    const/4 v5, 0x5

    .line 42
    if-ne v2, v5, :cond_1

    .line 43
    .line 44
    check-cast v3, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    invoke-virtual {v0, v4, v2}, Lcom/google/protobuf/f;->l(II)V

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    new-instance p0, Ljava/lang/RuntimeException;

    .line 55
    .line 56
    sget p1, Lcom/google/protobuf/w;->d:I

    .line 57
    .line 58
    new-instance p1, Lcom/google/protobuf/v;

    .line 59
    .line 60
    const-string v0, "Protocol message tag had invalid wire type."

    .line 61
    .line 62
    invoke-direct {p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    invoke-virtual {v0, v4, v5}, Lcom/google/protobuf/f;->r(II)V

    .line 70
    .line 71
    .line 72
    check-cast v3, Lcom/google/protobuf/d1;

    .line 73
    .line 74
    invoke-virtual {v3, p1}, Lcom/google/protobuf/d1;->b(Lcom/google/protobuf/f0;)V

    .line 75
    .line 76
    .line 77
    const/4 v2, 0x4

    .line 78
    invoke-virtual {v0, v4, v2}, Lcom/google/protobuf/f;->r(II)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    check-cast v3, Lcom/google/protobuf/e;

    .line 83
    .line 84
    invoke-virtual {v0, v4, v5}, Lcom/google/protobuf/f;->r(II)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, v3}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_4
    check-cast v3, Ljava/lang/Long;

    .line 92
    .line 93
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 94
    .line 95
    .line 96
    move-result-wide v2

    .line 97
    invoke-virtual {v0, v4, v2, v3}, Lcom/google/protobuf/f;->n(IJ)V

    .line 98
    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_5
    check-cast v3, Ljava/lang/Long;

    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 104
    .line 105
    .line 106
    move-result-wide v2

    .line 107
    invoke-virtual {v0, v4, v2, v3}, Lcom/google/protobuf/f;->t(IJ)V

    .line 108
    .line 109
    .line 110
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_6
    :goto_2
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-nez p1, :cond_1

    .line 7
    .line 8
    return v1

    .line 9
    :cond_1
    instance-of v2, p1, Lcom/google/protobuf/d1;

    .line 10
    .line 11
    if-nez v2, :cond_2

    .line 12
    .line 13
    return v1

    .line 14
    :cond_2
    check-cast p1, Lcom/google/protobuf/d1;

    .line 15
    .line 16
    iget v2, p0, Lcom/google/protobuf/d1;->a:I

    .line 17
    .line 18
    iget v3, p1, Lcom/google/protobuf/d1;->a:I

    .line 19
    .line 20
    if-ne v2, v3, :cond_7

    .line 21
    .line 22
    iget-object v3, p0, Lcom/google/protobuf/d1;->b:[I

    .line 23
    .line 24
    iget-object v4, p1, Lcom/google/protobuf/d1;->b:[I

    .line 25
    .line 26
    move v5, v1

    .line 27
    :goto_0
    if-ge v5, v2, :cond_4

    .line 28
    .line 29
    aget v6, v3, v5

    .line 30
    .line 31
    aget v7, v4, v5

    .line 32
    .line 33
    if-eq v6, v7, :cond_3

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_4
    iget-object v2, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 40
    .line 41
    iget-object p1, p1, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 42
    .line 43
    iget p0, p0, Lcom/google/protobuf/d1;->a:I

    .line 44
    .line 45
    move v3, v1

    .line 46
    :goto_1
    if-ge v3, p0, :cond_6

    .line 47
    .line 48
    aget-object v4, v2, v3

    .line 49
    .line 50
    aget-object v5, p1, v3

    .line 51
    .line 52
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-nez v4, :cond_5

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_5
    add-int/lit8 v3, v3, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_6
    return v0

    .line 63
    :cond_7
    :goto_2
    return v1
.end method

.method public final hashCode()I
    .locals 8

    .line 1
    iget v0, p0, Lcom/google/protobuf/d1;->a:I

    .line 2
    .line 3
    const/16 v1, 0x20f

    .line 4
    .line 5
    add-int/2addr v1, v0

    .line 6
    mul-int/lit8 v1, v1, 0x1f

    .line 7
    .line 8
    iget-object v2, p0, Lcom/google/protobuf/d1;->b:[I

    .line 9
    .line 10
    const/16 v3, 0x11

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    move v6, v3

    .line 14
    move v5, v4

    .line 15
    :goto_0
    if-ge v5, v0, :cond_0

    .line 16
    .line 17
    mul-int/lit8 v6, v6, 0x1f

    .line 18
    .line 19
    aget v7, v2, v5

    .line 20
    .line 21
    add-int/2addr v6, v7

    .line 22
    add-int/lit8 v5, v5, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    add-int/2addr v1, v6

    .line 26
    mul-int/lit8 v1, v1, 0x1f

    .line 27
    .line 28
    iget-object v0, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 29
    .line 30
    iget p0, p0, Lcom/google/protobuf/d1;->a:I

    .line 31
    .line 32
    :goto_1
    if-ge v4, p0, :cond_1

    .line 33
    .line 34
    mul-int/lit8 v3, v3, 0x1f

    .line 35
    .line 36
    aget-object v2, v0, v4

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    add-int/2addr v3, v2

    .line 43
    add-int/lit8 v4, v4, 0x1

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    add-int/2addr v1, v3

    .line 47
    return v1
.end method
