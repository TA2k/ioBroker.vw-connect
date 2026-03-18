.class public abstract Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;

    .line 2
    .line 3
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 4
    .line 5
    const/4 v1, 0x6

    .line 6
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;-><init>(I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 10
    .line 11
    return-void
.end method

.method public static A(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 22
    .line 23
    .line 24
    move p0, v0

    .line 25
    move p3, p0

    .line 26
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ge p0, v1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Long;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    add-int/lit8 p3, p3, 0x8

    .line 42
    .line 43
    add-int/lit8 p0, p0, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 47
    .line 48
    .line 49
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-ge v0, p0, :cond_3

    .line 54
    .line 55
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Ljava/lang/Long;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 62
    .line 63
    .line 64
    move-result-wide v1

    .line 65
    invoke-virtual {p2, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->m(J)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v0, v0, 0x1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 72
    .line 73
    .line 74
    move-result p3

    .line 75
    if-ge v0, p3, :cond_3

    .line 76
    .line 77
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p3

    .line 81
    check-cast p3, Ljava/lang/Long;

    .line 82
    .line 83
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 84
    .line 85
    .line 86
    move-result-wide v1

    .line 87
    invoke-virtual {p2, p0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 88
    .line 89
    .line 90
    add-int/lit8 v0, v0, 0x1

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 94
    .line 95
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_3
    return-void
.end method

.method public static a(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    add-int v1, v0, v0

    .line 37
    .line 38
    shr-int/lit8 v0, v0, 0x1f

    .line 39
    .line 40
    xor-int/2addr v0, v1

    .line 41
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    add-int/2addr p3, v0

    .line 46
    add-int/lit8 p0, p0, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 50
    .line 51
    .line 52
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 53
    .line 54
    if-ge v2, p0, :cond_5

    .line 55
    .line 56
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    add-int p3, p0, p0

    .line 61
    .line 62
    shr-int/lit8 p0, p0, 0x1f

    .line 63
    .line 64
    xor-int/2addr p0, p3

    .line 65
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v2, v2, 0x1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 72
    .line 73
    if-ge v2, p3, :cond_5

    .line 74
    .line 75
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    add-int v0, p3, p3

    .line 80
    .line 81
    shr-int/lit8 p3, p3, 0x1f

    .line 82
    .line 83
    xor-int/2addr p3, v0

    .line 84
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 85
    .line 86
    .line 87
    add-int/lit8 v2, v2, 0x1

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_2
    if-eqz p3, :cond_4

    .line 91
    .line 92
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 93
    .line 94
    .line 95
    move p0, v2

    .line 96
    move p3, p0

    .line 97
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    if-ge p0, v0, :cond_3

    .line 102
    .line 103
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    check-cast v0, Ljava/lang/Integer;

    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    add-int v1, v0, v0

    .line 114
    .line 115
    shr-int/lit8 v0, v0, 0x1f

    .line 116
    .line 117
    xor-int/2addr v0, v1

    .line 118
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    add-int/2addr p3, v0

    .line 123
    add-int/lit8 p0, p0, 0x1

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 127
    .line 128
    .line 129
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    if-ge v2, p0, :cond_5

    .line 134
    .line 135
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p0, Ljava/lang/Integer;

    .line 140
    .line 141
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    add-int p3, p0, p0

    .line 146
    .line 147
    shr-int/lit8 p0, p0, 0x1f

    .line 148
    .line 149
    xor-int/2addr p0, p3

    .line 150
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 151
    .line 152
    .line 153
    add-int/lit8 v2, v2, 0x1

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 157
    .line 158
    .line 159
    move-result p3

    .line 160
    if-ge v2, p3, :cond_5

    .line 161
    .line 162
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p3

    .line 166
    check-cast p3, Ljava/lang/Integer;

    .line 167
    .line 168
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 169
    .line 170
    .line 171
    move-result p3

    .line 172
    add-int v0, p3, p3

    .line 173
    .line 174
    shr-int/lit8 p3, p3, 0x1f

    .line 175
    .line 176
    xor-int/2addr p3, v0

    .line 177
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 178
    .line 179
    .line 180
    add-int/lit8 v2, v2, 0x1

    .line 181
    .line 182
    goto :goto_5

    .line 183
    :cond_5
    return-void
.end method

.method public static b(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 6

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/16 v0, 0x3f

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    if-eqz p3, :cond_1

    .line 21
    .line 22
    const/4 p3, 0x2

    .line 23
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v1

    .line 27
    move p3, p0

    .line 28
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-ge p0, v2, :cond_0

    .line 33
    .line 34
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Ljava/lang/Long;

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 41
    .line 42
    .line 43
    move-result-wide v2

    .line 44
    add-long v4, v2, v2

    .line 45
    .line 46
    shr-long/2addr v2, v0

    .line 47
    xor-long/2addr v2, v4

    .line 48
    invoke-static {v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    add-int/2addr p3, v2

    .line 53
    add-int/lit8 p0, p0, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 57
    .line 58
    .line 59
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-ge v1, p0, :cond_3

    .line 64
    .line 65
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Ljava/lang/Long;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 72
    .line 73
    .line 74
    move-result-wide v2

    .line 75
    add-long v4, v2, v2

    .line 76
    .line 77
    shr-long/2addr v2, v0

    .line 78
    xor-long/2addr v2, v4

    .line 79
    invoke-virtual {p2, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->u(J)V

    .line 80
    .line 81
    .line 82
    add-int/lit8 v1, v1, 0x1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 86
    .line 87
    .line 88
    move-result p3

    .line 89
    if-ge v1, p3, :cond_3

    .line 90
    .line 91
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p3

    .line 95
    check-cast p3, Ljava/lang/Long;

    .line 96
    .line 97
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 98
    .line 99
    .line 100
    move-result-wide v2

    .line 101
    add-long v4, v2, v2

    .line 102
    .line 103
    shr-long/2addr v2, v0

    .line 104
    xor-long/2addr v2, v4

    .line 105
    invoke-virtual {p2, p0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 106
    .line 107
    .line 108
    add-int/lit8 v1, v1, 0x1

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 112
    .line 113
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 114
    .line 115
    .line 116
    throw p0

    .line 117
    :cond_3
    return-void
.end method

.method public static c(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    add-int/2addr p3, v0

    .line 41
    add-int/lit8 p0, p0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 45
    .line 46
    .line 47
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 48
    .line 49
    if-ge v2, p0, :cond_5

    .line 50
    .line 51
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 56
    .line 57
    .line 58
    add-int/lit8 v2, v2, 0x1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 62
    .line 63
    if-ge v2, p3, :cond_5

    .line 64
    .line 65
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 66
    .line 67
    .line 68
    move-result p3

    .line 69
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 70
    .line 71
    .line 72
    add-int/lit8 v2, v2, 0x1

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_2
    if-eqz p3, :cond_4

    .line 76
    .line 77
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 78
    .line 79
    .line 80
    move p0, v2

    .line 81
    move p3, p0

    .line 82
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-ge p0, v0, :cond_3

    .line 87
    .line 88
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    check-cast v0, Ljava/lang/Integer;

    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    add-int/2addr p3, v0

    .line 103
    add-int/lit8 p0, p0, 0x1

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 107
    .line 108
    .line 109
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-ge v2, p0, :cond_5

    .line 114
    .line 115
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    check-cast p0, Ljava/lang/Integer;

    .line 120
    .line 121
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 126
    .line 127
    .line 128
    add-int/lit8 v2, v2, 0x1

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 132
    .line 133
    .line 134
    move-result p3

    .line 135
    if-ge v2, p3, :cond_5

    .line 136
    .line 137
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p3

    .line 141
    check-cast p3, Ljava/lang/Integer;

    .line 142
    .line 143
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->r(II)V

    .line 148
    .line 149
    .line 150
    add-int/lit8 v2, v2, 0x1

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_5
    return-void
.end method

.method public static d(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 22
    .line 23
    .line 24
    move p0, v0

    .line 25
    move p3, p0

    .line 26
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ge p0, v1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Long;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 39
    .line 40
    .line 41
    move-result-wide v1

    .line 42
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    add-int/2addr p3, v1

    .line 47
    add-int/lit8 p0, p0, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 51
    .line 52
    .line 53
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-ge v0, p0, :cond_3

    .line 58
    .line 59
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Ljava/lang/Long;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 66
    .line 67
    .line 68
    move-result-wide v1

    .line 69
    invoke-virtual {p2, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->u(J)V

    .line 70
    .line 71
    .line 72
    add-int/lit8 v0, v0, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    if-ge v0, p3, :cond_3

    .line 80
    .line 81
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p3

    .line 85
    check-cast p3, Ljava/lang/Long;

    .line 86
    .line 87
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 88
    .line 89
    .line 90
    move-result-wide v1

    .line 91
    invoke-virtual {p2, p0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 92
    .line 93
    .line 94
    add-int/lit8 v0, v0, 0x1

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 98
    .line 99
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_3
    return-void
.end method

.method public static e(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p0, p1, :cond_1

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return v0

    .line 14
    :cond_0
    return v1

    .line 15
    :cond_1
    return v0
.end method

.method public static f(Ljava/util/List;)I
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    move v2, v1

    .line 16
    :goto_0
    if-ge v1, v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    int-to-long v3, v3

    .line 23
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    add-int/2addr v2, v3

    .line 28
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    return v2

    .line 32
    :cond_2
    move v2, v1

    .line 33
    :goto_1
    if-ge v1, v0, :cond_3

    .line 34
    .line 35
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    int-to-long v3, v3

    .line 46
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    add-int/2addr v2, v3

    .line 51
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_3
    return v2
.end method

.method public static g(ILjava/util/List;)I
    .locals 0

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    shl-int/lit8 p0, p0, 0x3

    .line 10
    .line 11
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/lit8 p0, p0, 0x4

    .line 16
    .line 17
    mul-int/2addr p0, p1

    .line 18
    return p0
.end method

.method public static h(ILjava/util/List;)I
    .locals 0

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    shl-int/lit8 p0, p0, 0x3

    .line 10
    .line 11
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/lit8 p0, p0, 0x8

    .line 16
    .line 17
    mul-int/2addr p0, p1

    .line 18
    return p0
.end method

.method public static i(Ljava/util/List;)I
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    move v2, v1

    .line 16
    :goto_0
    if-ge v1, v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    int-to-long v3, v3

    .line 23
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    add-int/2addr v2, v3

    .line 28
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    return v2

    .line 32
    :cond_2
    move v2, v1

    .line 33
    :goto_1
    if-ge v1, v0, :cond_3

    .line 34
    .line 35
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    int-to-long v3, v3

    .line 46
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    add-int/2addr v2, v3

    .line 51
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_3
    return v2
.end method

.method public static j(Ljava/util/List;)I
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-gtz v0, :cond_1

    .line 16
    .line 17
    return v1

    .line 18
    :cond_1
    const/4 p0, 0x0

    .line 19
    throw p0

    .line 20
    :cond_2
    move v2, v1

    .line 21
    :goto_0
    if-ge v1, v0, :cond_3

    .line 22
    .line 23
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ljava/lang/Long;

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    add-int/2addr v2, v3

    .line 38
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_3
    return v2
.end method

.method public static k(Ljava/util/List;)I
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    move v2, v1

    .line 16
    :goto_0
    if-ge v1, v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    add-int v4, v3, v3

    .line 23
    .line 24
    shr-int/lit8 v3, v3, 0x1f

    .line 25
    .line 26
    xor-int/2addr v3, v4

    .line 27
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    add-int/2addr v2, v3

    .line 32
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    return v2

    .line 36
    :cond_2
    move v2, v1

    .line 37
    :goto_1
    if-ge v1, v0, :cond_3

    .line 38
    .line 39
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    add-int v4, v3, v3

    .line 50
    .line 51
    shr-int/lit8 v3, v3, 0x1f

    .line 52
    .line 53
    xor-int/2addr v3, v4

    .line 54
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    add-int/2addr v2, v3

    .line 59
    add-int/lit8 v1, v1, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    return v2
.end method

.method public static l(Ljava/util/List;)I
    .locals 8

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-gtz v0, :cond_1

    .line 16
    .line 17
    return v1

    .line 18
    :cond_1
    const/4 p0, 0x0

    .line 19
    throw p0

    .line 20
    :cond_2
    move v2, v1

    .line 21
    :goto_0
    if-ge v1, v0, :cond_3

    .line 22
    .line 23
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ljava/lang/Long;

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    add-long v5, v3, v3

    .line 34
    .line 35
    const/16 v7, 0x3f

    .line 36
    .line 37
    shr-long/2addr v3, v7

    .line 38
    xor-long/2addr v3, v5

    .line 39
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    add-int/2addr v2, v3

    .line 44
    add-int/lit8 v1, v1, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_3
    return v2
.end method

.method public static m(Ljava/util/List;)I
    .locals 4

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    move v2, v1

    .line 16
    :goto_0
    if-ge v1, v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    add-int/2addr v2, v3

    .line 27
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    return v2

    .line 31
    :cond_2
    move v2, v1

    .line 32
    :goto_1
    if-ge v1, v0, :cond_3

    .line 33
    .line 34
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    add-int/2addr v2, v3

    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    return v2
.end method

.method public static n(Ljava/util/List;)I
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    instance-of v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 10
    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-gtz v0, :cond_1

    .line 16
    .line 17
    return v1

    .line 18
    :cond_1
    const/4 p0, 0x0

    .line 19
    throw p0

    .line 20
    :cond_2
    move v2, v1

    .line 21
    :goto_0
    if-ge v1, v0, :cond_3

    .line 22
    .line 23
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ljava/lang/Long;

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    invoke-static {v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    add-int/2addr v2, v3

    .line 38
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_3
    return v2
.end method

.method public static o(IILjava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 4
    .line 5
    iget-object p3, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 6
    .line 7
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 8
    .line 9
    if-ne p3, v0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    iput-object p3, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 16
    .line 17
    :cond_0
    int-to-long p1, p1

    .line 18
    shl-int/lit8 p0, p0, 0x3

    .line 19
    .line 20
    move-object v0, p3

    .line 21
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 22
    .line 23
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {v0, p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    return-object p3
.end method

.method public static p(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 2
    .line 3
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 4
    .line 5
    iget-object v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_2

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;

    .line 14
    .line 15
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 16
    .line 17
    iget-boolean v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->b:Z

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 26
    .line 27
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 33
    .line 34
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    :goto_0
    if-ge v1, v0, :cond_1

    .line 38
    .line 39
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->g(Ljava/util/Map$Entry;)V

    .line 44
    .line 45
    .line 46
    add-int/lit8 v1, v1, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->a()Ljava/util/Set;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    check-cast v0, Ljava/util/Map$Entry;

    .line 68
    .line 69
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->g(Ljava/util/Map$Entry;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    return-void
.end method

.method public static q(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 4
    .line 5
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 6
    .line 7
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 8
    .line 9
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 10
    .line 11
    invoke-virtual {v1, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_3

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x0

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    iget v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 25
    .line 26
    iget v2, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 27
    .line 28
    add-int/2addr v1, v2

    .line 29
    iget-object v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b:[I

    .line 30
    .line 31
    invoke-static {v2, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    iget-object v4, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b:[I

    .line 36
    .line 37
    iget v5, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 38
    .line 39
    iget v6, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 40
    .line 41
    invoke-static {v4, v3, v2, v5, v6}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 42
    .line 43
    .line 44
    iget-object v4, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c:[Ljava/lang/Object;

    .line 45
    .line 46
    invoke-static {v4, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    iget-object v5, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c:[Ljava/lang/Object;

    .line 51
    .line 52
    iget v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 53
    .line 54
    iget p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 55
    .line 56
    invoke-static {v5, v3, v4, v0, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 60
    .line 61
    const/4 p1, 0x1

    .line 62
    invoke-direct {v0, v1, v2, v4, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;-><init>(I[I[Ljava/lang/Object;Z)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    iget-boolean v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->e:Z

    .line 77
    .line 78
    if-eqz v1, :cond_2

    .line 79
    .line 80
    iget v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 81
    .line 82
    iget v2, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 83
    .line 84
    add-int/2addr v1, v2

    .line 85
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->e(I)V

    .line 86
    .line 87
    .line 88
    iget-object v2, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b:[I

    .line 89
    .line 90
    iget-object v4, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b:[I

    .line 91
    .line 92
    iget v5, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 93
    .line 94
    iget v6, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 95
    .line 96
    invoke-static {v2, v3, v4, v5, v6}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 97
    .line 98
    .line 99
    iget-object v2, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c:[Ljava/lang/Object;

    .line 100
    .line 101
    iget-object v4, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c:[Ljava/lang/Object;

    .line 102
    .line 103
    iget v5, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 104
    .line 105
    iget p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 106
    .line 107
    invoke-static {v2, v3, v4, v5, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 108
    .line 109
    .line 110
    iput v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->a:I

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 114
    .line 115
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 116
    .line 117
    .line 118
    throw p0

    .line 119
    :cond_3
    :goto_0
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->zzc:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 120
    .line 121
    return-void
.end method

.method public static r(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 2

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n0;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 22
    .line 23
    .line 24
    move p0, v0

    .line 25
    move p3, p0

    .line 26
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ge p0, v1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    add-int/lit8 p3, p3, 0x1

    .line 42
    .line 43
    add-int/lit8 p0, p0, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 47
    .line 48
    .line 49
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-ge v0, p0, :cond_3

    .line 54
    .line 55
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Ljava/lang/Boolean;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->g(B)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v0, v0, 0x1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 72
    .line 73
    .line 74
    move-result p3

    .line 75
    if-ge v0, p3, :cond_3

    .line 76
    .line 77
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p3

    .line 81
    check-cast p3, Ljava/lang/Boolean;

    .line 82
    .line 83
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 84
    .line 85
    .line 86
    move-result p3

    .line 87
    shl-int/lit8 v1, p0, 0x3

    .line 88
    .line 89
    invoke-virtual {p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->g(B)V

    .line 93
    .line 94
    .line 95
    add-int/lit8 v0, v0, 0x1

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_3
    return-void
.end method

.method public static s(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u0;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 22
    .line 23
    .line 24
    move p0, v0

    .line 25
    move p3, p0

    .line 26
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ge p0, v1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Double;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    add-int/lit8 p3, p3, 0x8

    .line 42
    .line 43
    add-int/lit8 p0, p0, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 47
    .line 48
    .line 49
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-ge v0, p0, :cond_3

    .line 54
    .line 55
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Ljava/lang/Double;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    .line 62
    .line 63
    .line 64
    move-result-wide v1

    .line 65
    invoke-static {v1, v2}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 66
    .line 67
    .line 68
    move-result-wide v1

    .line 69
    invoke-virtual {p2, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->m(J)V

    .line 70
    .line 71
    .line 72
    add-int/lit8 v0, v0, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    if-ge v0, p3, :cond_3

    .line 80
    .line 81
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p3

    .line 85
    check-cast p3, Ljava/lang/Double;

    .line 86
    .line 87
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    .line 88
    .line 89
    .line 90
    move-result-wide v1

    .line 91
    invoke-static {v1, v2}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 92
    .line 93
    .line 94
    move-result-wide v1

    .line 95
    invoke-virtual {p2, p0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 96
    .line 97
    .line 98
    add-int/lit8 v0, v0, 0x1

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_3
    return-void
.end method

.method public static t(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    int-to-long v0, v0

    .line 37
    invoke-static {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    add-int/2addr p3, v0

    .line 42
    add-int/lit8 p0, p0, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 46
    .line 47
    .line 48
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 49
    .line 50
    if-ge v2, p0, :cond_5

    .line 51
    .line 52
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->o(I)V

    .line 57
    .line 58
    .line 59
    add-int/lit8 v2, v2, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 63
    .line 64
    if-ge v2, p3, :cond_5

    .line 65
    .line 66
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 67
    .line 68
    .line 69
    move-result p3

    .line 70
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 71
    .line 72
    .line 73
    add-int/lit8 v2, v2, 0x1

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    if-eqz p3, :cond_4

    .line 77
    .line 78
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 79
    .line 80
    .line 81
    move p0, v2

    .line 82
    move p3, p0

    .line 83
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-ge p0, v0, :cond_3

    .line 88
    .line 89
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    check-cast v0, Ljava/lang/Integer;

    .line 94
    .line 95
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    int-to-long v0, v0

    .line 100
    invoke-static {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    add-int/2addr p3, v0

    .line 105
    add-int/lit8 p0, p0, 0x1

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 109
    .line 110
    .line 111
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-ge v2, p0, :cond_5

    .line 116
    .line 117
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Ljava/lang/Integer;

    .line 122
    .line 123
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->o(I)V

    .line 128
    .line 129
    .line 130
    add-int/lit8 v2, v2, 0x1

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 134
    .line 135
    .line 136
    move-result p3

    .line 137
    if-ge v2, p3, :cond_5

    .line 138
    .line 139
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p3

    .line 143
    check-cast p3, Ljava/lang/Integer;

    .line 144
    .line 145
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 146
    .line 147
    .line 148
    move-result p3

    .line 149
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 150
    .line 151
    .line 152
    add-int/lit8 v2, v2, 0x1

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_5
    return-void
.end method

.method public static u(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 33
    .line 34
    .line 35
    add-int/lit8 p3, p3, 0x4

    .line 36
    .line 37
    add-int/lit8 p0, p0, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 41
    .line 42
    .line 43
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 44
    .line 45
    if-ge v2, p0, :cond_5

    .line 46
    .line 47
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->k(I)V

    .line 52
    .line 53
    .line 54
    add-int/lit8 v2, v2, 0x1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 58
    .line 59
    if-ge v2, p3, :cond_5

    .line 60
    .line 61
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 62
    .line 63
    .line 64
    move-result p3

    .line 65
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v2, v2, 0x1

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_2
    if-eqz p3, :cond_4

    .line 72
    .line 73
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 74
    .line 75
    .line 76
    move p0, v2

    .line 77
    move p3, p0

    .line 78
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-ge p0, v0, :cond_3

    .line 83
    .line 84
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    add-int/lit8 p3, p3, 0x4

    .line 94
    .line 95
    add-int/lit8 p0, p0, 0x1

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 99
    .line 100
    .line 101
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-ge v2, p0, :cond_5

    .line 106
    .line 107
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    check-cast p0, Ljava/lang/Integer;

    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->k(I)V

    .line 118
    .line 119
    .line 120
    add-int/lit8 v2, v2, 0x1

    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 124
    .line 125
    .line 126
    move-result p3

    .line 127
    if-ge v2, p3, :cond_5

    .line 128
    .line 129
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p3

    .line 133
    check-cast p3, Ljava/lang/Integer;

    .line 134
    .line 135
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 136
    .line 137
    .line 138
    move-result p3

    .line 139
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 140
    .line 141
    .line 142
    add-int/lit8 v2, v2, 0x1

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_5
    return-void
.end method

.method public static v(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 22
    .line 23
    .line 24
    move p0, v0

    .line 25
    move p3, p0

    .line 26
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ge p0, v1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Long;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    add-int/lit8 p3, p3, 0x8

    .line 42
    .line 43
    add-int/lit8 p0, p0, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 47
    .line 48
    .line 49
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-ge v0, p0, :cond_3

    .line 54
    .line 55
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Ljava/lang/Long;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 62
    .line 63
    .line 64
    move-result-wide v1

    .line 65
    invoke-virtual {p2, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->m(J)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v0, v0, 0x1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 72
    .line 73
    .line 74
    move-result p3

    .line 75
    if-ge v0, p3, :cond_3

    .line 76
    .line 77
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p3

    .line 81
    check-cast p3, Ljava/lang/Long;

    .line 82
    .line 83
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 84
    .line 85
    .line 86
    move-result-wide v1

    .line 87
    invoke-virtual {p2, p0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->l(IJ)V

    .line 88
    .line 89
    .line 90
    add-int/lit8 v0, v0, 0x1

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 94
    .line 95
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_3
    return-void
.end method

.method public static w(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->g(I)V

    .line 33
    .line 34
    .line 35
    iget-object v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e:[F

    .line 36
    .line 37
    aget v0, v0, p0

    .line 38
    .line 39
    add-int/lit8 p3, p3, 0x4

    .line 40
    .line 41
    add-int/lit8 p0, p0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 45
    .line 46
    .line 47
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 48
    .line 49
    if-ge v2, p0, :cond_5

    .line 50
    .line 51
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->g(I)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e:[F

    .line 55
    .line 56
    aget p0, p0, v2

    .line 57
    .line 58
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->k(I)V

    .line 63
    .line 64
    .line 65
    add-int/lit8 v2, v2, 0x1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 69
    .line 70
    if-ge v2, p3, :cond_5

    .line 71
    .line 72
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->g(I)V

    .line 73
    .line 74
    .line 75
    iget-object p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e:[F

    .line 76
    .line 77
    aget p3, p3, v2

    .line 78
    .line 79
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 80
    .line 81
    .line 82
    move-result p3

    .line 83
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 84
    .line 85
    .line 86
    add-int/lit8 v2, v2, 0x1

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_2
    if-eqz p3, :cond_4

    .line 90
    .line 91
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 92
    .line 93
    .line 94
    move p0, v2

    .line 95
    move p3, p0

    .line 96
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-ge p0, v0, :cond_3

    .line 101
    .line 102
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    check-cast v0, Ljava/lang/Float;

    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    add-int/lit8 p3, p3, 0x4

    .line 112
    .line 113
    add-int/lit8 p0, p0, 0x1

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 117
    .line 118
    .line 119
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    if-ge v2, p0, :cond_5

    .line 124
    .line 125
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    check-cast p0, Ljava/lang/Float;

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->k(I)V

    .line 140
    .line 141
    .line 142
    add-int/lit8 v2, v2, 0x1

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 146
    .line 147
    .line 148
    move-result p3

    .line 149
    if-ge v2, p3, :cond_5

    .line 150
    .line 151
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p3

    .line 155
    check-cast p3, Ljava/lang/Float;

    .line 156
    .line 157
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 158
    .line 159
    .line 160
    move-result p3

    .line 161
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 162
    .line 163
    .line 164
    move-result p3

    .line 165
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 166
    .line 167
    .line 168
    add-int/lit8 v2, v2, 0x1

    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_5
    return-void
.end method

.method public static x(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    int-to-long v0, v0

    .line 37
    invoke-static {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    add-int/2addr p3, v0

    .line 42
    add-int/lit8 p0, p0, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 46
    .line 47
    .line 48
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 49
    .line 50
    if-ge v2, p0, :cond_5

    .line 51
    .line 52
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->o(I)V

    .line 57
    .line 58
    .line 59
    add-int/lit8 v2, v2, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 63
    .line 64
    if-ge v2, p3, :cond_5

    .line 65
    .line 66
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 67
    .line 68
    .line 69
    move-result p3

    .line 70
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 71
    .line 72
    .line 73
    add-int/lit8 v2, v2, 0x1

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    if-eqz p3, :cond_4

    .line 77
    .line 78
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 79
    .line 80
    .line 81
    move p0, v2

    .line 82
    move p3, p0

    .line 83
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-ge p0, v0, :cond_3

    .line 88
    .line 89
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    check-cast v0, Ljava/lang/Integer;

    .line 94
    .line 95
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    int-to-long v0, v0

    .line 100
    invoke-static {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    add-int/2addr p3, v0

    .line 105
    add-int/lit8 p0, p0, 0x1

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 109
    .line 110
    .line 111
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-ge v2, p0, :cond_5

    .line 116
    .line 117
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Ljava/lang/Integer;

    .line 122
    .line 123
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->o(I)V

    .line 128
    .line 129
    .line 130
    add-int/lit8 v2, v2, 0x1

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 134
    .line 135
    .line 136
    move-result p3

    .line 137
    if-ge v2, p3, :cond_5

    .line 138
    .line 139
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p3

    .line 143
    check-cast p3, Ljava/lang/Integer;

    .line 144
    .line 145
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 146
    .line 147
    .line 148
    move-result p3

    .line 149
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->n(II)V

    .line 150
    .line 151
    .line 152
    add-int/lit8 v2, v2, 0x1

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_5
    return-void
.end method

.method public static y(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u1;

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 22
    .line 23
    .line 24
    move p0, v0

    .line 25
    move p3, p0

    .line 26
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ge p0, v1, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Long;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 39
    .line 40
    .line 41
    move-result-wide v1

    .line 42
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->f(J)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    add-int/2addr p3, v1

    .line 47
    add-int/lit8 p0, p0, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 51
    .line 52
    .line 53
    :goto_1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-ge v0, p0, :cond_3

    .line 58
    .line 59
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Ljava/lang/Long;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 66
    .line 67
    .line 68
    move-result-wide v1

    .line 69
    invoke-virtual {p2, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->u(J)V

    .line 70
    .line 71
    .line 72
    add-int/lit8 v0, v0, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    if-ge v0, p3, :cond_3

    .line 80
    .line 81
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p3

    .line 85
    check-cast p3, Ljava/lang/Long;

    .line 86
    .line 87
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 88
    .line 89
    .line 90
    move-result-wide v1

    .line 91
    invoke-virtual {p2, p0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->t(IJ)V

    .line 92
    .line 93
    .line 94
    add-int/lit8 v0, v0, 0x1

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 98
    .line 99
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_3
    return-void
.end method

.method public static z(ILjava/util/List;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    iget-object p2, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;

    .line 12
    .line 13
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    if-eqz p3, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 24
    .line 25
    .line 26
    move p0, v2

    .line 27
    move p3, p0

    .line 28
    :goto_0
    iget v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 29
    .line 30
    if-ge p0, v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 33
    .line 34
    .line 35
    add-int/lit8 p3, p3, 0x4

    .line 36
    .line 37
    add-int/lit8 p0, p0, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 41
    .line 42
    .line 43
    :goto_1
    iget p0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 44
    .line 45
    if-ge v2, p0, :cond_5

    .line 46
    .line 47
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->k(I)V

    .line 52
    .line 53
    .line 54
    add-int/lit8 v2, v2, 0x1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    :goto_2
    iget p3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->f:I

    .line 58
    .line 59
    if-ge v2, p3, :cond_5

    .line 60
    .line 61
    invoke-virtual {p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->e(I)I

    .line 62
    .line 63
    .line 64
    move-result p3

    .line 65
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v2, v2, 0x1

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_2
    if-eqz p3, :cond_4

    .line 72
    .line 73
    invoke-virtual {p2, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->q(II)V

    .line 74
    .line 75
    .line 76
    move p0, v2

    .line 77
    move p3, p0

    .line 78
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-ge p0, v0, :cond_3

    .line 83
    .line 84
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    add-int/lit8 p3, p3, 0x4

    .line 94
    .line 95
    add-int/lit8 p0, p0, 0x1

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_3
    invoke-virtual {p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->s(I)V

    .line 99
    .line 100
    .line 101
    :goto_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-ge v2, p0, :cond_5

    .line 106
    .line 107
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    check-cast p0, Ljava/lang/Integer;

    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    invoke-virtual {p2, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->k(I)V

    .line 118
    .line 119
    .line 120
    add-int/lit8 v2, v2, 0x1

    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_4
    :goto_5
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 124
    .line 125
    .line 126
    move-result p3

    .line 127
    if-ge v2, p3, :cond_5

    .line 128
    .line 129
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p3

    .line 133
    check-cast p3, Ljava/lang/Integer;

    .line 134
    .line 135
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 136
    .line 137
    .line 138
    move-result p3

    .line 139
    invoke-virtual {p2, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->j(II)V

    .line 140
    .line 141
    .line 142
    add-int/lit8 v2, v2, 0x1

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_5
    return-void
.end method
