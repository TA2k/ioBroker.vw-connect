.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final k:[I


# instance fields
.field public final f:I

.field public final g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

.field public final h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

.field public final i:I

.field public final j:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x2f

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->k:[I

    .line 9
    .line 10
    return-void

    .line 11
    :array_0
    .array-data 4
        0x1
        0x1
        0x2
        0x3
        0x5
        0x8
        0xd
        0x15
        0x22
        0x37
        0x59
        0x90
        0xe9
        0x179
        0x262
        0x3db
        0x63d
        0xa18
        0x1055
        0x1a6d
        0x2ac2
        0x452f
        0x6ff1
        0xb520
        0x12511
        0x1da31
        0x2ff42
        0x4d973
        0x7d8b5
        0xcb228
        0x148add
        0x213d05
        0x35c7e2
        0x5704e7
        0x8cccc9
        0xe3d1b0
        0x1709e79
        0x2547029
        0x3c50ea2
        0x6197ecb
        0x9de8d6d
        0xff80c38
        0x19d699a5
        0x29cea5dd
        0x43a53f82
        0x6d73e55f
        0x7fffffff
    .end array-data
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 7
    .line 8
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 13
    .line 14
    invoke-virtual {p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    add-int/2addr v1, v0

    .line 19
    iput v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->f:I

    .line 20
    .line 21
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-virtual {p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->m()I

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    invoke-static {p1, p2}, Ljava/lang/Math;->max(II)I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    add-int/lit8 p1, p1, 0x1

    .line 34
    .line 35
    iput p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->j:I

    .line 36
    .line 37
    return-void
.end method

.method public static A(I)I
    .locals 1

    .line 1
    const/16 v0, 0x2f

    .line 2
    .line 3
    if-lt p0, v0, :cond_0

    .line 4
    .line 5
    const p0, 0x7fffffff

    .line 6
    .line 7
    .line 8
    return p0

    .line 9
    :cond_0
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->k:[I

    .line 10
    .line 11
    aget p0, v0, p0

    .line 12
    .line 13
    return p0
.end method


# virtual methods
.method public final c(I)B
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->f:I

    .line 2
    .line 3
    invoke-static {p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->z(II)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->e(I)B

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final e(I)B
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 2
    .line 3
    if-ge p1, v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e(I)B

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 13
    .line 14
    sub-int/2addr p1, v0

    .line 15
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e(I)B

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 11

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_3

    .line 4
    :cond_0
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto :goto_2

    .line 10
    :cond_1
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 11
    .line 12
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->f:I

    .line 17
    .line 18
    if-eq v2, v0, :cond_2

    .line 19
    .line 20
    goto :goto_2

    .line 21
    :cond_2
    if-nez v2, :cond_3

    .line 22
    .line 23
    goto :goto_3

    .line 24
    :cond_3
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->d:I

    .line 25
    .line 26
    iget v3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->d:I

    .line 27
    .line 28
    if-eqz v0, :cond_4

    .line 29
    .line 30
    if-eqz v3, :cond_4

    .line 31
    .line 32
    if-ne v0, v3, :cond_6

    .line 33
    .line 34
    :cond_4
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 44
    .line 45
    invoke-direct {v3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    move v4, v1

    .line 53
    move v5, v4

    .line 54
    move v6, v5

    .line 55
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->i()I

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    sub-int/2addr v7, v4

    .line 60
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->i()I

    .line 61
    .line 62
    .line 63
    move-result v8

    .line 64
    sub-int/2addr v8, v5

    .line 65
    invoke-static {v7, v8}, Ljava/lang/Math;->min(II)I

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    if-nez v4, :cond_5

    .line 70
    .line 71
    invoke-virtual {p0, p1, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->B(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;II)Z

    .line 72
    .line 73
    .line 74
    move-result v10

    .line 75
    goto :goto_1

    .line 76
    :cond_5
    invoke-virtual {p1, p0, v4, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->B(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;II)Z

    .line 77
    .line 78
    .line 79
    move-result v10

    .line 80
    :goto_1
    if-nez v10, :cond_7

    .line 81
    .line 82
    :cond_6
    :goto_2
    return v1

    .line 83
    :cond_7
    add-int/2addr v6, v9

    .line 84
    if-lt v6, v2, :cond_9

    .line 85
    .line 86
    if-ne v6, v2, :cond_8

    .line 87
    .line 88
    :goto_3
    const/4 p0, 0x1

    .line 89
    return p0

    .line 90
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_9
    if-ne v9, v7, :cond_a

    .line 97
    .line 98
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    move v4, v1

    .line 103
    goto :goto_4

    .line 104
    :cond_a
    add-int/2addr v4, v9

    .line 105
    :goto_4
    if-ne v9, v8, :cond_b

    .line 106
    .line 107
    invoke-virtual {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    move v5, v1

    .line 112
    goto :goto_0

    .line 113
    :cond_b
    add-int/2addr v5, v9

    .line 114
    goto :goto_0
.end method

.method public final i()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final synthetic iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final k(I[BII)V
    .locals 3

    .line 1
    add-int v0, p1, p4

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 4
    .line 5
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 6
    .line 7
    if-gt v0, v2, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1, p1, p2, p3, p4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 14
    .line 15
    if-lt p1, v2, :cond_1

    .line 16
    .line 17
    sub-int/2addr p1, v2

    .line 18
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    sub-int/2addr v2, p1

    .line 23
    invoke-virtual {v1, p1, p2, p3, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 24
    .line 25
    .line 26
    add-int/2addr p3, v2

    .line 27
    sub-int/2addr p4, v2

    .line 28
    const/4 p1, 0x0

    .line 29
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->k(I[BII)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->j:I

    .line 2
    .line 3
    return p0
.end method

.method public final n()Z
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->f:I

    .line 2
    .line 3
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->j:I

    .line 4
    .line 5
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->A(I)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-lt v0, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final o(III)I
    .locals 3

    .line 1
    add-int v0, p2, p3

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 4
    .line 5
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 6
    .line 7
    if-gt v0, v2, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->o(III)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 15
    .line 16
    if-lt p2, v2, :cond_1

    .line 17
    .line 18
    sub-int/2addr p2, v2

    .line 19
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->o(III)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_1
    sub-int/2addr v2, p2

    .line 25
    invoke-virtual {v1, p1, p2, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->o(III)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    const/4 p2, 0x0

    .line 30
    sub-int/2addr p3, v2

    .line 31
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->o(III)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public final p(III)I
    .locals 3

    .line 1
    add-int v0, p2, p3

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 4
    .line 5
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 6
    .line 7
    if-gt v0, v2, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->p(III)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 15
    .line 16
    if-lt p2, v2, :cond_1

    .line 17
    .line 18
    sub-int/2addr p2, v2

    .line 19
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->p(III)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_1
    sub-int/2addr v2, p2

    .line 25
    invoke-virtual {v1, p1, p2, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->p(III)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    const/4 p2, 0x0

    .line 30
    sub-int/2addr p3, v2

    .line 31
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->p(III)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public final r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->f:I

    .line 2
    .line 3
    invoke-static {p1, p2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    if-ne v1, v0, :cond_1

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 16
    .line 17
    iget v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 18
    .line 19
    if-gt p2, v1, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_2
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 27
    .line 28
    if-lt p1, v1, :cond_3

    .line 29
    .line 30
    sub-int/2addr p2, v1

    .line 31
    sub-int/2addr p1, v1

    .line 32
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    invoke-virtual {v0, p1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    const/4 v0, 0x0

    .line 46
    sub-int/2addr p2, v1

    .line 47
    invoke-virtual {p0, v0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->r(II)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;

    .line 52
    .line 53
    invoke-direct {p2, p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 54
    .line 55
    .line 56
    return-object p2
.end method

.method public final s(Ljava/nio/charset/Charset;)Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->b:[B

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-array v2, v1, [B

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-virtual {p0, v3, v2, v3, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->k(I[BII)V

    .line 16
    .line 17
    .line 18
    move-object p0, v2

    .line 19
    :goto_0
    invoke-direct {v0, p0, p1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final t(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->t(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->t(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final u()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->i:I

    .line 5
    .line 6
    invoke-virtual {v0, v1, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->p(III)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;->h:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-virtual {p0, v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->p(III)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    return v1
.end method

.method public final w()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
