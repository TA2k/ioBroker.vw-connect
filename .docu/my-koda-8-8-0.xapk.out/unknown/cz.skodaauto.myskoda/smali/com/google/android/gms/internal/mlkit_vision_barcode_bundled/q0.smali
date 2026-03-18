.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:I

.field public final h:I


# direct methods
.method public constructor <init>([BII)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;-><init>([B)V

    .line 2
    .line 3
    .line 4
    add-int v0, p2, p3

    .line 5
    .line 6
    array-length p1, p1

    .line 7
    invoke-static {p2, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->v(III)I

    .line 8
    .line 9
    .line 10
    iput p2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->g:I

    .line 11
    .line 12
    iput p3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->h:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final A()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final c(I)B
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->h:I

    .line 2
    .line 3
    invoke-static {p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->z(II)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->g:I

    .line 7
    .line 8
    add-int/2addr v0, p1

    .line 9
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->f:[B

    .line 10
    .line 11
    aget-byte p0, p0, v0

    .line 12
    .line 13
    return p0
.end method

.method public final e(I)B
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->f:[B

    .line 2
    .line 3
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->g:I

    .line 4
    .line 5
    add-int/2addr p0, p1

    .line 6
    aget-byte p0, v0, p0

    .line 7
    .line 8
    return p0
.end method

.method public final i()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->h:I

    .line 2
    .line 3
    return p0
.end method

.method public final k(I[BII)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;->f:[B

    .line 2
    .line 3
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q0;->g:I

    .line 4
    .line 5
    add-int/2addr p0, p1

    .line 6
    invoke-static {v0, p0, p2, p3, p4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 7
    .line 8
    .line 9
    return-void
.end method
