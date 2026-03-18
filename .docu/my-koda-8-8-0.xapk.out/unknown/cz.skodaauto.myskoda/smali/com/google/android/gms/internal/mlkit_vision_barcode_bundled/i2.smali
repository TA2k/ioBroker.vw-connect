.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

.field public f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k2;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;-><init>(I)V

    .line 3
    .line 4
    .line 5
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()B
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;->a()B

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;

    .line 10
    .line 11
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iput-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;

    .line 22
    .line 23
    :cond_0
    return v0

    .line 24
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

.method public final b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->hasNext()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->a()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;

    .line 14
    .line 15
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V

    .line 16
    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return-object p0
.end method

.method public final hasNext()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i2;->f:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method
