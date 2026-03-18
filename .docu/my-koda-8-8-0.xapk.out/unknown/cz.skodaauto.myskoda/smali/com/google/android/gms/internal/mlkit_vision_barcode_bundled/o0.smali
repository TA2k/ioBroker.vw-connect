.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public e:I

.field public final f:I

.field public final synthetic g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p0;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 6
    .line 7
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->e:I

    .line 8
    .line 9
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->i()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    iput p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->f:I

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a()B
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->e:I

    .line 2
    .line 3
    iget v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->f:I

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    add-int/lit8 v1, v0, 0x1

    .line 8
    .line 9
    iput v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->e:I

    .line 10
    .line 11
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e(I)B

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->e:I

    .line 2
    .line 3
    iget p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o0;->f:I

    .line 4
    .line 5
    if-ge v0, p0, :cond_0

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
