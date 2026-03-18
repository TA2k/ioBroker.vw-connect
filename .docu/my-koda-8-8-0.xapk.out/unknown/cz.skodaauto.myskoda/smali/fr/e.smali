.class public final Lfr/e;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lfr/e;


# instance fields
.field private zzd:I

.field private zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

.field private zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

.field private zzg:I

.field private zzh:I

.field private zzi:I

.field private zzj:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfr/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lfr/e;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lfr/e;->zzb:Lfr/e;

    .line 7
    .line 8
    const-class v1, Lfr/e;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->h(Ljava/lang/Class;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 5
    .line 6
    iput-object v0, p0, Lfr/e;->zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 7
    .line 8
    iput-object v0, p0, Lfr/e;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 9
    .line 10
    return-void
.end method

.method public static n()Lfr/d;
    .locals 1

    .line 1
    sget-object v0, Lfr/e;->zzb:Lfr/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->d()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lfr/d;

    .line 8
    .line 9
    return-object v0
.end method

.method public static synthetic o(Lfr/e;I)V
    .locals 1

    .line 1
    iget v0, p0, Lfr/e;->zzd:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x2

    .line 4
    .line 5
    iput v0, p0, Lfr/e;->zzd:I

    .line 6
    .line 7
    iput p1, p0, Lfr/e;->zzh:I

    .line 8
    .line 9
    return-void
.end method

.method public static p(Lfr/e;F)V
    .locals 4

    .line 1
    iget-object v0, p0, Lfr/e;->zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_2

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    const/16 v1, 0xa

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    add-int/2addr v1, v1

    .line 20
    :goto_0
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 21
    .line 22
    iget v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 23
    .line 24
    if-lt v1, v2, :cond_1

    .line 25
    .line 26
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 27
    .line 28
    iget-object v3, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e:[F

    .line 29
    .line 30
    invoke-static {v3, v1}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    invoke-direct {v2, v1, v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;-><init>([FIZ)V

    .line 38
    .line 39
    .line 40
    iput-object v2, p0, Lfr/e;->zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    :goto_1
    iget-object p0, p0, Lfr/e;->zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 50
    .line 51
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e(F)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public static q(Lfr/e;F)V
    .locals 4

    .line 1
    iget-object v0, p0, Lfr/e;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k0;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_2

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    const/16 v1, 0xa

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    add-int/2addr v1, v1

    .line 20
    :goto_0
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 21
    .line 22
    iget v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 23
    .line 24
    if-lt v1, v2, :cond_1

    .line 25
    .line 26
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 27
    .line 28
    iget-object v3, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e:[F

    .line 29
    .line 30
    invoke-static {v3, v1}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->f:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    invoke-direct {v2, v1, v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;-><init>([FIZ)V

    .line 38
    .line 39
    .line 40
    iput-object v2, p0, Lfr/e;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    :goto_1
    iget-object p0, p0, Lfr/e;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k1;

    .line 50
    .line 51
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a1;->e(F)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public static synthetic r(Lfr/e;I)V
    .locals 1

    .line 1
    iget v0, p0, Lfr/e;->zzd:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lfr/e;->zzd:I

    .line 6
    .line 7
    iput p1, p0, Lfr/e;->zzg:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 7

    .line 1
    add-int/lit8 p1, p1, -0x1

    .line 2
    .line 3
    if-eqz p1, :cond_4

    .line 4
    .line 5
    const/4 p0, 0x2

    .line 6
    if-eq p1, p0, :cond_3

    .line 7
    .line 8
    const/4 p0, 0x3

    .line 9
    if-eq p1, p0, :cond_2

    .line 10
    .line 11
    const/4 p0, 0x4

    .line 12
    if-eq p1, p0, :cond_1

    .line 13
    .line 14
    const/4 p0, 0x5

    .line 15
    if-eq p1, p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Lfr/e;->zzb:Lfr/e;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    new-instance p0, Lfr/d;

    .line 23
    .line 24
    sget-object p1, Lfr/e;->zzb:Lfr/e;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lfr/e;

    .line 31
    .line 32
    invoke-direct {p0}, Lfr/e;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    const-string v5, "zzi"

    .line 37
    .line 38
    const-string v6, "zzj"

    .line 39
    .line 40
    const-string v0, "zzd"

    .line 41
    .line 42
    const-string v1, "zze"

    .line 43
    .line 44
    const-string v2, "zzf"

    .line 45
    .line 46
    const-string v3, "zzg"

    .line 47
    .line 48
    const-string v4, "zzh"

    .line 49
    .line 50
    filled-new-array/range {v0 .. v6}, [Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    sget-object p1, Lfr/e;->zzb:Lfr/e;

    .line 55
    .line 56
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 57
    .line 58
    const-string v0, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0002\u0000\u0001\u0013\u0002\u0013\u0003\u100b\u0000\u0004\u100b\u0001\u0005\u100b\u0002\u0006\u100b\u0003"

    .line 59
    .line 60
    invoke-direct {p2, p1, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    return-object p2

    .line 64
    :cond_4
    const/4 p0, 0x1

    .line 65
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method
