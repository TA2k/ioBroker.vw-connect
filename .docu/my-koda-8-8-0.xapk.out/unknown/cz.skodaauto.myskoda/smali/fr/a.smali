.class public final Lfr/a;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lfr/a;


# instance fields
.field private zzd:I

.field private zze:Lfr/i;

.field private zzf:Lfr/c;

.field private zzg:Lfr/m;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfr/a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lfr/a;->zzb:Lfr/a;

    .line 7
    .line 8
    const-class v1, Lfr/a;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->h(Ljava/lang/Class;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static n()Lfr/j;
    .locals 1

    .line 1
    sget-object v0, Lfr/a;->zzb:Lfr/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->d()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lfr/j;

    .line 8
    .line 9
    return-object v0
.end method

.method public static synthetic o(Lfr/a;Lfr/i;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lfr/a;->zze:Lfr/i;

    .line 2
    .line 3
    iget p1, p0, Lfr/a;->zzd:I

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x1

    .line 6
    .line 7
    iput p1, p0, Lfr/a;->zzd:I

    .line 8
    .line 9
    return-void
.end method

.method public static synthetic p(Lfr/a;Lfr/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lfr/a;->zzf:Lfr/c;

    .line 2
    .line 3
    iget p1, p0, Lfr/a;->zzd:I

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x2

    .line 6
    .line 7
    iput p1, p0, Lfr/a;->zzd:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 1

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
    sget-object p0, Lfr/a;->zzb:Lfr/a;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    new-instance p0, Lfr/j;

    .line 23
    .line 24
    sget-object p1, Lfr/a;->zzb:Lfr/a;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lfr/a;

    .line 31
    .line 32
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    const-string p0, "zzf"

    .line 37
    .line 38
    const-string p1, "zzg"

    .line 39
    .line 40
    const-string p2, "zzd"

    .line 41
    .line 42
    const-string v0, "zze"

    .line 43
    .line 44
    filled-new-array {p2, v0, p0, p1}, [Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    sget-object p1, Lfr/a;->zzb:Lfr/a;

    .line 49
    .line 50
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 51
    .line 52
    const-string v0, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u1009\u0000\u0002\u1009\u0001\u0003\u1009\u0002"

    .line 53
    .line 54
    invoke-direct {p2, p1, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    return-object p2

    .line 58
    :cond_4
    const/4 p0, 0x1

    .line 59
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0
.end method
