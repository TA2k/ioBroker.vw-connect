.class public final Lfr/i;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lfr/i;


# instance fields
.field private zzd:I

.field private zze:Ljava/lang/String;

.field private zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

.field private zzg:I

.field private zzh:F

.field private zzi:F

.field private zzj:Lfr/g;

.field private zzk:I

.field private zzl:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a3;

.field private zzm:I

.field private zzn:I

.field private zzo:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfr/i;

    .line 2
    .line 3
    invoke-direct {v0}, Lfr/i;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lfr/i;->zzb:Lfr/i;

    .line 7
    .line 8
    const-class v1, Lfr/i;

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
    const-string v0, ""

    .line 5
    .line 6
    iput-object v0, p0, Lfr/i;->zze:Ljava/lang/String;

    .line 7
    .line 8
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 9
    .line 10
    iput-object v0, p0, Lfr/i;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 11
    .line 12
    const/16 v0, 0xa

    .line 13
    .line 14
    iput v0, p0, Lfr/i;->zzg:I

    .line 15
    .line 16
    const/high16 v0, 0x3f000000    # 0.5f

    .line 17
    .line 18
    iput v0, p0, Lfr/i;->zzh:F

    .line 19
    .line 20
    const v0, 0x3d4ccccd    # 0.05f

    .line 21
    .line 22
    .line 23
    iput v0, p0, Lfr/i;->zzi:F

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    iput v0, p0, Lfr/i;->zzk:I

    .line 27
    .line 28
    const/16 v0, 0x140

    .line 29
    .line 30
    iput v0, p0, Lfr/i;->zzm:I

    .line 31
    .line 32
    const/4 v0, 0x4

    .line 33
    iput v0, p0, Lfr/i;->zzn:I

    .line 34
    .line 35
    const/4 v0, 0x2

    .line 36
    iput v0, p0, Lfr/i;->zzo:I

    .line 37
    .line 38
    return-void
.end method

.method public static n()Lfr/h;
    .locals 1

    .line 1
    sget-object v0, Lfr/i;->zzb:Lfr/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->d()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lfr/h;

    .line 8
    .line 9
    return-object v0
.end method

.method public static synthetic o(Lfr/i;Lfr/g;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lfr/i;->zzj:Lfr/g;

    .line 2
    .line 3
    iget p1, p0, Lfr/i;->zzd:I

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x20

    .line 6
    .line 7
    iput p1, p0, Lfr/i;->zzd:I

    .line 8
    .line 9
    return-void
.end method

.method public static synthetic p(Lfr/i;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lfr/i;->zzd:I

    .line 5
    .line 6
    or-int/lit8 v0, v0, 0x2

    .line 7
    .line 8
    iput v0, p0, Lfr/i;->zzd:I

    .line 9
    .line 10
    iput-object p1, p0, Lfr/i;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 12

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
    sget-object p0, Lfr/i;->zzb:Lfr/i;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    new-instance p0, Lfr/h;

    .line 23
    .line 24
    sget-object p1, Lfr/i;->zzb:Lfr/i;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lfr/i;

    .line 31
    .line 32
    invoke-direct {p0}, Lfr/i;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    const-string v10, "zzn"

    .line 37
    .line 38
    const-string v11, "zzo"

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
    const-string v5, "zzi"

    .line 51
    .line 52
    const-string v6, "zzj"

    .line 53
    .line 54
    const-string v7, "zzk"

    .line 55
    .line 56
    const-string v8, "zzl"

    .line 57
    .line 58
    const-string v9, "zzm"

    .line 59
    .line 60
    filled-new-array/range {v0 .. v11}, [Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    sget-object p1, Lfr/i;->zzb:Lfr/i;

    .line 65
    .line 66
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 67
    .line 68
    const-string v0, "\u0004\u000b\u0000\u0001\u0001\u000c\u000b\u0000\u0000\u0000\u0001\u1008\u0000\u0002\u100a\u0001\u0003\u100b\u0002\u0004\u1001\u0003\u0005\u1001\u0004\u0006\u1009\u0005\u0008\u1004\u0006\t\u1009\u0007\n\u1004\u0008\u000b\u1004\t\u000c\u1004\n"

    .line 69
    .line 70
    invoke-direct {p2, p1, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    return-object p2

    .line 74
    :cond_4
    const/4 p0, 0x1

    .line 75
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0
.end method
