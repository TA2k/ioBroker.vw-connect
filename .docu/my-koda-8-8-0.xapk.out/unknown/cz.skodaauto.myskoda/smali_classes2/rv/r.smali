.class public final Lrv/r;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lrv/r;


# instance fields
.field private zzd:I

.field private zze:Ljava/lang/String;

.field private zzf:Ljava/lang/String;

.field private zzg:Ljava/lang/String;

.field private zzh:Ljava/lang/String;

.field private zzi:Ljava/lang/String;

.field private zzj:Ljava/lang/String;

.field private zzk:Ljava/lang/String;

.field private zzl:Ljava/lang/String;

.field private zzm:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrv/r;

    .line 2
    .line 3
    invoke-direct {v0}, Lrv/r;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lrv/r;->zzb:Lrv/r;

    .line 7
    .line 8
    const-class v1, Lrv/r;

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
    iput-object v0, p0, Lrv/r;->zze:Ljava/lang/String;

    .line 7
    .line 8
    iput-object v0, p0, Lrv/r;->zzf:Ljava/lang/String;

    .line 9
    .line 10
    iput-object v0, p0, Lrv/r;->zzg:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v0, p0, Lrv/r;->zzh:Ljava/lang/String;

    .line 13
    .line 14
    iput-object v0, p0, Lrv/r;->zzi:Ljava/lang/String;

    .line 15
    .line 16
    iput-object v0, p0, Lrv/r;->zzj:Ljava/lang/String;

    .line 17
    .line 18
    iput-object v0, p0, Lrv/r;->zzk:Ljava/lang/String;

    .line 19
    .line 20
    iput-object v0, p0, Lrv/r;->zzl:Ljava/lang/String;

    .line 21
    .line 22
    iput-object v0, p0, Lrv/r;->zzm:Ljava/lang/String;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 10

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
    sget-object p0, Lrv/r;->zzb:Lrv/r;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    new-instance p0, Lfr/k;

    .line 23
    .line 24
    sget-object p1, Lrv/r;->zzb:Lrv/r;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lrv/r;

    .line 31
    .line 32
    invoke-direct {p0}, Lrv/r;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    const-string v8, "zzl"

    .line 37
    .line 38
    const-string v9, "zzm"

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
    filled-new-array/range {v0 .. v9}, [Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    sget-object p1, Lrv/r;->zzb:Lrv/r;

    .line 61
    .line 62
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 63
    .line 64
    const-string v0, "\u0004\t\u0000\u0001\u0001\t\t\u0000\u0000\u0000\u0001\u1008\u0000\u0002\u1008\u0001\u0003\u1008\u0002\u0004\u1008\u0003\u0005\u1008\u0004\u0006\u1008\u0005\u0007\u1008\u0006\u0008\u1008\u0007\t\u1008\u0008"

    .line 65
    .line 66
    invoke-direct {p2, p1, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    return-object p2

    .line 70
    :cond_4
    const/4 p0, 0x1

    .line 71
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0
.end method
