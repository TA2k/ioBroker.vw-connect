.class public final Lrv/o;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lrv/o;


# instance fields
.field private zzd:I

.field private zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h0;

.field private zzf:Ljava/lang/String;

.field private zzg:Ljava/lang/String;

.field private zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzi:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzj:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzk:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzl:Ljava/lang/String;

.field private zzm:B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrv/o;

    .line 2
    .line 3
    invoke-direct {v0}, Lrv/o;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lrv/o;->zzb:Lrv/o;

    .line 7
    .line 8
    const-class v1, Lrv/o;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->h(Ljava/lang/Class;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    iput-byte v0, p0, Lrv/o;->zzm:B

    .line 6
    .line 7
    const-string v0, ""

    .line 8
    .line 9
    iput-object v0, p0, Lrv/o;->zzf:Ljava/lang/String;

    .line 10
    .line 11
    iput-object v0, p0, Lrv/o;->zzg:Ljava/lang/String;

    .line 12
    .line 13
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;

    .line 14
    .line 15
    iput-object v1, p0, Lrv/o;->zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 16
    .line 17
    iput-object v1, p0, Lrv/o;->zzi:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 18
    .line 19
    iput-object v1, p0, Lrv/o;->zzj:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 20
    .line 21
    iput-object v1, p0, Lrv/o;->zzk:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 22
    .line 23
    iput-object v0, p0, Lrv/o;->zzl:Ljava/lang/String;

    .line 24
    .line 25
    return-void
.end method

.method public static o()Lrv/o;
    .locals 1

    .line 1
    sget-object v0, Lrv/o;->zzb:Lrv/o;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 12

    .line 1
    add-int/lit8 p1, p1, -0x1

    .line 2
    .line 3
    if-eqz p1, :cond_5

    .line 4
    .line 5
    const/4 v0, 0x2

    .line 6
    if-eq p1, v0, :cond_4

    .line 7
    .line 8
    const/4 v0, 0x3

    .line 9
    if-eq p1, v0, :cond_3

    .line 10
    .line 11
    const/4 v0, 0x4

    .line 12
    if-eq p1, v0, :cond_2

    .line 13
    .line 14
    const/4 v0, 0x5

    .line 15
    if-eq p1, v0, :cond_1

    .line 16
    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p1, 0x1

    .line 22
    :goto_0
    iput-byte p1, p0, Lrv/o;->zzm:B

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    return-object p0

    .line 26
    :cond_1
    sget-object p0, Lrv/o;->zzb:Lrv/o;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    new-instance p0, Lfr/k;

    .line 30
    .line 31
    sget-object p1, Lrv/o;->zzb:Lrv/o;

    .line 32
    .line 33
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 34
    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_3
    new-instance p0, Lrv/o;

    .line 38
    .line 39
    invoke-direct {p0}, Lrv/o;-><init>()V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_4
    const-class v10, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g0;

    .line 44
    .line 45
    const-string v11, "zzl"

    .line 46
    .line 47
    const-string v0, "zzd"

    .line 48
    .line 49
    const-string v1, "zze"

    .line 50
    .line 51
    const-string v2, "zzf"

    .line 52
    .line 53
    const-string v3, "zzg"

    .line 54
    .line 55
    const-string v4, "zzh"

    .line 56
    .line 57
    const-class v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i0;

    .line 58
    .line 59
    const-string v6, "zzi"

    .line 60
    .line 61
    const-class v7, Lrv/q;

    .line 62
    .line 63
    const-string v8, "zzj"

    .line 64
    .line 65
    const-string v9, "zzk"

    .line 66
    .line 67
    filled-new-array/range {v0 .. v11}, [Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    sget-object p1, Lrv/o;->zzb:Lrv/o;

    .line 72
    .line 73
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 74
    .line 75
    const-string v0, "\u0004\u0008\u0000\u0001\u0001\u0008\u0008\u0000\u0004\u0001\u0001\u1009\u0000\u0002\u1008\u0001\u0003\u1008\u0002\u0004\u001b\u0005\u001b\u0006\u001a\u0007\u041b\u0008\u1008\u0003"

    .line 76
    .line 77
    invoke-direct {p2, p1, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    return-object p2

    .line 81
    :cond_5
    iget-byte p0, p0, Lrv/o;->zzm:B

    .line 82
    .line 83
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0
.end method

.method public final n()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zze:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h0;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h0;->n()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final p()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zzf:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final q()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zzg:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zzk:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zzi:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final t()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/o;->zzj:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 2
    .line 3
    return-object p0
.end method
