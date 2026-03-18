.class public final Lrv/p;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lrv/p;


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

.field private zzn:Ljava/lang/String;

.field private zzo:Ljava/lang/String;

.field private zzp:Ljava/lang/String;

.field private zzq:Ljava/lang/String;

.field private zzr:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrv/p;

    .line 2
    .line 3
    invoke-direct {v0}, Lrv/p;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lrv/p;->zzb:Lrv/p;

    .line 7
    .line 8
    const-class v1, Lrv/p;

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
    iput-object v0, p0, Lrv/p;->zze:Ljava/lang/String;

    .line 7
    .line 8
    iput-object v0, p0, Lrv/p;->zzf:Ljava/lang/String;

    .line 9
    .line 10
    iput-object v0, p0, Lrv/p;->zzg:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v0, p0, Lrv/p;->zzh:Ljava/lang/String;

    .line 13
    .line 14
    iput-object v0, p0, Lrv/p;->zzi:Ljava/lang/String;

    .line 15
    .line 16
    iput-object v0, p0, Lrv/p;->zzj:Ljava/lang/String;

    .line 17
    .line 18
    iput-object v0, p0, Lrv/p;->zzk:Ljava/lang/String;

    .line 19
    .line 20
    iput-object v0, p0, Lrv/p;->zzl:Ljava/lang/String;

    .line 21
    .line 22
    iput-object v0, p0, Lrv/p;->zzm:Ljava/lang/String;

    .line 23
    .line 24
    iput-object v0, p0, Lrv/p;->zzn:Ljava/lang/String;

    .line 25
    .line 26
    iput-object v0, p0, Lrv/p;->zzo:Ljava/lang/String;

    .line 27
    .line 28
    iput-object v0, p0, Lrv/p;->zzp:Ljava/lang/String;

    .line 29
    .line 30
    iput-object v0, p0, Lrv/p;->zzq:Ljava/lang/String;

    .line 31
    .line 32
    iput-object v0, p0, Lrv/p;->zzr:Ljava/lang/String;

    .line 33
    .line 34
    return-void
.end method

.method public static n()Lrv/p;
    .locals 1

    .line 1
    sget-object v0, Lrv/p;->zzb:Lrv/p;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final A()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzn:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final B()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzg:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 16

    .line 1
    add-int/lit8 v0, p1, -0x1

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    if-eq v0, v1, :cond_3

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    if-eq v0, v1, :cond_2

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    const/4 v1, 0x5

    .line 15
    if-eq v0, v1, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    return-object v0

    .line 19
    :cond_0
    sget-object v0, Lrv/p;->zzb:Lrv/p;

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_1
    new-instance v0, Lfr/k;

    .line 23
    .line 24
    sget-object v1, Lrv/p;->zzb:Lrv/p;

    .line 25
    .line 26
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_2
    new-instance v0, Lrv/p;

    .line 31
    .line 32
    invoke-direct {v0}, Lrv/p;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :cond_3
    const-string v14, "zzq"

    .line 37
    .line 38
    const-string v15, "zzr"

    .line 39
    .line 40
    const-string v1, "zzd"

    .line 41
    .line 42
    const-string v2, "zze"

    .line 43
    .line 44
    const-string v3, "zzf"

    .line 45
    .line 46
    const-string v4, "zzg"

    .line 47
    .line 48
    const-string v5, "zzh"

    .line 49
    .line 50
    const-string v6, "zzi"

    .line 51
    .line 52
    const-string v7, "zzj"

    .line 53
    .line 54
    const-string v8, "zzk"

    .line 55
    .line 56
    const-string v9, "zzl"

    .line 57
    .line 58
    const-string v10, "zzm"

    .line 59
    .line 60
    const-string v11, "zzn"

    .line 61
    .line 62
    const-string v12, "zzo"

    .line 63
    .line 64
    const-string v13, "zzp"

    .line 65
    .line 66
    filled-new-array/range {v1 .. v15}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sget-object v1, Lrv/p;->zzb:Lrv/p;

    .line 71
    .line 72
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 73
    .line 74
    const-string v3, "\u0004\u000e\u0000\u0001\u0001\u000e\u000e\u0000\u0000\u0000\u0001\u1008\u0000\u0002\u1008\u0001\u0003\u1008\u0002\u0004\u1008\u0003\u0005\u1008\u0004\u0006\u1008\u0005\u0007\u1008\u0006\u0008\u1008\u0007\t\u1008\u0008\n\u1008\t\u000b\u1008\n\u000c\u1008\u000b\r\u1008\u000c\u000e\u1008\r"

    .line 75
    .line 76
    invoke-direct {v2, v1, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    return-object v2

    .line 80
    :cond_4
    const/4 v0, 0x1

    .line 81
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    return-object v0
.end method

.method public final o()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzk:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final q()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzj:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzm:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzq:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final t()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zze:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzp:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final v()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzf:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final w()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzi:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final x()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzo:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final y()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzr:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final z()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/p;->zzh:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
