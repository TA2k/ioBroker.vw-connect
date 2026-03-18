.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;


# instance fields
.field private zzd:I

.field private zze:I

.field private zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t3;

.field private zzg:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/k3;

.field private zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c3;

.field private zzi:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n3;

.field private zzj:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

.field private zzk:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e3;

.field private zzl:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x3;

.field private zzm:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f3;

.field private zzn:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l3;

.field private zzo:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m3;

.field private zzp:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m3;

.field private zzq:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m3;

.field private zzr:Z

.field private zzs:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j3;

.field private zzt:I

.field private zzu:Z

.field private zzv:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u3;

.field private zzw:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d3;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

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
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;->zzt:I

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 22

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
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y3;

    .line 23
    .line 24
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

    .line 25
    .line 26
    const/16 v2, 0x1d

    .line 27
    .line 28
    invoke-direct {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y3;-><init>(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_2
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

    .line 33
    .line 34
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;-><init>()V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :cond_3
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;

    .line 39
    .line 40
    const-string v20, "zzn"

    .line 41
    .line 42
    const-string v21, "zzw"

    .line 43
    .line 44
    const-string v1, "zzd"

    .line 45
    .line 46
    const-string v2, "zze"

    .line 47
    .line 48
    const-string v4, "zzf"

    .line 49
    .line 50
    const-string v5, "zzg"

    .line 51
    .line 52
    const-string v6, "zzh"

    .line 53
    .line 54
    const-string v7, "zzi"

    .line 55
    .line 56
    const-string v8, "zzo"

    .line 57
    .line 58
    const-string v9, "zzp"

    .line 59
    .line 60
    const-string v10, "zzq"

    .line 61
    .line 62
    const-string v11, "zzr"

    .line 63
    .line 64
    const-string v12, "zzj"

    .line 65
    .line 66
    const-string v13, "zzs"

    .line 67
    .line 68
    const-string v14, "zzk"

    .line 69
    .line 70
    const-string v15, "zzl"

    .line 71
    .line 72
    const-string v16, "zzt"

    .line 73
    .line 74
    const-string v17, "zzm"

    .line 75
    .line 76
    const-string v18, "zzu"

    .line 77
    .line 78
    const-string v19, "zzv"

    .line 79
    .line 80
    filled-new-array/range {v1 .. v21}, [Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v3;

    .line 85
    .line 86
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 87
    .line 88
    const-string v3, "\u0001\u0013\u0000\u0001\u0001\u0013\u0013\u0000\u0000\u0000\u0001\u180c\u0000\u0002\u1009\u0001\u0003\u1009\u0002\u0004\u1009\u0003\u0005\u1009\u0004\u0006\u1009\n\u0007\u1009\u000b\u0008\u1009\u000c\t\u1007\r\n\u1009\u0005\u000b\u1009\u000e\u000c\u1009\u0006\r\u1009\u0007\u000e\u1004\u000f\u000f\u1009\u0008\u0010\u1007\u0010\u0011\u1009\u0011\u0012\u1009\t\u0013\u1009\u0012"

    .line 89
    .line 90
    invoke-direct {v2, v1, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    return-object v2

    .line 94
    :cond_4
    const/4 v0, 0x1

    .line 95
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    return-object v0
.end method
