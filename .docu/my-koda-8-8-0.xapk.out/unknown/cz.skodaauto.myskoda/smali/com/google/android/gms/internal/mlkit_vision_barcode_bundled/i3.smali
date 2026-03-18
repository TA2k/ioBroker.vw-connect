.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;


# instance fields
.field private zzd:I

.field private zze:I

.field private zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzg:I

.field private zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g3;

.field private zzi:Ljava/lang/String;

.field private zzj:I

.field private zzk:I

.field private zzl:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l1;

.field private zzm:Ljava/lang/String;

.field private zzn:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

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
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 7
    .line 8
    const/4 v0, -0x1

    .line 9
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzg:I

    .line 10
    .line 11
    const-string v0, ""

    .line 12
    .line 13
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzi:Ljava/lang/String;

    .line 14
    .line 15
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 16
    .line 17
    iput-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzl:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l1;

    .line 18
    .line 19
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzm:Ljava/lang/String;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 17

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
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y3;

    .line 23
    .line 24
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

    .line 25
    .line 26
    const/16 v2, 0x11

    .line 27
    .line 28
    invoke-direct {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y3;-><init>(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_2
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

    .line 33
    .line 34
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;-><init>()V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :cond_3
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;->j:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;

    .line 39
    .line 40
    sget-object v10, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;->k:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;

    .line 41
    .line 42
    sget-object v12, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;->l:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;

    .line 43
    .line 44
    const-string v15, "zzn"

    .line 45
    .line 46
    sget-object v16, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;->m:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c;

    .line 47
    .line 48
    const-string v1, "zzd"

    .line 49
    .line 50
    const-string v2, "zze"

    .line 51
    .line 52
    const-string v4, "zzf"

    .line 53
    .line 54
    const-class v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h3;

    .line 55
    .line 56
    const-string v6, "zzg"

    .line 57
    .line 58
    const-string v7, "zzh"

    .line 59
    .line 60
    const-string v8, "zzi"

    .line 61
    .line 62
    const-string v9, "zzj"

    .line 63
    .line 64
    const-string v11, "zzk"

    .line 65
    .line 66
    const-string v13, "zzl"

    .line 67
    .line 68
    const-string v14, "zzm"

    .line 69
    .line 70
    filled-new-array/range {v1 .. v16}, [Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i3;

    .line 75
    .line 76
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 77
    .line 78
    const-string v3, "\u0001\n\u0000\u0001\u0001\n\n\u0000\u0002\u0000\u0001\u180c\u0000\u0002\u001b\u0003\u1004\u0001\u0004\u1009\u0002\u0005\u1008\u0003\u0006\u180c\u0004\u0007\u180c\u0005\u0008\'\t\u1008\u0006\n\u180c\u0007"

    .line 79
    .line 80
    invoke-direct {v2, v1, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-object v2

    .line 84
    :cond_4
    const/4 v0, 0x1

    .line 85
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    return-object v0
.end method
