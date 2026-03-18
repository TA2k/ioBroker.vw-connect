.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;


# instance fields
.field private zzd:I

.field private zze:Ljava/lang/String;

.field private zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzg:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzi:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z3;

.field private zzj:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

.field private zzk:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e4;

.field private zzl:B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->h(Ljava/lang/Class;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 11
    .line 12
    .line 13
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z3;->n()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z3;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 23
    .line 24
    const-string v1, "Null containingTypeDefaultInstance"

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw v0
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    iput-byte v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzl:B

    .line 6
    .line 7
    const-string v0, ""

    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zze:Ljava/lang/String;

    .line 10
    .line 11
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;

    .line 12
    .line 13
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 14
    .line 15
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzg:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 16
    .line 17
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzh:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 11

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
    iput-byte p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzl:B

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    return-object p0

    .line 26
    :cond_1
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y3;

    .line 30
    .line 31
    sget-object p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 32
    .line 33
    const/4 p2, 0x7

    .line 34
    invoke-direct {p0, p2, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y3;-><init>(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_3
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 39
    .line 40
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;-><init>()V

    .line 41
    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_4
    const-string v9, "zzj"

    .line 45
    .line 46
    const-string v10, "zzk"

    .line 47
    .line 48
    const-string v0, "zzd"

    .line 49
    .line 50
    const-string v1, "zzf"

    .line 51
    .line 52
    const-class v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o3;

    .line 53
    .line 54
    const-string v3, "zzh"

    .line 55
    .line 56
    const-class v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o3;

    .line 57
    .line 58
    const-string v5, "zzg"

    .line 59
    .line 60
    const-class v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/a4;

    .line 61
    .line 62
    const-string v7, "zzi"

    .line 63
    .line 64
    const-string v8, "zze"

    .line 65
    .line 66
    filled-new-array/range {v0 .. v10}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    sget-object p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzb:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;

    .line 71
    .line 72
    new-instance p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 73
    .line 74
    const-string v0, "\u0001\u0007\u0000\u0001\u0002\u01f4\u0007\u0000\u0003\u0004\u0002\u041b\u0005\u041b\u0006\u001b\u0008\u1409\u0001\n\u1008\u0000\u000b\u1409\u0002\u01f4\u1009\u0003"

    .line 75
    .line 76
    invoke-direct {p2, p1, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    return-object p2

    .line 80
    :cond_5
    iget-byte p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s1;->zzl:B

    .line 81
    .line 82
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0
.end method
