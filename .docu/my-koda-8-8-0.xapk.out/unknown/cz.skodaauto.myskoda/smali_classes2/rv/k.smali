.class public final Lrv/k;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z1;


# static fields
.field private static final zzb:Lrv/k;


# instance fields
.field private zzA:B

.field private zzd:I

.field private zze:I

.field private zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

.field private zzg:Ljava/lang/String;

.field private zzh:Lrv/c;

.field private zzi:I

.field private zzj:Lrv/o;

.field private zzk:Lrv/q;

.field private zzl:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i0;

.field private zzm:Lrv/f;

.field private zzn:Lrv/i;

.field private zzo:Lrv/h;

.field private zzp:Lrv/s;

.field private zzq:Lrv/n;

.field private zzr:Lrv/p;

.field private zzs:Lrv/l;

.field private zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzu:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l1;

.field private zzv:Ljava/lang/String;

.field private zzw:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

.field private zzx:Z

.field private zzy:D

.field private zzz:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrv/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lrv/k;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lrv/k;->zzb:Lrv/k;

    .line 7
    .line 8
    const-class v1, Lrv/k;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->h(Ljava/lang/Class;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    iput-byte v0, p0, Lrv/k;->zzA:B

    .line 6
    .line 7
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 8
    .line 9
    iput-object v0, p0, Lrv/k;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 10
    .line 11
    const-string v1, ""

    .line 12
    .line 13
    iput-object v1, p0, Lrv/k;->zzg:Ljava/lang/String;

    .line 14
    .line 15
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g2;

    .line 16
    .line 17
    iput-object v2, p0, Lrv/k;->zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 18
    .line 19
    sget-object v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 20
    .line 21
    iput-object v3, p0, Lrv/k;->zzu:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l1;

    .line 22
    .line 23
    iput-object v1, p0, Lrv/k;->zzv:Ljava/lang/String;

    .line 24
    .line 25
    iput-object v2, p0, Lrv/k;->zzw:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 26
    .line 27
    const/4 v1, 0x1

    .line 28
    iput-boolean v1, p0, Lrv/k;->zzx:Z

    .line 29
    .line 30
    iput-object v0, p0, Lrv/k;->zzz:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 31
    .line 32
    return-void
.end method

.method public static B(Lrv/k;ILrv/e;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lrv/k;->zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

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
    if-nez v1, :cond_1

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
    invoke-interface {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;->d(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Lrv/k;->zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 25
    .line 26
    :cond_1
    iget-object p0, p0, Lrv/k;->zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 27
    .line 28
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final A()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final C()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x1000

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final D()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x20

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final E()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x2000

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final F()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x40

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final G()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x800

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final H()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x80

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final I()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x100

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final J()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x400

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final K()Z
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzd:I

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0x200

    .line 4
    .line 5
    if-eqz p0, :cond_0

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

.method public final L()I
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zze:I

    .line 2
    .line 3
    invoke-static {p0}, Lkp/q6;->c(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    :cond_0
    return p0
.end method

.method public final m(ILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)Ljava/lang/Object;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    add-int/lit8 v1, p1, -0x1

    .line 4
    .line 5
    if-eqz v1, :cond_5

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    if-eq v1, v2, :cond_4

    .line 9
    .line 10
    const/4 v2, 0x3

    .line 11
    if-eq v1, v2, :cond_3

    .line 12
    .line 13
    const/4 v2, 0x4

    .line 14
    if-eq v1, v2, :cond_2

    .line 15
    .line 16
    const/4 v2, 0x5

    .line 17
    if-eq v1, v2, :cond_1

    .line 18
    .line 19
    if-nez p2, :cond_0

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v1, 0x1

    .line 24
    :goto_0
    iput-byte v1, v0, Lrv/k;->zzA:B

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    return-object v0

    .line 28
    :cond_1
    sget-object v0, Lrv/k;->zzb:Lrv/k;

    .line 29
    .line 30
    return-object v0

    .line 31
    :cond_2
    new-instance v0, Lrv/j;

    .line 32
    .line 33
    sget-object v1, Lrv/k;->zzb:Lrv/k;

    .line 34
    .line 35
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c1;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :cond_3
    new-instance v0, Lrv/k;

    .line 40
    .line 41
    invoke-direct {v0}, Lrv/k;-><init>()V

    .line 42
    .line 43
    .line 44
    return-object v0

    .line 45
    :cond_4
    sget-object v3, Lrv/g;->d:Lrv/g;

    .line 46
    .line 47
    sget-object v7, Lrv/g;->e:Lrv/g;

    .line 48
    .line 49
    const-string v26, "zzy"

    .line 50
    .line 51
    const-string v27, "zzh"

    .line 52
    .line 53
    const-string v1, "zzd"

    .line 54
    .line 55
    const-string v2, "zze"

    .line 56
    .line 57
    const-string v4, "zzf"

    .line 58
    .line 59
    const-string v5, "zzg"

    .line 60
    .line 61
    const-string v6, "zzi"

    .line 62
    .line 63
    const-string v8, "zzj"

    .line 64
    .line 65
    const-string v9, "zzk"

    .line 66
    .line 67
    const-string v10, "zzl"

    .line 68
    .line 69
    const-string v11, "zzm"

    .line 70
    .line 71
    const-string v12, "zzn"

    .line 72
    .line 73
    const-string v13, "zzo"

    .line 74
    .line 75
    const-string v14, "zzt"

    .line 76
    .line 77
    const-class v15, Lrv/e;

    .line 78
    .line 79
    const-string v16, "zzv"

    .line 80
    .line 81
    const-string v17, "zzw"

    .line 82
    .line 83
    const-class v18, Lrv/e;

    .line 84
    .line 85
    const-string v19, "zzz"

    .line 86
    .line 87
    const-string v20, "zzp"

    .line 88
    .line 89
    const-string v21, "zzq"

    .line 90
    .line 91
    const-string v22, "zzr"

    .line 92
    .line 93
    const-string v23, "zzu"

    .line 94
    .line 95
    const-string v24, "zzs"

    .line 96
    .line 97
    const-string v25, "zzx"

    .line 98
    .line 99
    filled-new-array/range {v1 .. v27}, [Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    sget-object v1, Lrv/k;->zzb:Lrv/k;

    .line 104
    .line 105
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 106
    .line 107
    const-string v3, "\u0004\u0016\u0000\u0001\u0001\u0017\u0016\u0000\u0003\u000b\u0001\u1d0c\u0000\u0002\u150a\u0001\u0003\u1508\u0002\u0004\u1d0c\u0004\u0005\u1409\u0005\u0006\u1009\u0006\u0007\u1009\u0007\u0008\u1409\u0008\t\u1409\t\n\u1409\n\u000b\u041b\u000c\u1008\u000f\r\u041b\u000e\u100a\u0012\u000f\u1409\u000b\u0010\u1009\u000c\u0011\u1009\r\u0012\u0016\u0013\u1009\u000e\u0014\u1007\u0010\u0015\u1000\u0011\u0017\u1009\u0003"

    .line 108
    .line 109
    invoke-direct {v2, v1, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    return-object v2

    .line 113
    :cond_5
    iget-byte v0, v0, Lrv/k;->zzA:B

    .line 114
    .line 115
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    return-object v0
.end method

.method public final n()I
    .locals 0

    .line 1
    iget p0, p0, Lrv/k;->zzi:I

    .line 2
    .line 3
    invoke-static {p0}, Lkp/r6;->b(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    :cond_0
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzt:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final p()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzl:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i0;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i0;->n()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/i0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final q()Lrv/n;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzq:Lrv/n;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/n;->p()Lrv/n;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final r()Lrv/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzj:Lrv/o;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/o;->o()Lrv/o;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final s()Lrv/p;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzr:Lrv/p;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/p;->n()Lrv/p;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final t()Lrv/q;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzk:Lrv/q;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/q;->n()Lrv/q;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final u()Lrv/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzp:Lrv/s;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/s;->p()Lrv/s;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final v()Lrv/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzm:Lrv/f;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/f;->n()Lrv/f;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final w()Lrv/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzo:Lrv/h;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/h;->n()Lrv/h;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final x()Lrv/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzn:Lrv/i;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lrv/i;->n()Lrv/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final y()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzf:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final z()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrv/k;->zzg:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
