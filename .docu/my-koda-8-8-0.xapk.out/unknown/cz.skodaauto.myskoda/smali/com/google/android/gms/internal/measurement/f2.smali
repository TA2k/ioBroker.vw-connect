.class public final Lcom/google/android/gms/internal/measurement/f2;
.super Lcom/google/android/gms/internal/measurement/l5;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final zzu:Lcom/google/android/gms/internal/measurement/f2;


# instance fields
.field private zzb:I

.field private zzd:J

.field private zze:Ljava/lang/String;

.field private zzf:I

.field private zzg:Lcom/google/android/gms/internal/measurement/r5;

.field private zzh:Lcom/google/android/gms/internal/measurement/r5;

.field private zzi:Lcom/google/android/gms/internal/measurement/r5;

.field private zzj:Ljava/lang/String;

.field private zzk:Z

.field private zzl:Lcom/google/android/gms/internal/measurement/r5;

.field private zzm:Lcom/google/android/gms/internal/measurement/r5;

.field private zzn:Ljava/lang/String;

.field private zzo:Ljava/lang/String;

.field private zzp:Lcom/google/android/gms/internal/measurement/a2;

.field private zzq:Lcom/google/android/gms/internal/measurement/h2;

.field private zzr:Lcom/google/android/gms/internal/measurement/k2;

.field private zzs:Lcom/google/android/gms/internal/measurement/i2;

.field private zzt:Lcom/google/android/gms/internal/measurement/g2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/f2;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/f2;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/f2;->zzu:Lcom/google/android/gms/internal/measurement/f2;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/measurement/f2;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/measurement/l5;->m(Ljava/lang/Class;Lcom/google/android/gms/internal/measurement/l5;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/l5;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, ""

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zze:Ljava/lang/String;

    .line 7
    .line 8
    sget-object v1, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 9
    .line 10
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/f2;->zzg:Lcom/google/android/gms/internal/measurement/r5;

    .line 11
    .line 12
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/f2;->zzh:Lcom/google/android/gms/internal/measurement/r5;

    .line 13
    .line 14
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/f2;->zzi:Lcom/google/android/gms/internal/measurement/r5;

    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzj:Ljava/lang/String;

    .line 17
    .line 18
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/f2;->zzl:Lcom/google/android/gms/internal/measurement/r5;

    .line 19
    .line 20
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/f2;->zzm:Lcom/google/android/gms/internal/measurement/r5;

    .line 21
    .line 22
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzn:Ljava/lang/String;

    .line 23
    .line 24
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzo:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public static F()Lcom/google/android/gms/internal/measurement/e2;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/f2;->zzu:Lcom/google/android/gms/internal/measurement/f2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->h()Lcom/google/android/gms/internal/measurement/k5;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcom/google/android/gms/internal/measurement/e2;

    .line 8
    .line 9
    return-object v0
.end method

.method public static G()Lcom/google/android/gms/internal/measurement/f2;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/f2;->zzu:Lcom/google/android/gms/internal/measurement/f2;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final A()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzn:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final B()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzb:I

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

.method public final C()Lcom/google/android/gms/internal/measurement/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzp:Lcom/google/android/gms/internal/measurement/a2;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/google/android/gms/internal/measurement/a2;->v()Lcom/google/android/gms/internal/measurement/a2;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final D()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzb:I

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

.method public final E()Lcom/google/android/gms/internal/measurement/k2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzr:Lcom/google/android/gms/internal/measurement/k2;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/google/android/gms/internal/measurement/k2;->r()Lcom/google/android/gms/internal/measurement/k2;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final H(ILcom/google/android/gms/internal/measurement/d2;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzh:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcom/google/android/gms/internal/measurement/u4;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/google/android/gms/internal/measurement/u4;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    add-int/2addr v1, v1

    .line 15
    invoke-interface {v0, v1}, Lcom/google/android/gms/internal/measurement/r5;->M(I)Lcom/google/android/gms/internal/measurement/r5;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzh:Lcom/google/android/gms/internal/measurement/r5;

    .line 20
    .line 21
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzh:Lcom/google/android/gms/internal/measurement/r5;

    .line 22
    .line 23
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final I()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 2
    .line 3
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzi:Lcom/google/android/gms/internal/measurement/r5;

    .line 4
    .line 5
    return-void
.end method

.method public final J()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 2
    .line 3
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzl:Lcom/google/android/gms/internal/measurement/r5;

    .line 4
    .line 5
    return-void
.end method

.method public final o(I)Ljava/lang/Object;
    .locals 24

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
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    sget-object v0, Lcom/google/android/gms/internal/measurement/f2;->zzu:Lcom/google/android/gms/internal/measurement/f2;

    .line 18
    .line 19
    return-object v0

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    throw v0

    .line 22
    :cond_1
    new-instance v0, Lcom/google/android/gms/internal/measurement/e2;

    .line 23
    .line 24
    sget-object v1, Lcom/google/android/gms/internal/measurement/f2;->zzu:Lcom/google/android/gms/internal/measurement/f2;

    .line 25
    .line 26
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/k5;-><init>(Lcom/google/android/gms/internal/measurement/l5;)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_2
    new-instance v0, Lcom/google/android/gms/internal/measurement/f2;

    .line 31
    .line 32
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/f2;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :cond_3
    const-string v22, "zzs"

    .line 37
    .line 38
    const-string v23, "zzt"

    .line 39
    .line 40
    const-string v1, "zzb"

    .line 41
    .line 42
    const-string v2, "zzd"

    .line 43
    .line 44
    const-string v3, "zze"

    .line 45
    .line 46
    const-string v4, "zzf"

    .line 47
    .line 48
    const-string v5, "zzg"

    .line 49
    .line 50
    const-class v6, Lcom/google/android/gms/internal/measurement/j2;

    .line 51
    .line 52
    const-string v7, "zzh"

    .line 53
    .line 54
    const-class v8, Lcom/google/android/gms/internal/measurement/d2;

    .line 55
    .line 56
    const-string v9, "zzi"

    .line 57
    .line 58
    const-class v10, Lcom/google/android/gms/internal/measurement/m1;

    .line 59
    .line 60
    const-string v11, "zzj"

    .line 61
    .line 62
    const-string v12, "zzk"

    .line 63
    .line 64
    const-string v13, "zzl"

    .line 65
    .line 66
    const-class v14, Lcom/google/android/gms/internal/measurement/v3;

    .line 67
    .line 68
    const-string v15, "zzm"

    .line 69
    .line 70
    const-class v16, Lcom/google/android/gms/internal/measurement/b2;

    .line 71
    .line 72
    const-string v17, "zzn"

    .line 73
    .line 74
    const-string v18, "zzo"

    .line 75
    .line 76
    const-string v19, "zzp"

    .line 77
    .line 78
    const-string v20, "zzq"

    .line 79
    .line 80
    const-string v21, "zzr"

    .line 81
    .line 82
    filled-new-array/range {v1 .. v23}, [Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    sget-object v1, Lcom/google/android/gms/internal/measurement/f2;->zzu:Lcom/google/android/gms/internal/measurement/f2;

    .line 87
    .line 88
    new-instance v2, Lcom/google/android/gms/internal/measurement/m6;

    .line 89
    .line 90
    const-string v3, "\u0004\u0011\u0000\u0001\u0001\u0013\u0011\u0000\u0005\u0000\u0001\u1002\u0000\u0002\u1008\u0001\u0003\u1004\u0002\u0004\u001b\u0005\u001b\u0006\u001b\u0007\u1008\u0003\u0008\u1007\u0004\t\u001b\n\u001b\u000b\u1008\u0005\u000e\u1008\u0006\u000f\u1009\u0007\u0010\u1009\u0008\u0011\u1009\t\u0012\u1009\n\u0013\u1009\u000b"

    .line 91
    .line 92
    invoke-direct {v2, v1, v3, v0}, Lcom/google/android/gms/internal/measurement/m6;-><init>(Lcom/google/android/gms/internal/measurement/t4;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    return-object v2

    .line 96
    :cond_4
    const/4 v0, 0x1

    .line 97
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    return-object v0
.end method

.method public final p()Z
    .locals 1

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzb:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    and-int/2addr p0, v0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return v0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final q()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzd:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final r()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzb:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x2

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

.method public final s()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zze:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final t()Lcom/google/android/gms/internal/measurement/r5;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzg:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzh:Lcom/google/android/gms/internal/measurement/r5;

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

.method public final v(I)Lcom/google/android/gms/internal/measurement/d2;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzh:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/gms/internal/measurement/d2;

    .line 8
    .line 9
    return-object p0
.end method

.method public final w()Lcom/google/android/gms/internal/measurement/r5;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzi:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final x()Lcom/google/android/gms/internal/measurement/r5;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzl:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final y()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzl:Lcom/google/android/gms/internal/measurement/r5;

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

.method public final z()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f2;->zzm:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    return-object p0
.end method
