.class public final Lcom/google/android/gms/internal/measurement/t2;
.super Lcom/google/android/gms/internal/measurement/l5;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final zzh:Lcom/google/android/gms/internal/measurement/t2;


# instance fields
.field private zzb:I

.field private zzd:I

.field private zze:Lcom/google/android/gms/internal/measurement/m3;

.field private zzf:Lcom/google/android/gms/internal/measurement/m3;

.field private zzg:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/t2;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/l5;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/t2;->zzh:Lcom/google/android/gms/internal/measurement/t2;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/measurement/t2;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/measurement/l5;->m(Ljava/lang/Class;Lcom/google/android/gms/internal/measurement/l5;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static w()Lcom/google/android/gms/internal/measurement/s2;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/t2;->zzh:Lcom/google/android/gms/internal/measurement/t2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->h()Lcom/google/android/gms/internal/measurement/k5;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcom/google/android/gms/internal/measurement/s2;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final synthetic A(Z)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x8

    .line 4
    .line 5
    iput v0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 6
    .line 7
    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzg:Z

    .line 8
    .line 9
    return-void
.end method

.method public final o(I)Ljava/lang/Object;
    .locals 3

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
    if-ne p1, p0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lcom/google/android/gms/internal/measurement/t2;->zzh:Lcom/google/android/gms/internal/measurement/t2;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    :cond_1
    new-instance p0, Lcom/google/android/gms/internal/measurement/s2;

    .line 23
    .line 24
    sget-object p1, Lcom/google/android/gms/internal/measurement/t2;->zzh:Lcom/google/android/gms/internal/measurement/t2;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/k5;-><init>(Lcom/google/android/gms/internal/measurement/l5;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/measurement/t2;

    .line 31
    .line 32
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/l5;-><init>()V

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
    const-string v0, "zzb"

    .line 41
    .line 42
    const-string v1, "zzd"

    .line 43
    .line 44
    const-string v2, "zze"

    .line 45
    .line 46
    filled-new-array {v0, v1, v2, p0, p1}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    sget-object p1, Lcom/google/android/gms/internal/measurement/t2;->zzh:Lcom/google/android/gms/internal/measurement/t2;

    .line 51
    .line 52
    new-instance v0, Lcom/google/android/gms/internal/measurement/m6;

    .line 53
    .line 54
    const-string v1, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001\u1004\u0000\u0002\u1009\u0001\u0003\u1009\u0002\u0004\u1007\u0003"

    .line 55
    .line 56
    invoke-direct {v0, p1, v1, p0}, Lcom/google/android/gms/internal/measurement/m6;-><init>(Lcom/google/android/gms/internal/measurement/t4;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object v0

    .line 60
    :cond_4
    const/4 p0, 0x1

    .line 61
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0
.end method

.method public final p()Z
    .locals 1

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

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

.method public final q()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzd:I

    .line 2
    .line 3
    return p0
.end method

.method public final r()Lcom/google/android/gms/internal/measurement/m3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zze:Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/google/android/gms/internal/measurement/m3;->y()Lcom/google/android/gms/internal/measurement/m3;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final s()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x4

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

.method public final t()Lcom/google/android/gms/internal/measurement/m3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzf:Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/google/android/gms/internal/measurement/m3;->y()Lcom/google/android/gms/internal/measurement/m3;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final u()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x8

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

.method public final v()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzg:Z

    .line 2
    .line 3
    return p0
.end method

.method public final synthetic x(I)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 6
    .line 7
    iput p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzd:I

    .line 8
    .line 9
    return-void
.end method

.method public final synthetic y(Lcom/google/android/gms/internal/measurement/m3;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zze:Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    iget p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x2

    .line 6
    .line 7
    iput p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 8
    .line 9
    return-void
.end method

.method public final synthetic z(Lcom/google/android/gms/internal/measurement/m3;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzf:Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    iget p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x4

    .line 6
    .line 7
    iput p1, p0, Lcom/google/android/gms/internal/measurement/t2;->zzb:I

    .line 8
    .line 9
    return-void
.end method
