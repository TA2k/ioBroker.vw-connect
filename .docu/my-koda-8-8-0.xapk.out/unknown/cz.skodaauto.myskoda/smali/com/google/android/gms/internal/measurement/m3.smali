.class public final Lcom/google/android/gms/internal/measurement/m3;
.super Lcom/google/android/gms/internal/measurement/l5;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final zzg:Lcom/google/android/gms/internal/measurement/m3;


# instance fields
.field private zzb:Lcom/google/android/gms/internal/measurement/q5;

.field private zzd:Lcom/google/android/gms/internal/measurement/q5;

.field private zze:Lcom/google/android/gms/internal/measurement/r5;

.field private zzf:Lcom/google/android/gms/internal/measurement/r5;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/m3;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/m3;->zzg:Lcom/google/android/gms/internal/measurement/m3;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/measurement/m3;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/measurement/l5;->m(Ljava/lang/Class;Lcom/google/android/gms/internal/measurement/l5;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/l5;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/android/gms/internal/measurement/z5;->h:Lcom/google/android/gms/internal/measurement/z5;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

    .line 7
    .line 8
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

    .line 9
    .line 10
    sget-object v0, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 11
    .line 12
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

    .line 13
    .line 14
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

    .line 15
    .line 16
    return-void
.end method

.method public static x()Lcom/google/android/gms/internal/measurement/l3;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/m3;->zzg:Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->h()Lcom/google/android/gms/internal/measurement/k5;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcom/google/android/gms/internal/measurement/l3;

    .line 8
    .line 9
    return-object v0
.end method

.method public static y()Lcom/google/android/gms/internal/measurement/m3;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/m3;->zzg:Lcom/google/android/gms/internal/measurement/m3;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final A()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/z5;->h:Lcom/google/android/gms/internal/measurement/z5;

    .line 2
    .line 3
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

    .line 4
    .line 5
    return-void
.end method

.method public final B(Ljava/util/List;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

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
    check-cast v0, Lcom/google/android/gms/internal/measurement/z5;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/z5;->g(I)Lcom/google/android/gms/internal/measurement/z5;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

    .line 22
    .line 23
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

    .line 24
    .line 25
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/t4;->c(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final C()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/z5;->h:Lcom/google/android/gms/internal/measurement/z5;

    .line 2
    .line 3
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

    .line 4
    .line 5
    return-void
.end method

.method public final D(Ljava/util/ArrayList;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

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
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

    .line 20
    .line 21
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

    .line 22
    .line 23
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/t4;->c(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final E()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 2
    .line 3
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

    .line 4
    .line 5
    return-void
.end method

.method public final F(Ljava/lang/Iterable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

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
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

    .line 20
    .line 21
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

    .line 22
    .line 23
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/t4;->c(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final G()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 2
    .line 3
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

    .line 4
    .line 5
    return-void
.end method

.method public final o(I)Ljava/lang/Object;
    .locals 6

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
    sget-object p0, Lcom/google/android/gms/internal/measurement/m3;->zzg:Lcom/google/android/gms/internal/measurement/m3;

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
    new-instance p0, Lcom/google/android/gms/internal/measurement/l3;

    .line 23
    .line 24
    sget-object p1, Lcom/google/android/gms/internal/measurement/m3;->zzg:Lcom/google/android/gms/internal/measurement/m3;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/k5;-><init>(Lcom/google/android/gms/internal/measurement/l5;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/measurement/m3;

    .line 31
    .line 32
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/m3;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    const-string v4, "zzf"

    .line 37
    .line 38
    const-class v5, Lcom/google/android/gms/internal/measurement/o3;

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
    const-class v3, Lcom/google/android/gms/internal/measurement/z2;

    .line 47
    .line 48
    filled-new-array/range {v0 .. v5}, [Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    sget-object p1, Lcom/google/android/gms/internal/measurement/m3;->zzg:Lcom/google/android/gms/internal/measurement/m3;

    .line 53
    .line 54
    new-instance v0, Lcom/google/android/gms/internal/measurement/m6;

    .line 55
    .line 56
    const-string v1, "\u0004\u0004\u0000\u0000\u0001\u0004\u0004\u0000\u0004\u0000\u0001\u0015\u0002\u0015\u0003\u001b\u0004\u001b"

    .line 57
    .line 58
    invoke-direct {v0, p1, v1, p0}, Lcom/google/android/gms/internal/measurement/m6;-><init>(Lcom/google/android/gms/internal/measurement/t4;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-object v0

    .line 62
    :cond_4
    const/4 p0, 0x1

    .line 63
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0
.end method

.method public final p()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final q()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

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

.method public final r()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzd:Lcom/google/android/gms/internal/measurement/q5;

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

.method public final t()Lcom/google/android/gms/internal/measurement/r5;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zze:Lcom/google/android/gms/internal/measurement/r5;

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

.method public final v()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

    .line 2
    .line 3
    return-object p0
.end method

.method public final w()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzf:Lcom/google/android/gms/internal/measurement/r5;

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

.method public final z(Ljava/lang/Iterable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

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
    check-cast v0, Lcom/google/android/gms/internal/measurement/z5;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/z5;->g(I)Lcom/google/android/gms/internal/measurement/z5;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

    .line 22
    .line 23
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/m3;->zzb:Lcom/google/android/gms/internal/measurement/q5;

    .line 24
    .line 25
    invoke-static {p1, p0}, Lcom/google/android/gms/internal/measurement/t4;->c(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
