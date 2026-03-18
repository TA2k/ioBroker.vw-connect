.class public final Lcom/google/android/gms/internal/measurement/x1;
.super Lcom/google/android/gms/internal/measurement/l5;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final zzg:Lcom/google/android/gms/internal/measurement/x1;


# instance fields
.field private zzb:I

.field private zzd:I

.field private zze:I

.field private zzf:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/x1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/l5;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/x1;->zzg:Lcom/google/android/gms/internal/measurement/x1;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/measurement/x1;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/android/gms/internal/measurement/l5;->m(Ljava/lang/Class;Lcom/google/android/gms/internal/measurement/l5;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final o(I)Ljava/lang/Object;
    .locals 7

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
    sget-object p0, Lcom/google/android/gms/internal/measurement/x1;->zzg:Lcom/google/android/gms/internal/measurement/x1;

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
    new-instance p0, Lcom/google/android/gms/internal/measurement/r1;

    .line 23
    .line 24
    sget-object p1, Lcom/google/android/gms/internal/measurement/x1;->zzg:Lcom/google/android/gms/internal/measurement/x1;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/k5;-><init>(Lcom/google/android/gms/internal/measurement/l5;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/measurement/x1;

    .line 31
    .line 32
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/l5;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    sget-object v2, Lcom/google/android/gms/internal/measurement/s1;->e:Lcom/google/android/gms/internal/measurement/s1;

    .line 37
    .line 38
    sget-object v4, Lcom/google/android/gms/internal/measurement/s1;->d:Lcom/google/android/gms/internal/measurement/s1;

    .line 39
    .line 40
    const-string v5, "zzf"

    .line 41
    .line 42
    sget-object v6, Lcom/google/android/gms/internal/measurement/s1;->f:Lcom/google/android/gms/internal/measurement/s1;

    .line 43
    .line 44
    const-string v0, "zzb"

    .line 45
    .line 46
    const-string v1, "zzd"

    .line 47
    .line 48
    const-string v3, "zze"

    .line 49
    .line 50
    filled-new-array/range {v0 .. v6}, [Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    sget-object p1, Lcom/google/android/gms/internal/measurement/x1;->zzg:Lcom/google/android/gms/internal/measurement/x1;

    .line 55
    .line 56
    new-instance v0, Lcom/google/android/gms/internal/measurement/m6;

    .line 57
    .line 58
    const-string v1, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u180c\u0000\u0002\u180c\u0001\u0003\u180c\u0002"

    .line 59
    .line 60
    invoke-direct {v0, p1, v1, p0}, Lcom/google/android/gms/internal/measurement/m6;-><init>(Lcom/google/android/gms/internal/measurement/t4;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    return-object v0

    .line 64
    :cond_4
    const/4 p0, 0x1

    .line 65
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method

.method public final p()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/x1;->zzd:I

    .line 2
    .line 3
    invoke-static {p0}, Ljp/ud;->a(I)I

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

.method public final q()I
    .locals 2

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/x1;->zze:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eqz p0, :cond_1

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-eq p0, v0, :cond_2

    .line 8
    .line 9
    if-eq p0, v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v1, 0x3

    .line 14
    goto :goto_0

    .line 15
    :cond_1
    move v1, v0

    .line 16
    :cond_2
    :goto_0
    if-nez v1, :cond_3

    .line 17
    .line 18
    return v0

    .line 19
    :cond_3
    return v1
.end method

.method public final r()I
    .locals 2

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/x1;->zzf:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eqz p0, :cond_1

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-eq p0, v0, :cond_2

    .line 8
    .line 9
    if-eq p0, v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v1, 0x3

    .line 14
    goto :goto_0

    .line 15
    :cond_1
    move v1, v0

    .line 16
    :cond_2
    :goto_0
    if-nez v1, :cond_3

    .line 17
    .line 18
    return v0

    .line 19
    :cond_3
    return v1
.end method
