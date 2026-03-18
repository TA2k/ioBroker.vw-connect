.class public final Lcom/google/android/gms/internal/measurement/k3;
.super Lcom/google/android/gms/internal/measurement/l5;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final zzf:Lcom/google/android/gms/internal/measurement/k3;


# instance fields
.field private zzb:I

.field private zzd:I

.field private zze:Lcom/google/android/gms/internal/measurement/r5;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/k3;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/k3;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/k3;->zzf:Lcom/google/android/gms/internal/measurement/k3;

    .line 7
    .line 8
    const-class v1, Lcom/google/android/gms/internal/measurement/k3;

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
    const/4 v0, 0x1

    .line 5
    iput v0, p0, Lcom/google/android/gms/internal/measurement/k3;->zzd:I

    .line 6
    .line 7
    sget-object v0, Lcom/google/android/gms/internal/measurement/l6;->h:Lcom/google/android/gms/internal/measurement/l6;

    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/k3;->zze:Lcom/google/android/gms/internal/measurement/r5;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
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
    sget-object p0, Lcom/google/android/gms/internal/measurement/k3;->zzf:Lcom/google/android/gms/internal/measurement/k3;

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
    sget-object p1, Lcom/google/android/gms/internal/measurement/k3;->zzf:Lcom/google/android/gms/internal/measurement/k3;

    .line 25
    .line 26
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/k5;-><init>(Lcom/google/android/gms/internal/measurement/l5;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/measurement/k3;

    .line 31
    .line 32
    invoke-direct {p0}, Lcom/google/android/gms/internal/measurement/k3;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_3
    sget-object p0, Lcom/google/android/gms/internal/measurement/s1;->k:Lcom/google/android/gms/internal/measurement/s1;

    .line 37
    .line 38
    const-string p1, "zze"

    .line 39
    .line 40
    const-class v0, Lcom/google/android/gms/internal/measurement/c3;

    .line 41
    .line 42
    const-string v1, "zzb"

    .line 43
    .line 44
    const-string v2, "zzd"

    .line 45
    .line 46
    filled-new-array {v1, v2, p0, p1, v0}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    sget-object p1, Lcom/google/android/gms/internal/measurement/k3;->zzf:Lcom/google/android/gms/internal/measurement/k3;

    .line 51
    .line 52
    new-instance v0, Lcom/google/android/gms/internal/measurement/m6;

    .line 53
    .line 54
    const-string v1, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u180c\u0000\u0002\u001b"

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
