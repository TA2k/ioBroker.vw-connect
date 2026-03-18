.class public final Lcom/google/android/gms/internal/measurement/t8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/internal/measurement/s8;


# static fields
.field public static final a:Lcom/google/android/gms/internal/measurement/n4;

.field public static final b:Lcom/google/android/gms/internal/measurement/n4;

.field public static final c:Lcom/google/android/gms/internal/measurement/n4;

.field public static final d:Lcom/google/android/gms/internal/measurement/n4;

.field public static final e:Lcom/google/android/gms/internal/measurement/n4;

.field public static final f:Lcom/google/android/gms/internal/measurement/n4;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/m4;->a()Landroid/net/Uri;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lb6/f;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-direct {v1, v0, v2, v2}, Lb6/f;-><init>(Landroid/net/Uri;ZZ)V

    .line 9
    .line 10
    .line 11
    const-string v0, "measurement.test.boolean_flag"

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v1, v0, v2}, Lb6/f;->A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lcom/google/android/gms/internal/measurement/t8;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 19
    .line 20
    const-string v0, "measurement.test.cached_long_flag"

    .line 21
    .line 22
    const-wide/16 v2, -0x1

    .line 23
    .line 24
    invoke-virtual {v1, v2, v3, v0}, Lb6/f;->z(JLjava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sput-object v0, Lcom/google/android/gms/internal/measurement/t8;->b:Lcom/google/android/gms/internal/measurement/n4;

    .line 29
    .line 30
    const-wide/high16 v4, -0x3ff8000000000000L    # -3.0

    .line 31
    .line 32
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sget-object v4, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 37
    .line 38
    new-instance v4, Lcom/google/android/gms/internal/measurement/n4;

    .line 39
    .line 40
    const-string v5, "measurement.test.double_flag"

    .line 41
    .line 42
    const/4 v6, 0x2

    .line 43
    invoke-direct {v4, v1, v5, v0, v6}, Lcom/google/android/gms/internal/measurement/n4;-><init>(Lb6/f;Ljava/lang/String;Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    sput-object v4, Lcom/google/android/gms/internal/measurement/t8;->c:Lcom/google/android/gms/internal/measurement/n4;

    .line 47
    .line 48
    const-string v0, "measurement.test.int_flag"

    .line 49
    .line 50
    const-wide/16 v4, -0x2

    .line 51
    .line 52
    invoke-virtual {v1, v4, v5, v0}, Lb6/f;->z(JLjava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sput-object v0, Lcom/google/android/gms/internal/measurement/t8;->d:Lcom/google/android/gms/internal/measurement/n4;

    .line 57
    .line 58
    const-string v0, "measurement.test.long_flag"

    .line 59
    .line 60
    invoke-virtual {v1, v2, v3, v0}, Lb6/f;->z(JLjava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    sput-object v0, Lcom/google/android/gms/internal/measurement/t8;->e:Lcom/google/android/gms/internal/measurement/n4;

    .line 65
    .line 66
    const-string v0, "measurement.test.string_flag"

    .line 67
    .line 68
    const-string v2, "---"

    .line 69
    .line 70
    invoke-virtual {v1, v0, v2}, Lb6/f;->B(Ljava/lang/String;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    sput-object v0, Lcom/google/android/gms/internal/measurement/t8;->f:Lcom/google/android/gms/internal/measurement/n4;

    .line 75
    .line 76
    return-void
.end method
