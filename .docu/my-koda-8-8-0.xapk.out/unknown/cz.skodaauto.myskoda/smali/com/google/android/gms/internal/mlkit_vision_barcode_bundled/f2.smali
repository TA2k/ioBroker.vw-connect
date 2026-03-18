.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;


# instance fields
.field public final a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;

.field public final b:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Class;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;
    .locals 4

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    if-eqz p1, :cond_4

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 12
    .line 13
    if-nez v1, :cond_3

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 21
    .line 22
    const-class v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 23
    .line 24
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v1;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    iget v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->d:I

    .line 36
    .line 37
    const/4 v2, 0x2

    .line 38
    and-int/2addr v1, v2

    .line 39
    if-ne v1, v2, :cond_0

    .line 40
    .line 41
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 42
    .line 43
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 44
    .line 45
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 46
    .line 47
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d2;

    .line 48
    .line 49
    invoke-direct {v2, v1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/d2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_0
    sget v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e2;->a:I

    .line 54
    .line 55
    sget v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t1;->a:I

    .line 56
    .line 57
    sget-object v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 58
    .line 59
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;->a()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    add-int/lit8 v2, v2, -0x1

    .line 64
    .line 65
    const/4 v3, 0x1

    .line 66
    if-eq v2, v3, :cond_1

    .line 67
    .line 68
    sget-object v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    const/4 v2, 0x0

    .line 72
    :goto_0
    sget v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x1;->a:I

    .line 73
    .line 74
    invoke-static {p0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->v(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h2;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    :goto_1
    invoke-virtual {v0, p1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 83
    .line 84
    if-nez p0, :cond_2

    .line 85
    .line 86
    return-object v2

    .line 87
    :cond_2
    return-object p0

    .line 88
    :cond_3
    return-object v1

    .line 89
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    .line 90
    .line 91
    const-string p1, "messageType"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0
.end method
