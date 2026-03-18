.class public final Lcom/google/android/filament/utils/Mat4$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/Mat4;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0014\n\u0002\u0010\u0007\n\u0002\u0008\u0002\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0012\u0010\u0004\u001a\u00020\u00052\n\u0010\u0006\u001a\u00020\u0007\"\u00020\u0008J\u0006\u0010\t\u001a\u00020\u0005\u00a8\u0006\n"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Mat4$Companion;",
        "",
        "<init>",
        "()V",
        "of",
        "Lcom/google/android/filament/utils/Mat4;",
        "a",
        "",
        "",
        "identity",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/utils/Mat4$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final identity()Lcom/google/android/filament/utils/Mat4;
    .locals 7

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    const/16 v5, 0xf

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;ILkotlin/jvm/internal/g;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final varargs of([F)Lcom/google/android/filament/utils/Mat4;
    .locals 8

    .line 1
    const-string p0, "a"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length p0, p1

    .line 7
    const/16 v0, 0x10

    .line 8
    .line 9
    if-lt p0, v0, :cond_0

    .line 10
    .line 11
    new-instance p0, Lcom/google/android/filament/utils/Mat4;

    .line 12
    .line 13
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    aget v1, p1, v1

    .line 17
    .line 18
    const/4 v2, 0x4

    .line 19
    aget v2, p1, v2

    .line 20
    .line 21
    const/16 v3, 0x8

    .line 22
    .line 23
    aget v3, p1, v3

    .line 24
    .line 25
    const/16 v4, 0xc

    .line 26
    .line 27
    aget v4, p1, v4

    .line 28
    .line 29
    invoke-direct {v0, v1, v2, v3, v4}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    aget v2, p1, v2

    .line 36
    .line 37
    const/4 v3, 0x5

    .line 38
    aget v3, p1, v3

    .line 39
    .line 40
    const/16 v4, 0x9

    .line 41
    .line 42
    aget v4, p1, v4

    .line 43
    .line 44
    const/16 v5, 0xd

    .line 45
    .line 46
    aget v5, p1, v5

    .line 47
    .line 48
    invoke-direct {v1, v2, v3, v4, v5}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 49
    .line 50
    .line 51
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 52
    .line 53
    const/4 v3, 0x2

    .line 54
    aget v3, p1, v3

    .line 55
    .line 56
    const/4 v4, 0x6

    .line 57
    aget v4, p1, v4

    .line 58
    .line 59
    const/16 v5, 0xa

    .line 60
    .line 61
    aget v5, p1, v5

    .line 62
    .line 63
    const/16 v6, 0xe

    .line 64
    .line 65
    aget v6, p1, v6

    .line 66
    .line 67
    invoke-direct {v2, v3, v4, v5, v6}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 68
    .line 69
    .line 70
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 71
    .line 72
    const/4 v4, 0x3

    .line 73
    aget v4, p1, v4

    .line 74
    .line 75
    const/4 v5, 0x7

    .line 76
    aget v5, p1, v5

    .line 77
    .line 78
    const/16 v6, 0xb

    .line 79
    .line 80
    aget v6, p1, v6

    .line 81
    .line 82
    const/16 v7, 0xf

    .line 83
    .line 84
    aget p1, p1, v7

    .line 85
    .line 86
    invoke-direct {v3, v4, v5, v6, p1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 87
    .line 88
    .line 89
    invoke-direct {p0, v0, v1, v2, v3}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 90
    .line 91
    .line 92
    return-object p0

    .line 93
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 94
    .line 95
    const-string p1, "Failed requirement."

    .line 96
    .line 97
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0
.end method
