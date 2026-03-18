.class public final Lcom/google/android/filament/utils/Mat2$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/Mat2;
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
        "Lcom/google/android/filament/utils/Mat2$Companion;",
        "",
        "<init>",
        "()V",
        "of",
        "Lcom/google/android/filament/utils/Mat2;",
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
    invoke-direct {p0}, Lcom/google/android/filament/utils/Mat2$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final identity()Lcom/google/android/filament/utils/Mat2;
    .locals 2

    .line 1
    new-instance p0, Lcom/google/android/filament/utils/Mat2;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x3

    .line 5
    invoke-direct {p0, v0, v0, v1, v0}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;ILkotlin/jvm/internal/g;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public final varargs of([F)Lcom/google/android/filament/utils/Mat2;
    .locals 4

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
    const/4 v0, 0x4

    .line 8
    if-lt p0, v0, :cond_0

    .line 9
    .line 10
    new-instance p0, Lcom/google/android/filament/utils/Mat2;

    .line 11
    .line 12
    new-instance v0, Lcom/google/android/filament/utils/Float2;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    aget v1, p1, v1

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    aget v2, p1, v2

    .line 19
    .line 20
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 21
    .line 22
    .line 23
    new-instance v1, Lcom/google/android/filament/utils/Float2;

    .line 24
    .line 25
    const/4 v2, 0x1

    .line 26
    aget v2, p1, v2

    .line 27
    .line 28
    const/4 v3, 0x3

    .line 29
    aget p1, p1, v3

    .line 30
    .line 31
    invoke-direct {v1, v2, p1}, Lcom/google/android/filament/utils/Float2;-><init>(FF)V

    .line 32
    .line 33
    .line 34
    invoke-direct {p0, v0, v1}, Lcom/google/android/filament/utils/Mat2;-><init>(Lcom/google/android/filament/utils/Float2;Lcom/google/android/filament/utils/Float2;)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 39
    .line 40
    const-string p1, "Failed requirement."

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0
.end method
