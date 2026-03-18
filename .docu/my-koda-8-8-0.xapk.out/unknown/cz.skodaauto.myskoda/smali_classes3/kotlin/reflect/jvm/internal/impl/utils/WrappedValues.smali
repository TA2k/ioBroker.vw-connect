.class public Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$WrappedProcessCanceledException;,
        Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$ThrowableWrapper;
    }
.end annotation


# static fields
.field private static final NULL_VALUE:Ljava/lang/Object;

.field public static volatile throwWrappedProcessCanceledException:Z


# direct methods
.method private static synthetic $$$reportNull$$$0(I)V
    .locals 8

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x1

    .line 3
    if-eq p0, v1, :cond_0

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    const-string v2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v2, "@NotNull method %s.%s must not return null"

    .line 11
    .line 12
    :goto_0
    const/4 v3, 0x3

    .line 13
    if-eq p0, v1, :cond_1

    .line 14
    .line 15
    if-eq p0, v0, :cond_1

    .line 16
    .line 17
    move v4, v3

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move v4, v0

    .line 20
    :goto_1
    new-array v4, v4, [Ljava/lang/Object;

    .line 21
    .line 22
    const-string v5, "kotlin/reflect/jvm/internal/impl/utils/WrappedValues"

    .line 23
    .line 24
    const/4 v6, 0x0

    .line 25
    if-eq p0, v1, :cond_3

    .line 26
    .line 27
    if-eq p0, v0, :cond_3

    .line 28
    .line 29
    if-eq p0, v3, :cond_2

    .line 30
    .line 31
    const-string v7, "value"

    .line 32
    .line 33
    aput-object v7, v4, v6

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_2
    const-string v7, "throwable"

    .line 37
    .line 38
    aput-object v7, v4, v6

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_3
    aput-object v5, v4, v6

    .line 42
    .line 43
    :goto_2
    if-eq p0, v1, :cond_4

    .line 44
    .line 45
    if-eq p0, v0, :cond_4

    .line 46
    .line 47
    aput-object v5, v4, v1

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_4
    const-string v5, "escapeNull"

    .line 51
    .line 52
    aput-object v5, v4, v1

    .line 53
    .line 54
    :goto_3
    if-eq p0, v1, :cond_7

    .line 55
    .line 56
    if-eq p0, v0, :cond_7

    .line 57
    .line 58
    if-eq p0, v3, :cond_6

    .line 59
    .line 60
    const/4 v3, 0x4

    .line 61
    if-eq p0, v3, :cond_5

    .line 62
    .line 63
    const-string v3, "unescapeNull"

    .line 64
    .line 65
    aput-object v3, v4, v0

    .line 66
    .line 67
    goto :goto_4

    .line 68
    :cond_5
    const-string v3, "unescapeExceptionOrNull"

    .line 69
    .line 70
    aput-object v3, v4, v0

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_6
    const-string v3, "escapeThrowable"

    .line 74
    .line 75
    aput-object v3, v4, v0

    .line 76
    .line 77
    :cond_7
    :goto_4
    invoke-static {v2, v4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    if-eq p0, v1, :cond_8

    .line 82
    .line 83
    if-eq p0, v0, :cond_8

    .line 84
    .line 85
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 86
    .line 87
    invoke-direct {p0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 92
    .line 93
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :goto_5
    throw p0
.end method

.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->NULL_VALUE:Ljava/lang/Object;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    sput-boolean v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->throwWrappedProcessCanceledException:Z

    .line 10
    .line 11
    return-void
.end method

.method public static escapeNull(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<V:",
            "Ljava/lang/Object;",
            ">(TV;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->NULL_VALUE:Ljava/lang/Object;

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->$$$reportNull$$$0(I)V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-object p0
.end method

.method public static escapeThrowable(Ljava/lang/Throwable;)Ljava/lang/Object;
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$ThrowableWrapper;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, p0, v1}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$ThrowableWrapper;-><init>(Ljava/lang/Throwable;Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$1;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static unescapeExceptionOrNull(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<V:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Object;",
            ")TV;"
        }
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->unescapeThrowable(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->unescapeNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static unescapeNull(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<V:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Object;",
            ")TV;"
        }
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->NULL_VALUE:Ljava/lang/Object;

    .line 8
    .line 9
    if-ne p0, v0, :cond_1

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    :cond_1
    return-object p0
.end method

.method public static unescapeThrowable(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<V:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Object;",
            ")TV;"
        }
    .end annotation

    .line 1
    instance-of v0, p0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$ThrowableWrapper;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$ThrowableWrapper;

    .line 6
    .line 7
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$ThrowableWrapper;->getThrowable()Ljava/lang/Throwable;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    sget-boolean v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues;->throwWrappedProcessCanceledException:Z

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/utils/ExceptionUtilsKt;->isProcessCanceledException(Ljava/lang/Throwable;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$WrappedProcessCanceledException;

    .line 22
    .line 23
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/impl/utils/WrappedValues$WrappedProcessCanceledException;-><init>(Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    throw v0

    .line 27
    :cond_0
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/utils/ExceptionUtilsKt;->rethrow(Ljava/lang/Throwable;)Ljava/lang/RuntimeException;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    throw p0

    .line 32
    :cond_1
    return-object p0
.end method
