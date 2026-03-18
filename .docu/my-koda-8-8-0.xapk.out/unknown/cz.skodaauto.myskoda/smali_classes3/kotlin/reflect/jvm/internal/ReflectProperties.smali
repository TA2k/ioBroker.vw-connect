.class public Lkotlin/reflect/jvm/internal/ReflectProperties;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;,
        Lkotlin/reflect/jvm/internal/ReflectProperties$Val;
    }
.end annotation


# direct methods
.method private static synthetic $$$reportNull$$$0(I)V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 2
    .line 3
    const-string v0, "Argument for @NotNull parameter \'initializer\' of kotlin/reflect/jvm/internal/ReflectProperties.lazySoft must not be null"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public static lazySoft(Lay0/a;)Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lay0/a;",
            ")",
            "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal<",
            "TT;>;"
        }
    .end annotation

    if-nez p0, :cond_0

    const/4 v0, 0x1

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/ReflectProperties;->$$$reportNull$$$0(I)V

    :cond_0
    const/4 v0, 0x0

    .line 2
    invoke-static {v0, p0}, Lkotlin/reflect/jvm/internal/ReflectProperties;->lazySoft(Ljava/lang/Object;Lay0/a;)Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;

    move-result-object p0

    return-object p0
.end method

.method public static lazySoft(Ljava/lang/Object;Lay0/a;)Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(TT;",
            "Lay0/a;",
            ")",
            "Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal<",
            "TT;>;"
        }
    .end annotation

    if-nez p1, :cond_0

    const/4 v0, 0x0

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/ReflectProperties;->$$$reportNull$$$0(I)V

    .line 1
    :cond_0
    new-instance v0, Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;

    invoke-direct {v0, p0, p1}, Lkotlin/reflect/jvm/internal/ReflectProperties$LazySoftVal;-><init>(Ljava/lang/Object;Lay0/a;)V

    return-object v0
.end method
