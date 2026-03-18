.class final Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = null
.end annotation


# direct methods
.method private static synthetic $$$reportNull$$$0(I)V
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v2, "fqName"

    .line 9
    .line 10
    aput-object v2, v0, v1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :pswitch_0
    const-string v2, "javaClass"

    .line 14
    .line 15
    aput-object v2, v0, v1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :pswitch_1
    const-string v2, "field"

    .line 19
    .line 20
    aput-object v2, v0, v1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :pswitch_2
    const-string v2, "element"

    .line 24
    .line 25
    aput-object v2, v0, v1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_3
    const-string v2, "descriptor"

    .line 29
    .line 30
    aput-object v2, v0, v1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :pswitch_4
    const-string v2, "member"

    .line 34
    .line 35
    aput-object v2, v0, v1

    .line 36
    .line 37
    :goto_0
    const/4 v1, 0x1

    .line 38
    const-string v2, "kotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1"

    .line 39
    .line 40
    aput-object v2, v0, v1

    .line 41
    .line 42
    const/4 v1, 0x2

    .line 43
    packed-switch p0, :pswitch_data_1

    .line 44
    .line 45
    .line 46
    const-string p0, "getClassResolvedFromSource"

    .line 47
    .line 48
    aput-object p0, v0, v1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :pswitch_5
    const-string p0, "recordClass"

    .line 52
    .line 53
    aput-object p0, v0, v1

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :pswitch_6
    const-string p0, "recordField"

    .line 57
    .line 58
    aput-object p0, v0, v1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :pswitch_7
    const-string p0, "recordConstructor"

    .line 62
    .line 63
    aput-object p0, v0, v1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :pswitch_8
    const-string p0, "recordMethod"

    .line 67
    .line 68
    aput-object p0, v0, v1

    .line 69
    .line 70
    :goto_1
    const-string p0, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    .line 71
    .line 72
    invoke-static {p0, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 77
    .line 78
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw v0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_3
        :pswitch_0
        :pswitch_3
    .end packed-switch

    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    .line 102
    .line 103
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_7
        :pswitch_6
        :pswitch_6
        :pswitch_5
        :pswitch_5
    .end packed-switch
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getClassResolvedFromSource(Lkotlin/reflect/jvm/internal/impl/name/FqName;)Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return-object p0
.end method

.method public recordClass(Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaClass;Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x7

    .line 4
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/16 p0, 0x8

    .line 10
    .line 11
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 12
    .line 13
    .line 14
    :cond_1
    return-void
.end method

.method public recordConstructor(Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaElement;Lkotlin/reflect/jvm/internal/impl/descriptors/ConstructorDescriptor;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x3

    .line 4
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x4

    .line 10
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 11
    .line 12
    .line 13
    :cond_1
    return-void
.end method

.method public recordField(Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaField;Lkotlin/reflect/jvm/internal/impl/descriptors/PropertyDescriptor;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x5

    .line 4
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x6

    .line 10
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 11
    .line 12
    .line 13
    :cond_1
    return-void
.end method

.method public recordMethod(Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaMember;Lkotlin/reflect/jvm/internal/impl/descriptors/SimpleFunctionDescriptor;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x2

    .line 10
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1;->$$$reportNull$$$0(I)V

    .line 11
    .line 12
    .line 13
    :cond_1
    return-void
.end method
