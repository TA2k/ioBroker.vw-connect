.class final Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;
.super Lkotlin/reflect/jvm/internal/impl/resolve/NonReportingOverrideStrategy;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils;->resolveOverrides(Lkotlin/reflect/jvm/internal/impl/name/Name;Ljava/util/Collection;Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/ErrorReporter;Lkotlin/reflect/jvm/internal/impl/resolve/OverridingUtil;Z)Ljava/util/Collection;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = null
.end annotation


# instance fields
.field final synthetic val$errorReporter:Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/ErrorReporter;

.field final synthetic val$isStaticContext:Z

.field final synthetic val$result:Ljava/util/Set;


# direct methods
.method private static synthetic $$$reportNull$$$0(I)V
    .locals 7

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const/4 v2, 0x4

    .line 5
    const/4 v3, 0x0

    .line 6
    const/4 v4, 0x2

    .line 7
    const/4 v5, 0x1

    .line 8
    if-eq p0, v5, :cond_3

    .line 9
    .line 10
    if-eq p0, v4, :cond_2

    .line 11
    .line 12
    if-eq p0, v0, :cond_1

    .line 13
    .line 14
    if-eq p0, v2, :cond_0

    .line 15
    .line 16
    const-string v6, "fakeOverride"

    .line 17
    .line 18
    aput-object v6, v1, v3

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const-string v6, "overridden"

    .line 22
    .line 23
    aput-object v6, v1, v3

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const-string v6, "member"

    .line 27
    .line 28
    aput-object v6, v1, v3

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_2
    const-string v6, "fromCurrent"

    .line 32
    .line 33
    aput-object v6, v1, v3

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_3
    const-string v6, "fromSuper"

    .line 37
    .line 38
    aput-object v6, v1, v3

    .line 39
    .line 40
    :goto_0
    const-string v3, "kotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1"

    .line 41
    .line 42
    aput-object v3, v1, v5

    .line 43
    .line 44
    if-eq p0, v5, :cond_5

    .line 45
    .line 46
    if-eq p0, v4, :cond_5

    .line 47
    .line 48
    if-eq p0, v0, :cond_4

    .line 49
    .line 50
    if-eq p0, v2, :cond_4

    .line 51
    .line 52
    const-string p0, "addFakeOverride"

    .line 53
    .line 54
    aput-object p0, v1, v4

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_4
    const-string p0, "setOverriddenDescriptors"

    .line 58
    .line 59
    aput-object p0, v1, v4

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_5
    const-string p0, "conflict"

    .line 63
    .line 64
    aput-object p0, v1, v4

    .line 65
    .line 66
    :goto_1
    const-string p0, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    .line 67
    .line 68
    invoke-static {p0, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 73
    .line 74
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0
.end method

.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/ErrorReporter;Ljava/util/Set;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->val$errorReporter:Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/ErrorReporter;

    .line 2
    .line 3
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->val$result:Ljava/util/Set;

    .line 4
    .line 5
    iput-boolean p3, p0, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->val$isStaticContext:Z

    .line 6
    .line 7
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/resolve/NonReportingOverrideStrategy;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public addFakeOverride(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1$1;

    .line 8
    .line 9
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1$1;-><init>(Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/reflect/jvm/internal/impl/resolve/OverridingUtil;->resolveUnknownVisibilityForMember(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Lay0/k;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->val$result:Ljava/util/Set;

    .line 16
    .line 17
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public conflict(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x2

    .line 10
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->$$$reportNull$$$0(I)V

    .line 11
    .line 12
    .line 13
    :cond_1
    return-void
.end method

.method public setOverriddenDescriptors(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Ljava/util/Collection;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;",
            "Ljava/util/Collection<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;",
            ">;)V"
        }
    .end annotation

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/4 v0, 0x4

    .line 10
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->$$$reportNull$$$0(I)V

    .line 11
    .line 12
    .line 13
    :cond_1
    iget-boolean v0, p0, Lkotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1;->val$isStaticContext:Z

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;->getKind()Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor$Kind;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor$Kind;->FAKE_OVERRIDE:Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor$Kind;

    .line 22
    .line 23
    if-eq v0, v1, :cond_2

    .line 24
    .line 25
    return-void

    .line 26
    :cond_2
    invoke-super {p0, p1, p2}, Lkotlin/reflect/jvm/internal/impl/resolve/OverridingStrategy;->setOverriddenDescriptors(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Ljava/util/Collection;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
