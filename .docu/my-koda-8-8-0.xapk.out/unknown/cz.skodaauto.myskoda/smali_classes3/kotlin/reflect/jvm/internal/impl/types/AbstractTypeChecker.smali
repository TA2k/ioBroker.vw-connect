.class public final Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$WhenMappings;
    }
.end annotation


# static fields
.field public static final INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

.field public static RUN_SLOW_ASSERTIONS:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 2
    .line 3
    invoke-direct {v0}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic accessor$AbstractTypeChecker$lambda0(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$ForkPointContext;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOfForSingleClassifierType$lambda$5(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$ForkPointContext;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$AbstractTypeChecker$lambda1(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOfForSingleClassifierType$lambda$5$0(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private final checkSubtypeForIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Ljava/lang/Boolean;
    .locals 1

    .line 1
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType$isIntegerLiteralTypeOrCapturedOne(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType$isIntegerLiteralTypeOrCapturedOne(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_1
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    const/4 p0, 0x0

    .line 37
    invoke-static {p2, p1, p3, p4, p0}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType$isTypeInIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Z)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_4

    .line 42
    .line 43
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_2
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_4

    .line 51
    .line 52
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType$isIntegerLiteralTypeInIntersectionComponents(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-nez p0, :cond_3

    .line 57
    .line 58
    const/4 p0, 0x1

    .line 59
    invoke-static {p2, p1, p4, p3, p0}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType$isTypeInIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Z)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-eqz p0, :cond_4

    .line 64
    .line 65
    :cond_3
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 66
    .line 67
    return-object p0

    .line 68
    :cond_4
    return-object v0
.end method

.method private static final checkSubtypeForIntegerLiteralType$isCapturedIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 8
    .line 9
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeConstructorMarker;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->projection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeConstructorMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->upperBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    const/4 p1, 0x1

    .line 34
    if-ne p0, p1, :cond_1

    .line 35
    .line 36
    return p1

    .line 37
    :cond_1
    return v1
.end method

.method private static final checkSubtypeForIntegerLiteralType$isIntegerLiteralTypeInIntersectionComponents(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 2

    .line 1
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/types/model/IntersectionTypeConstructorMarker;

    .line 6
    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->supertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Ljava/lang/Iterable;

    .line 14
    .line 15
    instance-of v0, p1, Ljava/util/Collection;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    move-object v0, p1

    .line 20
    check-cast v0, Ljava/util/Collection;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 44
    .line 45
    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asRigidType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    const/4 v1, 0x1

    .line 56
    if-ne v0, v1, :cond_1

    .line 57
    .line 58
    return v1

    .line 59
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 60
    return p0
.end method

.method private static final checkSubtypeForIntegerLiteralType$isIntegerLiteralTypeOrCapturedOne(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 1

    .line 1
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType$isCapturedIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method private static final checkSubtypeForIntegerLiteralType$isTypeInIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Z)Z
    .locals 9

    .line 1
    invoke-static {p0, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->possibleIntegerTypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    check-cast p2, Ljava/lang/Iterable;

    .line 6
    .line 7
    instance-of v0, p2, Ljava/util/Collection;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    move-object v0, p2

    .line 13
    check-cast v0, Ljava/util/Collection;

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    return v1

    .line 22
    :cond_0
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_4

    .line 31
    .line 32
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    move-object v5, v0

    .line 37
    check-cast v5, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 38
    .line 39
    invoke-static {p0, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-static {p0, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_3

    .line 52
    .line 53
    if-eqz p4, :cond_1

    .line 54
    .line 55
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 56
    .line 57
    const/16 v7, 0x8

    .line 58
    .line 59
    const/4 v8, 0x0

    .line 60
    const/4 v6, 0x0

    .line 61
    move-object v3, p1

    .line 62
    move-object v4, p3

    .line 63
    invoke-static/range {v2 .. v8}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    move-object v3, p1

    .line 71
    move-object v4, p3

    .line 72
    :cond_2
    move-object p1, v3

    .line 73
    move-object p3, v4

    .line 74
    goto :goto_0

    .line 75
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 76
    return p0

    .line 77
    :cond_4
    return v1
.end method

.method private final checkSubtypeForSpecialCases(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Ljava/lang/Boolean;
    .locals 12

    .line 1
    move-object/from16 v8, p4

    .line 2
    .line 3
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isError(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v9, 0x0

    .line 8
    if-nez v1, :cond_15

    .line 9
    .line 10
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isError(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    goto/16 :goto_7

    .line 17
    .line 18
    :cond_0
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isStubTypeForBuilderInference(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    const/4 v10, 0x1

    .line 23
    if-eqz v1, :cond_3

    .line 24
    .line 25
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isStubTypeForBuilderInference(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_3

    .line 30
    .line 31
    invoke-direct {p0, p2, p3, v8}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isStubTypeSubtypeOfAnother(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isStubTypeEqualsToAnything()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    :cond_1
    move v9, v10

    .line 44
    :cond_2
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    return-object v0

    .line 49
    :cond_3
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isStubType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_14

    .line 54
    .line 55
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isStubType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_4

    .line 60
    .line 61
    goto/16 :goto_6

    .line 62
    .line 63
    :cond_4
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asCapturedTypeUnwrappingDnn(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    const/4 v11, 0x0

    .line 68
    if-eqz v1, :cond_5

    .line 69
    .line 70
    invoke-static {p2, v1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->lowerType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    goto :goto_0

    .line 75
    :cond_5
    move-object v3, v11

    .line 76
    :goto_0
    if-eqz v1, :cond_b

    .line 77
    .line 78
    if-eqz v3, :cond_b

    .line 79
    .line 80
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    if-eqz v4, :cond_6

    .line 85
    .line 86
    invoke-static {p2, v3, v10}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->withNullability(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    goto :goto_1

    .line 91
    :cond_6
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDefinitelyNotNullType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    if-eqz v4, :cond_7

    .line 96
    .line 97
    invoke-static {p2, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->makeDefinitelyNotNullOrNotNull(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    :cond_7
    :goto_1
    invoke-virtual {p1, p3, v1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getLowerCapturedTypePolicy(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$LowerCapturedTypePolicy;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    sget-object v5, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$WhenMappings;->$EnumSwitchMapping$1:[I

    .line 106
    .line 107
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    aget v1, v5, v1

    .line 112
    .line 113
    if-eq v1, v10, :cond_a

    .line 114
    .line 115
    const/4 v5, 0x2

    .line 116
    if-eq v1, v5, :cond_9

    .line 117
    .line 118
    const/4 v3, 0x3

    .line 119
    if-ne v1, v3, :cond_8

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_8
    new-instance v0, La8/r0;

    .line 123
    .line 124
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 125
    .line 126
    .line 127
    throw v0

    .line 128
    :cond_9
    const/16 v5, 0x8

    .line 129
    .line 130
    const/4 v6, 0x0

    .line 131
    const/4 v4, 0x0

    .line 132
    move-object v0, p0

    .line 133
    move-object v1, p1

    .line 134
    move-object v2, p3

    .line 135
    invoke-static/range {v0 .. v6}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    if-eqz v3, :cond_b

    .line 140
    .line 141
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 142
    .line 143
    return-object v0

    .line 144
    :cond_a
    const/16 v5, 0x8

    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    const/4 v4, 0x0

    .line 148
    move-object v0, p0

    .line 149
    move-object v1, p1

    .line 150
    move-object v2, p3

    .line 151
    invoke-static/range {v0 .. v6}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    return-object v0

    .line 160
    :cond_b
    :goto_2
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    invoke-static {p2, v1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntersection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 165
    .line 166
    .line 167
    move-result v2

    .line 168
    if-eqz v2, :cond_f

    .line 169
    .line 170
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 171
    .line 172
    .line 173
    invoke-static {p2, v1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->supertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/Collection;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    check-cast v0, Ljava/lang/Iterable;

    .line 178
    .line 179
    instance-of v1, v0, Ljava/util/Collection;

    .line 180
    .line 181
    if-eqz v1, :cond_d

    .line 182
    .line 183
    move-object v1, v0

    .line 184
    check-cast v1, Ljava/util/Collection;

    .line 185
    .line 186
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    if-eqz v1, :cond_d

    .line 191
    .line 192
    :cond_c
    move v9, v10

    .line 193
    goto :goto_3

    .line 194
    :cond_d
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 195
    .line 196
    .line 197
    move-result-object v7

    .line 198
    :cond_e
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    if-eqz v0, :cond_c

    .line 203
    .line 204
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    move-object v3, v0

    .line 209
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 210
    .line 211
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 212
    .line 213
    const/16 v5, 0x8

    .line 214
    .line 215
    const/4 v6, 0x0

    .line 216
    const/4 v4, 0x0

    .line 217
    move-object v1, p1

    .line 218
    move-object v2, p3

    .line 219
    invoke-static/range {v0 .. v6}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v0

    .line 223
    if-nez v0, :cond_e

    .line 224
    .line 225
    :goto_3
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    return-object v0

    .line 230
    :cond_f
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    instance-of v3, p3, Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 235
    .line 236
    if-nez v3, :cond_12

    .line 237
    .line 238
    invoke-static {p2, v1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntersection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 239
    .line 240
    .line 241
    move-result v3

    .line 242
    if-eqz v3, :cond_13

    .line 243
    .line 244
    invoke-static {p2, v1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->supertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/Collection;

    .line 245
    .line 246
    .line 247
    move-result-object v1

    .line 248
    check-cast v1, Ljava/lang/Iterable;

    .line 249
    .line 250
    instance-of v3, v1, Ljava/util/Collection;

    .line 251
    .line 252
    if-eqz v3, :cond_10

    .line 253
    .line 254
    move-object v3, v1

    .line 255
    check-cast v3, Ljava/util/Collection;

    .line 256
    .line 257
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 258
    .line 259
    .line 260
    move-result v3

    .line 261
    if-eqz v3, :cond_10

    .line 262
    .line 263
    goto :goto_4

    .line 264
    :cond_10
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    :cond_11
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 269
    .line 270
    .line 271
    move-result v3

    .line 272
    if-eqz v3, :cond_12

    .line 273
    .line 274
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 279
    .line 280
    instance-of v3, v3, Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 281
    .line 282
    if-nez v3, :cond_11

    .line 283
    .line 284
    goto :goto_5

    .line 285
    :cond_12
    :goto_4
    invoke-direct {p0, p2, v8, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->getTypeParameterForArgumentInBaseIfItEqualToTarget(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    if-eqz v0, :cond_13

    .line 290
    .line 291
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    invoke-static {p2, v0, v1}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->hasRecursiveBounds(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 296
    .line 297
    .line 298
    move-result v0

    .line 299
    if-eqz v0, :cond_13

    .line 300
    .line 301
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 302
    .line 303
    return-object v0

    .line 304
    :cond_13
    :goto_5
    return-object v11

    .line 305
    :cond_14
    :goto_6
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isStubTypeEqualsToAnything()Z

    .line 306
    .line 307
    .line 308
    move-result v0

    .line 309
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    return-object v0

    .line 314
    :cond_15
    :goto_7
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isErrorTypeEqualsToAnything()Z

    .line 315
    .line 316
    .line 317
    move-result v0

    .line 318
    if-eqz v0, :cond_16

    .line 319
    .line 320
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 321
    .line 322
    return-object v0

    .line 323
    :cond_16
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 324
    .line 325
    .line 326
    move-result v0

    .line 327
    if-eqz v0, :cond_17

    .line 328
    .line 329
    invoke-static {p2, v8}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 330
    .line 331
    .line 332
    move-result v0

    .line 333
    if-nez v0, :cond_17

    .line 334
    .line 335
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 336
    .line 337
    return-object v0

    .line 338
    :cond_17
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractStrictEqualityTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractStrictEqualityTypeChecker;

    .line 339
    .line 340
    invoke-static {p2, p3, v9}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->withNullability(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Z)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    invoke-static {p2, v8, v9}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->withNullability(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Z)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 345
    .line 346
    .line 347
    move-result-object v2

    .line 348
    invoke-virtual {v0, p2, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/AbstractStrictEqualityTypeChecker;->strictEqualTypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 349
    .line 350
    .line 351
    move-result v0

    .line 352
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    return-object v0
.end method

.method private final collectAllSupertypesWithGivenTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;",
            ")",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p2, p3, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->fastCorrespondingSupertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 13
    .line 14
    if-nez p0, :cond_1

    .line 15
    .line 16
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_1
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isCommonFinalClassConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_4

    .line 28
    .line 29
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-interface {p2, p0, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->areEqualTypeConstructors(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_3

    .line 38
    .line 39
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;->FOR_SUBTYPING:Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;

    .line 40
    .line 41
    invoke-interface {p2, p3, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->captureFromArguments(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    if-nez p0, :cond_2

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    move-object p3, p0

    .line 49
    :goto_0
    invoke-static {p3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_3
    return-object v0

    .line 55
    :cond_4
    new-instance p0, Lkotlin/reflect/jvm/internal/impl/utils/SmartList;

    .line 56
    .line 57
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/utils/SmartList;-><init>()V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->initialize()V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getSupertypesDeque()Ljava/util/ArrayDeque;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getSupertypesSet()Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0, p3}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_5
    :goto_1
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 81
    .line 82
    .line 83
    move-result p3

    .line 84
    if-nez p3, :cond_b

    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p3

    .line 90
    check-cast p3, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 91
    .line 92
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    invoke-interface {v1, p3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_5

    .line 100
    .line 101
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;->FOR_SUBTYPING:Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;

    .line 102
    .line 103
    invoke-interface {p2, p3, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->captureFromArguments(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    if-nez v2, :cond_6

    .line 108
    .line 109
    move-object v2, p3

    .line 110
    :cond_6
    invoke-static {p2, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    invoke-interface {p2, v3, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->areEqualTypeConstructors(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    if-eqz v3, :cond_7

    .line 119
    .line 120
    invoke-interface {p0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_7
    invoke-static {p2, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->argumentsCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)I

    .line 127
    .line 128
    .line 129
    move-result v3

    .line 130
    if-nez v3, :cond_8

    .line 131
    .line 132
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$LowerIfFlexible;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$LowerIfFlexible;

    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_8
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    invoke-interface {v3, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->substitutionSupertypePolicy(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    :goto_2
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;

    .line 144
    .line 145
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v3

    .line 149
    if-nez v3, :cond_9

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_9
    const/4 v2, 0x0

    .line 153
    :goto_3
    if-nez v2, :cond_a

    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_a
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    invoke-interface {v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 161
    .line 162
    .line 163
    move-result-object p3

    .line 164
    invoke-interface {v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->supertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/Collection;

    .line 165
    .line 166
    .line 167
    move-result-object p3

    .line 168
    invoke-interface {p3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 169
    .line 170
    .line 171
    move-result-object p3

    .line 172
    :goto_4
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    if-eqz v3, :cond_5

    .line 177
    .line 178
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 183
    .line 184
    invoke-virtual {v2, p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy;->transformType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    invoke-virtual {v0, v3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    goto :goto_4

    .line 192
    :cond_b
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->clear()V

    .line 193
    .line 194
    .line 195
    return-object p0
.end method

.method private final collectAndFilter(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;",
            ")",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2, p3, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->collectAllSupertypesWithGivenTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-direct {p0, p2, p1}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->selectOnlyPureKotlinSupertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Ljava/util/List;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final completeIsSubTypeOf(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Z
    .locals 6

    .line 1
    invoke-virtual {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->refineType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 2
    .line 3
    .line 4
    move-result-object p3

    .line 5
    invoke-virtual {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->prepareType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 6
    .line 7
    .line 8
    move-result-object p3

    .line 9
    invoke-virtual {p1, p4}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->refineType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 10
    .line 11
    .line 12
    move-result-object p4

    .line 13
    invoke-virtual {p1, p4}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->prepareType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 14
    .line 15
    .line 16
    move-result-object p4

    .line 17
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isDnnTypesEqualToFlexible()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDefinitelyNotNullType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asFlexibleType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/FlexibleTypeMarker;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->lowerBound(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/FlexibleTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asRigidType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 47
    .line 48
    .line 49
    move-result-object p3

    .line 50
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->originalIfDefinitelyNotNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/SimpleTypeMarker;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    move-object v0, p0

    .line 58
    move-object v1, p1

    .line 59
    move-object v2, p2

    .line 60
    move v5, p5

    .line 61
    invoke-direct/range {v0 .. v5}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->completeIsSubTypeOf(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    return p0

    .line 66
    :cond_0
    move-object v0, p0

    .line 67
    move-object v1, p1

    .line 68
    move-object v2, p2

    .line 69
    move v5, p5

    .line 70
    invoke-static {v2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->lowerBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-static {v2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->upperBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-direct {v0, v1, v2, p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForSpecialCases(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Ljava/lang/Boolean;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-eqz p0, :cond_1

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    invoke-virtual {v1, p3, p4, v5}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->addSubtypeConstraint(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Ljava/lang/Boolean;

    .line 89
    .line 90
    .line 91
    return p0

    .line 92
    :cond_1
    invoke-virtual {v1, p3, p4, v5}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->addSubtypeConstraint(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Ljava/lang/Boolean;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-eqz p0, :cond_2

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    return p0

    .line 103
    :cond_2
    invoke-static {v2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->lowerBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-static {v2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->upperBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-direct {v0, v1, v2, p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOfForSingleClassifierType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    return p0
.end method

.method private final getTypeParameterForArgumentInBaseIfItEqualToTarget(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;
    .locals 6

    .line 1
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->argumentsCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    const/4 v3, 0x0

    .line 8
    if-ge v2, v0, :cond_6

    .line 9
    .line 10
    invoke-static {p1, p2, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getArgument(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 11
    .line 12
    .line 13
    move-result-object v4

    .line 14
    invoke-static {p1, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isStarProjection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Z

    .line 15
    .line 16
    .line 17
    move-result v5

    .line 18
    if-nez v5, :cond_0

    .line 19
    .line 20
    move-object v3, v4

    .line 21
    :cond_0
    if-eqz v3, :cond_5

    .line 22
    .line 23
    invoke-static {p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    if-nez v3, :cond_1

    .line 28
    .line 29
    goto :goto_3

    .line 30
    :cond_1
    invoke-static {p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->lowerBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-static {p1, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isCapturedType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    invoke-static {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->lowerBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-static {p1, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isCapturedType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_2

    .line 49
    .line 50
    const/4 v4, 0x1

    .line 51
    goto :goto_1

    .line 52
    :cond_2
    move v4, v1

    .line 53
    :goto_1
    invoke-virtual {v3, p3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    if-nez v5, :cond_4

    .line 58
    .line 59
    if-eqz v4, :cond_3

    .line 60
    .line 61
    invoke-static {p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    invoke-static {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    if-eqz v4, :cond_3

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    invoke-direct {p0, p1, v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->getTypeParameterForArgumentInBaseIfItEqualToTarget(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    if-eqz v3, :cond_5

    .line 81
    .line 82
    return-object v3

    .line 83
    :cond_4
    :goto_2
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-static {p1, p0, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getParameter(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    :cond_5
    :goto_3
    add-int/lit8 v2, v2, 0x1

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_6
    return-object v3
.end method

.method private final hasNothingSupertype(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 5

    .line 1
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p2, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {p2, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isNothingConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p2, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isNothingConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    const/4 v0, 0x1

    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    return v0

    .line 28
    :cond_1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->initialize()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getSupertypesDeque()Ljava/util/ArrayDeque;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getSupertypesSet()Ljava/util/Set;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, p3}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    :goto_0
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 49
    .line 50
    .line 51
    move-result p3

    .line 52
    if-nez p3, :cond_7

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p3

    .line 58
    check-cast p3, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 59
    .line 60
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    invoke-interface {v1, p3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-eqz v2, :cond_2

    .line 68
    .line 69
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_3

    .line 74
    .line 75
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_3
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$LowerIfFlexible;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$LowerIfFlexible;

    .line 79
    .line 80
    :goto_1
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;

    .line 81
    .line 82
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    if-nez v3, :cond_4

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_4
    const/4 v2, 0x0

    .line 90
    :goto_2
    if-nez v2, :cond_5

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    invoke-interface {v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 98
    .line 99
    .line 100
    move-result-object p3

    .line 101
    invoke-interface {v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->supertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/Collection;

    .line 102
    .line 103
    .line 104
    move-result-object p3

    .line 105
    invoke-interface {p3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object p3

    .line 109
    :goto_3
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-eqz v3, :cond_2

    .line 114
    .line 115
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 120
    .line 121
    invoke-virtual {v2, p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy;->transformType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    invoke-static {p2, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 126
    .line 127
    .line 128
    move-result-object v4

    .line 129
    invoke-static {p2, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isNothingConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-eqz v4, :cond_6

    .line 134
    .line 135
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->clear()V

    .line 136
    .line 137
    .line 138
    return v0

    .line 139
    :cond_6
    invoke-virtual {p0, v3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_7
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->clear()V

    .line 144
    .line 145
    .line 146
    const/4 p0, 0x0

    .line 147
    return p0
.end method

.method private final isCommonDenotableType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z
    .locals 0

    .line 1
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDenotable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDynamic(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDefinitelyNotNullType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isNotNullTypeParameter(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-nez p0, :cond_0

    .line 28
    .line 29
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isFlexibleWithDifferentTypeConstructors(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-nez p0, :cond_0

    .line 34
    .line 35
    const/4 p0, 0x1

    .line 36
    return p0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method private final isStubTypeSubtypeOfAnother(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 2

    .line 1
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eq p0, v0, :cond_0

    .line 11
    .line 12
    return v1

    .line 13
    :cond_0
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDefinitelyNotNullType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_1

    .line 18
    .line 19
    invoke-static {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isDefinitelyNotNullType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    return v1

    .line 26
    :cond_1
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_2

    .line 31
    .line 32
    invoke-static {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-nez p0, :cond_2

    .line 37
    .line 38
    return v1

    .line 39
    :cond_2
    const/4 p0, 0x1

    .line 40
    return p0
.end method

.method public static synthetic isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z
    .locals 0

    .line 1
    and-int/lit8 p5, p5, 0x8

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-virtual {p0, p1, p2, p3, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method private final isSubtypeOfForSingleClassifierType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    sget-boolean v5, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->RUN_SLOW_ASSERTIONS:Z

    .line 12
    .line 13
    if-eqz v5, :cond_1

    .line 14
    .line 15
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isSingleClassifierType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    if-nez v5, :cond_0

    .line 20
    .line 21
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 22
    .line 23
    .line 24
    move-result-object v5

    .line 25
    invoke-static {v2, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntersection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    if-nez v5, :cond_0

    .line 30
    .line 31
    invoke-virtual {v1, v3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isAllowedTypeVariable(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    :cond_0
    invoke-static {v2, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isSingleClassifierType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    if-nez v5, :cond_1

    .line 40
    .line 41
    invoke-virtual {v1, v4}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isAllowedTypeVariable(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    :cond_1
    sget-object v5, Lkotlin/reflect/jvm/internal/impl/types/AbstractNullabilityChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractNullabilityChecker;

    .line 46
    .line 47
    invoke-virtual {v5, v1, v3, v4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractNullabilityChecker;->isPossibleSubtype(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    const/4 v6, 0x0

    .line 52
    if-nez v5, :cond_2

    .line 53
    .line 54
    return v6

    .line 55
    :cond_2
    invoke-direct/range {p0 .. p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->checkSubtypeForIntegerLiteralType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Ljava/lang/Boolean;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    if-eqz v5, :cond_3

    .line 60
    .line 61
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 62
    .line 63
    .line 64
    move-result v6

    .line 65
    const/4 v4, 0x4

    .line 66
    const/4 v5, 0x0

    .line 67
    const/4 v3, 0x0

    .line 68
    move-object/from16 v2, p4

    .line 69
    .line 70
    move-object v0, v1

    .line 71
    move-object/from16 v1, p3

    .line 72
    .line 73
    invoke-static/range {v0 .. v5}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->addSubtypeConstraint$default(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    return v6

    .line 77
    :cond_3
    invoke-static {v2, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    invoke-interface {v2, v7, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->areEqualTypeConstructors(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 86
    .line 87
    .line 88
    move-result v7

    .line 89
    const/4 v8, 0x1

    .line 90
    if-eqz v7, :cond_4

    .line 91
    .line 92
    invoke-static {v2, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->parametersCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)I

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    if-nez v7, :cond_4

    .line 97
    .line 98
    return v8

    .line 99
    :cond_4
    invoke-static {v2, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    invoke-static {v2, v7}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isAnyConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 104
    .line 105
    .line 106
    move-result v7

    .line 107
    if-eqz v7, :cond_5

    .line 108
    .line 109
    return v8

    .line 110
    :cond_5
    invoke-virtual {v0, v1, v3, v5}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->findCorrespondingSupertypes(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    .line 111
    .line 112
    .line 113
    move-result-object v7

    .line 114
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 115
    .line 116
    .line 117
    move-result v9

    .line 118
    const/16 v10, 0xa

    .line 119
    .line 120
    if-le v9, v8, :cond_8

    .line 121
    .line 122
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 123
    .line 124
    .line 125
    move-result-object v9

    .line 126
    instance-of v12, v9, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemInferenceExtensionContext;

    .line 127
    .line 128
    if-eqz v12, :cond_6

    .line 129
    .line 130
    check-cast v9, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemInferenceExtensionContext;

    .line 131
    .line 132
    goto :goto_0

    .line 133
    :cond_6
    const/4 v9, 0x0

    .line 134
    :goto_0
    if-eqz v9, :cond_8

    .line 135
    .line 136
    invoke-interface {v9}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemInferenceExtensionContext;->isK2()Z

    .line 137
    .line 138
    .line 139
    move-result v9

    .line 140
    if-ne v9, v8, :cond_8

    .line 141
    .line 142
    check-cast v7, Ljava/lang/Iterable;

    .line 143
    .line 144
    new-instance v9, Ljava/util/LinkedHashSet;

    .line 145
    .line 146
    invoke-direct {v9}, Ljava/util/LinkedHashSet;-><init>()V

    .line 147
    .line 148
    .line 149
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 154
    .line 155
    .line 156
    move-result v12

    .line 157
    if-eqz v12, :cond_a

    .line 158
    .line 159
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v12

    .line 163
    check-cast v12, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 164
    .line 165
    invoke-virtual {v1, v12}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->prepareType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 166
    .line 167
    .line 168
    move-result-object v13

    .line 169
    invoke-static {v2, v13}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asRigidType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 170
    .line 171
    .line 172
    move-result-object v13

    .line 173
    if-nez v13, :cond_7

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_7
    move-object v12, v13

    .line 177
    :goto_2
    invoke-interface {v9, v12}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    goto :goto_1

    .line 181
    :cond_8
    check-cast v7, Ljava/lang/Iterable;

    .line 182
    .line 183
    new-instance v9, Ljava/util/ArrayList;

    .line 184
    .line 185
    invoke-static {v7, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 186
    .line 187
    .line 188
    move-result v12

    .line 189
    invoke-direct {v9, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 190
    .line 191
    .line 192
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 193
    .line 194
    .line 195
    move-result-object v7

    .line 196
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 197
    .line 198
    .line 199
    move-result v12

    .line 200
    if-eqz v12, :cond_a

    .line 201
    .line 202
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v12

    .line 206
    check-cast v12, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 207
    .line 208
    invoke-virtual {v1, v12}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->prepareType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 209
    .line 210
    .line 211
    move-result-object v13

    .line 212
    invoke-static {v2, v13}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asRigidType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 213
    .line 214
    .line 215
    move-result-object v13

    .line 216
    if-nez v13, :cond_9

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_9
    move-object v12, v13

    .line 220
    :goto_4
    invoke-interface {v9, v12}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    goto :goto_3

    .line 224
    :cond_a
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 225
    .line 226
    .line 227
    move-result v7

    .line 228
    if-eqz v7, :cond_14

    .line 229
    .line 230
    if-eq v7, v8, :cond_13

    .line 231
    .line 232
    new-instance v7, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;

    .line 233
    .line 234
    invoke-static {v2, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->parametersCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)I

    .line 235
    .line 236
    .line 237
    move-result v12

    .line 238
    invoke-direct {v7, v12}, Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;-><init>(I)V

    .line 239
    .line 240
    .line 241
    invoke-static {v2, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->parametersCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)I

    .line 242
    .line 243
    .line 244
    move-result v12

    .line 245
    move v13, v6

    .line 246
    move v14, v13

    .line 247
    :goto_5
    if-ge v13, v12, :cond_11

    .line 248
    .line 249
    if-nez v14, :cond_c

    .line 250
    .line 251
    invoke-static {v2, v5, v13}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getParameter(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;

    .line 252
    .line 253
    .line 254
    move-result-object v14

    .line 255
    invoke-static {v2, v14}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 256
    .line 257
    .line 258
    move-result-object v14

    .line 259
    sget-object v15, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->OUT:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 260
    .line 261
    if-eq v14, v15, :cond_b

    .line 262
    .line 263
    goto :goto_6

    .line 264
    :cond_b
    move v14, v6

    .line 265
    goto :goto_7

    .line 266
    :cond_c
    :goto_6
    move v14, v8

    .line 267
    :goto_7
    if-nez v14, :cond_10

    .line 268
    .line 269
    new-instance v15, Ljava/util/ArrayList;

    .line 270
    .line 271
    invoke-static {v9, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 272
    .line 273
    .line 274
    move-result v6

    .line 275
    invoke-direct {v15, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 276
    .line 277
    .line 278
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 279
    .line 280
    .line 281
    move-result-object v6

    .line 282
    :goto_8
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 283
    .line 284
    .line 285
    move-result v16

    .line 286
    if-eqz v16, :cond_f

    .line 287
    .line 288
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v16

    .line 292
    move/from16 v17, v8

    .line 293
    .line 294
    move-object/from16 v8, v16

    .line 295
    .line 296
    check-cast v8, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 297
    .line 298
    invoke-static {v2, v8, v13}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getArgumentOrNull(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 299
    .line 300
    .line 301
    move-result-object v10

    .line 302
    if-eqz v10, :cond_e

    .line 303
    .line 304
    invoke-static {v2, v10}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 305
    .line 306
    .line 307
    move-result-object v11

    .line 308
    move-object/from16 v18, v5

    .line 309
    .line 310
    sget-object v5, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->INV:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 311
    .line 312
    if-ne v11, v5, :cond_d

    .line 313
    .line 314
    goto :goto_9

    .line 315
    :cond_d
    const/4 v10, 0x0

    .line 316
    :goto_9
    if-eqz v10, :cond_e

    .line 317
    .line 318
    invoke-static {v2, v10}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 319
    .line 320
    .line 321
    move-result-object v5

    .line 322
    if-eqz v5, :cond_e

    .line 323
    .line 324
    invoke-interface {v15, v5}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 325
    .line 326
    .line 327
    move/from16 v8, v17

    .line 328
    .line 329
    move-object/from16 v5, v18

    .line 330
    .line 331
    const/16 v10, 0xa

    .line 332
    .line 333
    goto :goto_8

    .line 334
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 335
    .line 336
    new-instance v1, Ljava/lang/StringBuilder;

    .line 337
    .line 338
    const-string v2, "Incorrect type: "

    .line 339
    .line 340
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 344
    .line 345
    .line 346
    const-string v2, ", subType: "

    .line 347
    .line 348
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 349
    .line 350
    .line 351
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 352
    .line 353
    .line 354
    const-string v2, ", superType: "

    .line 355
    .line 356
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 360
    .line 361
    .line 362
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 363
    .line 364
    .line 365
    move-result-object v1

    .line 366
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v1

    .line 370
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    throw v0

    .line 374
    :cond_f
    move-object/from16 v18, v5

    .line 375
    .line 376
    move/from16 v17, v8

    .line 377
    .line 378
    invoke-interface {v2, v15}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->intersectTypes(Ljava/util/Collection;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 379
    .line 380
    .line 381
    move-result-object v5

    .line 382
    invoke-static {v2, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asTypeArgument(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 383
    .line 384
    .line 385
    move-result-object v5

    .line 386
    invoke-virtual {v7, v5}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 387
    .line 388
    .line 389
    goto :goto_a

    .line 390
    :cond_10
    move-object/from16 v18, v5

    .line 391
    .line 392
    move/from16 v17, v8

    .line 393
    .line 394
    :goto_a
    add-int/lit8 v13, v13, 0x1

    .line 395
    .line 396
    move/from16 v8, v17

    .line 397
    .line 398
    move-object/from16 v5, v18

    .line 399
    .line 400
    const/4 v6, 0x0

    .line 401
    const/16 v10, 0xa

    .line 402
    .line 403
    goto/16 :goto_5

    .line 404
    .line 405
    :cond_11
    move/from16 v17, v8

    .line 406
    .line 407
    if-nez v14, :cond_12

    .line 408
    .line 409
    invoke-virtual {v0, v1, v2, v7, v4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeForSameConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 410
    .line 411
    .line 412
    move-result v0

    .line 413
    if-eqz v0, :cond_12

    .line 414
    .line 415
    return v17

    .line 416
    :cond_12
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;

    .line 417
    .line 418
    invoke-direct {v0, v9, v1, v2, v4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;-><init>(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v1, v0}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->runForkingPoint(Lay0/k;)Z

    .line 422
    .line 423
    .line 424
    move-result v0

    .line 425
    return v0

    .line 426
    :cond_13
    invoke-static {v9}, Lmx0/q;->I(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 431
    .line 432
    invoke-static {v2, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asArgumentList(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;

    .line 433
    .line 434
    .line 435
    move-result-object v3

    .line 436
    invoke-virtual {v0, v1, v2, v3, v4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeForSameConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 437
    .line 438
    .line 439
    move-result v0

    .line 440
    return v0

    .line 441
    :cond_14
    invoke-direct/range {p0 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->hasNothingSupertype(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 442
    .line 443
    .line 444
    move-result v0

    .line 445
    return v0
.end method

.method private static final isSubtypeOfForSingleClassifierType$lambda$5(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$ForkPointContext;)Llx0/b0;
    .locals 2

    .line 1
    const-string v0, "$this$runForkingPoint"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 21
    .line 22
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$1;

    .line 23
    .line 24
    invoke-direct {v1, p1, p2, v0, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$1;-><init>(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p4, v1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$ForkPointContext;->fork(Lay0/a;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method

.method private static final isSubtypeOfForSingleClassifierType$lambda$5$0(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asArgumentList(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-virtual {v0, p0, p1, p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeForSameConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method private final isTypeVariableAgainstStarProjectionForSelfType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asRigidType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    instance-of p2, p0, Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    if-eqz p2, :cond_4

    .line 9
    .line 10
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isOldCapturedType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;)Z

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    if-nez p2, :cond_4

    .line 17
    .line 18
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeConstructorMarker;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->projection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeConstructorMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isStarProjection(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-nez p2, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->captureStatus(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/CapturedTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    sget-object p2, Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;->FOR_SUBTYPING:Lkotlin/reflect/jvm/internal/impl/types/model/CaptureStatus;

    .line 38
    .line 39
    if-eq p0, p2, :cond_1

    .line 40
    .line 41
    return v0

    .line 42
    :cond_1
    invoke-static {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    instance-of p2, p0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariableTypeConstructorMarker;

    .line 47
    .line 48
    if-eqz p2, :cond_2

    .line 49
    .line 50
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariableTypeConstructorMarker;

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    const/4 p0, 0x0

    .line 54
    :goto_0
    if-nez p0, :cond_3

    .line 55
    .line 56
    return v0

    .line 57
    :cond_3
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getTypeParameter(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariableTypeConstructorMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-eqz p0, :cond_4

    .line 62
    .line 63
    invoke-static {p1, p0, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->hasRecursiveBounds(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    const/4 p1, 0x1

    .line 68
    if-ne p0, p1, :cond_4

    .line 69
    .line 70
    return p1

    .line 71
    :cond_4
    :goto_1
    return v0
.end method

.method private final selectOnlyPureKotlinSupertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Ljava/util/List;)Ljava/util/List;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;",
            "Ljava/util/List<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            ">;)",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x2

    .line 6
    if-ge p0, v0, :cond_0

    .line 7
    .line 8
    goto :goto_3

    .line 9
    :cond_0
    move-object p0, p2

    .line 10
    check-cast p0, Ljava/lang/Iterable;

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_4

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    move-object v2, v1

    .line 32
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 33
    .line 34
    invoke-static {p1, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asArgumentList(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-interface {p1, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->size(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;)I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    const/4 v4, 0x0

    .line 43
    :goto_1
    if-ge v4, v3, :cond_3

    .line 44
    .line 45
    invoke-interface {p1, v2, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->get(Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    invoke-static {p1, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    if-eqz v5, :cond_2

    .line 54
    .line 55
    invoke-static {p1, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->asFlexibleType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/FlexibleTypeMarker;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    goto :goto_2

    .line 60
    :cond_2
    const/4 v5, 0x0

    .line 61
    :goto_2
    if-nez v5, :cond_1

    .line 62
    .line 63
    add-int/lit8 v4, v4, 0x1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_4
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    if-nez p0, :cond_5

    .line 75
    .line 76
    return-object v0

    .line 77
    :cond_5
    :goto_3
    return-object p2
.end method


# virtual methods
.method public final effectiveVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;
    .locals 0

    .line 1
    const-string p0, "declared"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "useSite"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->INV:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 12
    .line 13
    if-ne p1, p0, :cond_0

    .line 14
    .line 15
    return-object p2

    .line 16
    :cond_0
    if-ne p2, p0, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    if-ne p1, p2, :cond_2

    .line 20
    .line 21
    :goto_0
    return-object p1

    .line 22
    :cond_2
    const/4 p0, 0x0

    .line 23
    return-object p0
.end method

.method public final equalTypes(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z
    .locals 10

    .line 1
    const-string p0, "state"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "a"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "b"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 v0, 0x1

    .line 21
    if-ne p2, p3, :cond_0

    .line 22
    .line 23
    return v0

    .line 24
    :cond_0
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 25
    .line 26
    invoke-direct {v1, p0, p2}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isCommonDenotableType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    const/4 v8, 0x0

    .line 31
    if-eqz v2, :cond_5

    .line 32
    .line 33
    invoke-direct {v1, p0, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isCommonDenotableType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_5

    .line 38
    .line 39
    invoke-virtual {p1, p2}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->refineType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-virtual {p1, v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->prepareType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {p1, p3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->refineType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->prepareType(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    invoke-interface {p0, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->lowerBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    invoke-interface {p0, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    invoke-interface {p0, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    invoke-interface {p0, v5, v6}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->areEqualTypeConstructors(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    if-nez v5, :cond_1

    .line 72
    .line 73
    return v8

    .line 74
    :cond_1
    invoke-interface {p0, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->argumentsCount(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    if-nez v5, :cond_5

    .line 79
    .line 80
    invoke-interface {p0, v2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->hasFlexibleNullability(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    if-nez p1, :cond_4

    .line 85
    .line 86
    invoke-interface {p0, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->hasFlexibleNullability(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    if-eqz p1, :cond_2

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_2
    invoke-interface {p0, v4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    invoke-interface {p0, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->lowerBoundIfFlexible(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    invoke-interface {p0, p2}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->isMarkedNullable(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-ne p1, p0, :cond_3

    .line 106
    .line 107
    return v0

    .line 108
    :cond_3
    return v8

    .line 109
    :cond_4
    :goto_0
    return v0

    .line 110
    :cond_5
    const/16 v6, 0x8

    .line 111
    .line 112
    const/4 v7, 0x0

    .line 113
    const/4 v5, 0x0

    .line 114
    move-object v2, p1

    .line 115
    move-object v3, p2

    .line 116
    move-object v4, p3

    .line 117
    invoke-static/range {v1 .. v7}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    if-eqz p0, :cond_6

    .line 122
    .line 123
    const/16 v6, 0x8

    .line 124
    .line 125
    const/4 v7, 0x0

    .line 126
    const/4 v5, 0x0

    .line 127
    move-object v9, v4

    .line 128
    move-object v4, v3

    .line 129
    move-object v3, v9

    .line 130
    invoke-static/range {v1 .. v7}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-eqz p0, :cond_6

    .line 135
    .line 136
    return v0

    .line 137
    :cond_6
    return v8
.end method

.method public final findCorrespondingSupertypes(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;",
            ")",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            ">;"
        }
    .end annotation

    const-string p0, "state"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "subType"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "superConstructor"

    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    move-result-object p0

    .line 2
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    invoke-virtual {v0, p1, p0, p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->findCorrespondingSupertypes(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public final findCorrespondingSupertypes(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            "Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;",
            ")",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;",
            ">;"
        }
    .end annotation

    const-string v0, "state"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "c"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subType"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "superConstructor"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 4
    invoke-direct {p0, p1, p2, p3, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->collectAndFilter(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    move-result-object p0

    return-object p0

    .line 5
    :cond_0
    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-static {p2, p4}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isIntegerLiteralTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    move-result v0

    if-nez v0, :cond_1

    .line 6
    invoke-direct {p0, p1, p2, p3, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->collectAllSupertypesWithGivenTypeConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    move-result-object p0

    return-object p0

    .line 7
    :cond_1
    new-instance p0, Lkotlin/reflect/jvm/internal/impl/utils/SmartList;

    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/utils/SmartList;-><init>()V

    .line 8
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->initialize()V

    .line 9
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getSupertypesDeque()Ljava/util/ArrayDeque;

    move-result-object v0

    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getSupertypesSet()Ljava/util/Set;

    move-result-object v1

    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    invoke-virtual {v0, p3}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 12
    :cond_2
    :goto_0
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result p3

    if-nez p3, :cond_6

    .line 13
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 14
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-interface {v1, p3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    .line 15
    invoke-static {p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->isClassType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z

    move-result v2

    if-eqz v2, :cond_3

    .line 16
    invoke-virtual {p0, p3}, Lkotlin/reflect/jvm/internal/impl/utils/SmartList;->add(Ljava/lang/Object;)Z

    .line 17
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;

    goto :goto_1

    .line 18
    :cond_3
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$LowerIfFlexible;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$LowerIfFlexible;

    .line 19
    :goto_1
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy$None;

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_4

    goto :goto_2

    :cond_4
    const/4 v2, 0x0

    :goto_2
    if-nez v2, :cond_5

    goto :goto_0

    .line 20
    :cond_5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    move-result-object v3

    invoke-interface {v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    move-result-object p3

    invoke-interface {v3, p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;->supertypes(Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/Collection;

    move-result-object p3

    .line 21
    invoke-interface {p3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_3
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 22
    invoke-virtual {v2, p1, v3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$SupertypesPolicy;->transformType(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    move-result-object v3

    .line 23
    invoke-virtual {v0, v3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    goto :goto_3

    .line 24
    :cond_6
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->clear()V

    .line 25
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    .line 26
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    .line 27
    check-cast v0, Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 28
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-direct {v1, p1, p2, v0, p4}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->collectAndFilter(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Ljava/util/List;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    .line 29
    invoke-static {v0, p3}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_4

    :cond_7
    return-object p3
.end method

.method public final isSubtypeForSameConstructor(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Z
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v8, p2

    .line 6
    .line 7
    move-object/from16 v9, p3

    .line 8
    .line 9
    move-object/from16 v10, p4

    .line 10
    .line 11
    const-string v1, "state"

    .line 12
    .line 13
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v1, "c"

    .line 17
    .line 18
    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v1, "capturedSubArguments"

    .line 22
    .line 23
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, "superType"

    .line 27
    .line 28
    invoke-static {v10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v8, v10}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->typeConstructor(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;

    .line 32
    .line 33
    .line 34
    move-result-object v11

    .line 35
    invoke-static/range {p2 .. p3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->size(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    invoke-static {v8, v11}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->parametersCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)I

    .line 40
    .line 41
    .line 42
    move-result v12

    .line 43
    const/4 v13, 0x0

    .line 44
    if-ne v1, v12, :cond_a

    .line 45
    .line 46
    invoke-static {v8, v10}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->argumentsCount(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eq v1, v3, :cond_0

    .line 51
    .line 52
    goto/16 :goto_3

    .line 53
    .line 54
    :cond_0
    move v14, v13

    .line 55
    :goto_0
    const/4 v1, 0x1

    .line 56
    if-ge v14, v12, :cond_9

    .line 57
    .line 58
    invoke-static {v8, v10, v14}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getArgument(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-static {v8, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    if-nez v4, :cond_1

    .line 67
    .line 68
    goto/16 :goto_2

    .line 69
    .line 70
    :cond_1
    invoke-static {v8, v9, v14}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->get(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentListMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    invoke-static {v8, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 75
    .line 76
    .line 77
    sget-object v6, Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;->INV:Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 78
    .line 79
    invoke-static {v8, v5}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v8, v11, v14}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getParameter(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;I)Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    invoke-static {v8, v7}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    invoke-static {v8, v3}, Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContextContextualKt;->getVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/TypeArgumentMarker;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    invoke-virtual {v0, v7, v3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->effectiveVariance(Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;)Lkotlin/reflect/jvm/internal/impl/types/model/TypeVariance;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    if-nez v3, :cond_2

    .line 103
    .line 104
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->isErrorTypeEqualsToAnything()Z

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    return v0

    .line 109
    :cond_2
    if-ne v3, v6, :cond_3

    .line 110
    .line 111
    invoke-direct {v0, v8, v5, v4, v11}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isTypeVariableAgainstStarProjectionForSelfType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 112
    .line 113
    .line 114
    move-result v6

    .line 115
    if-nez v6, :cond_7

    .line 116
    .line 117
    invoke-direct {v0, v8, v4, v5, v11}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isTypeVariableAgainstStarProjectionForSelfType(Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/TypeConstructorMarker;)Z

    .line 118
    .line 119
    .line 120
    move-result v6

    .line 121
    if-eqz v6, :cond_3

    .line 122
    .line 123
    goto/16 :goto_2

    .line 124
    .line 125
    :cond_3
    invoke-static {v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->access$getArgumentsDepth(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;)I

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    const/16 v7, 0x64

    .line 130
    .line 131
    if-gt v6, v7, :cond_8

    .line 132
    .line 133
    invoke-static {v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->access$getArgumentsDepth(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;)I

    .line 134
    .line 135
    .line 136
    move-result v6

    .line 137
    add-int/2addr v6, v1

    .line 138
    invoke-static {v2, v6}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->access$setArgumentsDepth(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;I)V

    .line 139
    .line 140
    .line 141
    sget-object v6, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 142
    .line 143
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    aget v3, v6, v3

    .line 148
    .line 149
    if-eq v3, v1, :cond_6

    .line 150
    .line 151
    const/4 v1, 0x2

    .line 152
    if-eq v3, v1, :cond_5

    .line 153
    .line 154
    const/4 v1, 0x3

    .line 155
    if-ne v3, v1, :cond_4

    .line 156
    .line 157
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 158
    .line 159
    const/16 v6, 0x8

    .line 160
    .line 161
    const/4 v7, 0x0

    .line 162
    move-object v3, v5

    .line 163
    const/4 v5, 0x0

    .line 164
    move-object v15, v4

    .line 165
    move-object v4, v3

    .line 166
    move-object v3, v15

    .line 167
    invoke-static/range {v1 .. v7}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    move-object/from16 v2, p1

    .line 172
    .line 173
    goto :goto_1

    .line 174
    :cond_4
    new-instance v0, La8/r0;

    .line 175
    .line 176
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 177
    .line 178
    .line 179
    throw v0

    .line 180
    :cond_5
    move-object v3, v4

    .line 181
    move-object v4, v5

    .line 182
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 183
    .line 184
    const/16 v6, 0x8

    .line 185
    .line 186
    const/4 v7, 0x0

    .line 187
    const/4 v5, 0x0

    .line 188
    move-object v2, v4

    .line 189
    move-object v4, v3

    .line 190
    move-object v3, v2

    .line 191
    move-object/from16 v2, p1

    .line 192
    .line 193
    invoke-static/range {v1 .. v7}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    goto :goto_1

    .line 198
    :cond_6
    move-object v3, v4

    .line 199
    move-object v4, v5

    .line 200
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    .line 201
    .line 202
    invoke-virtual {v1, v2, v4, v3}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->equalTypes(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    .line 203
    .line 204
    .line 205
    move-result v1

    .line 206
    :goto_1
    invoke-static {v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->access$getArgumentsDepth(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;)I

    .line 207
    .line 208
    .line 209
    move-result v3

    .line 210
    add-int/lit8 v3, v3, -0x1

    .line 211
    .line 212
    invoke-static {v2, v3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->access$setArgumentsDepth(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;I)V

    .line 213
    .line 214
    .line 215
    if-nez v1, :cond_7

    .line 216
    .line 217
    return v13

    .line 218
    :cond_7
    :goto_2
    add-int/lit8 v14, v14, 0x1

    .line 219
    .line 220
    goto/16 :goto_0

    .line 221
    .line 222
    :cond_8
    move-object v4, v5

    .line 223
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 224
    .line 225
    new-instance v1, Ljava/lang/StringBuilder;

    .line 226
    .line 227
    const-string v2, "Arguments depth is too high. Some related argument: "

    .line 228
    .line 229
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 233
    .line 234
    .line 235
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    throw v0

    .line 247
    :cond_9
    return v1

    .line 248
    :cond_a
    :goto_3
    return v13
.end method

.method public final isSubtypeOf(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z
    .locals 8

    .line 1
    const-string v0, "state"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subType"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "superType"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v6, 0x8

    const/4 v7, 0x0

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    invoke-static/range {v1 .. v7}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->isSubtypeOf$default(Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;ZILjava/lang/Object;)Z

    move-result p0

    return p0
.end method

.method public final isSubtypeOf(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Z
    .locals 6

    const-string p0, "state"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "subType"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "superType"

    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    if-ne p2, p3, :cond_0

    const/4 p0, 0x1

    return p0

    .line 2
    :cond_0
    invoke-virtual {p1, p2, p3}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->customIsSubtypeOf(Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;)Z

    move-result p0

    if-nez p0, :cond_1

    const/4 p0, 0x0

    return p0

    .line 3
    :cond_1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;->getTypeSystemContext()Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    move-result-object v2

    .line 4
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;

    move-object v1, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-direct/range {v0 .. v5}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->completeIsSubTypeOf(Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/model/KotlinTypeMarker;Z)Z

    move-result p0

    return p0
.end method
