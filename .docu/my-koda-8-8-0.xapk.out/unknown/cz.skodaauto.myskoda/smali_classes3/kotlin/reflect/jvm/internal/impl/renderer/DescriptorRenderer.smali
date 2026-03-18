.class public abstract Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;,
        Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$ValueParametersHandler;
    }
.end annotation


# static fields
.field public static final COMPACT:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final COMPACT_WITHOUT_SUPERTYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final COMPACT_WITH_MODIFIERS:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final COMPACT_WITH_SHORT_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final Companion:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;

.field public static final DEBUG_TEXT:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final FQ_NAMES_IN_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final FQ_NAMES_IN_TYPES_WITH_ANNOTATIONS:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final HTML:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final ONLY_NAMES_WITH_SHORT_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final SHORT_NAMES_IN_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

.field public static final WITHOUT_MODIFIERS:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->Companion:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;

    .line 8
    .line 9
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$0;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$0;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->WITHOUT_MODIFIERS:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 16
    .line 17
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$1;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$1;

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT_WITH_MODIFIERS:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 24
    .line 25
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$2;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$2;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 32
    .line 33
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$3;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$3;

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT_WITHOUT_SUPERTYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 40
    .line 41
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$4;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$4;

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT_WITH_SHORT_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 48
    .line 49
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$5;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$5;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->ONLY_NAMES_WITH_SHORT_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 56
    .line 57
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$6;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$6;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->FQ_NAMES_IN_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 64
    .line 65
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$7;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$7;

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->FQ_NAMES_IN_TYPES_WITH_ANNOTATIONS:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 72
    .line 73
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$8;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$8;

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->SHORT_NAMES_IN_TYPES:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 80
    .line 81
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$9;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$9;

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->DEBUG_TEXT:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 88
    .line 89
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$10;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$$Lambda$10;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$Companion;->withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->HTML:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;

    .line 96
    .line 97
    return-void
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

.method private static final COMPACT$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithDefinedIn(Z)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0
.end method

.method private static final COMPACT_WITHOUT_SUPERTYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithDefinedIn(Z)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 13
    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithoutSuperTypes(Z)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method

.method private static final COMPACT_WITH_MODIFIERS$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithDefinedIn(Z)V

    .line 8
    .line 9
    .line 10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0
.end method

.method private static final COMPACT_WITH_SHORT_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SHORT;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SHORT;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setClassifierNamePolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;)V

    .line 14
    .line 15
    .line 16
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;->ONLY_NON_SYNTHESIZED:Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;

    .line 17
    .line 18
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setParameterNameRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method

.method private static final DEBUG_TEXT$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setDebugMode(Z)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$FULLY_QUALIFIED;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$FULLY_QUALIFIED;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setClassifierNamePolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;->ALL:Ljava/util/Set;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method

.method private static final FQ_NAMES_IN_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;->ALL_EXCEPT_ANNOTATIONS:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method private static final FQ_NAMES_IN_TYPES_WITH_ANNOTATIONS$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;->ALL:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method private static final HTML$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;->HTML:Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setTextFormat(Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;->ALL:Ljava/util/Set;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method

.method private static final ONLY_NAMES_WITH_SHORT_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 2

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithDefinedIn(Z)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SHORT;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SHORT;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setClassifierNamePolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithoutTypeParameters(Z)V

    .line 22
    .line 23
    .line 24
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;->NONE:Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;

    .line 25
    .line 26
    invoke-interface {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setParameterNameRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;)V

    .line 27
    .line 28
    .line 29
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setReceiverAfterName(Z)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setRenderCompanionObjectName(Z)V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setWithoutSuperTypes(Z)V

    .line 36
    .line 37
    .line 38
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setStartFromName(Z)V

    .line 39
    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0
.end method

.method private static final SHORT_NAMES_IN_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SHORT;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SHORT;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setClassifierNamePolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;->ONLY_NON_SYNTHESIZED:Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setParameterNameRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method

.method private static final WITHOUT_MODIFIERS$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "$this$withOptions"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;->setModifiers(Ljava/util/Set;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->WITHOUT_MODIFIERS$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda1(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT_WITH_MODIFIERS$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda10(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->HTML$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda2(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda3(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT_WITHOUT_SUPERTYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda4(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->COMPACT_WITH_SHORT_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda5(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->ONLY_NAMES_WITH_SHORT_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda6(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->FQ_NAMES_IN_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda7(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->FQ_NAMES_IN_TYPES_WITH_ANNOTATIONS$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda8(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->SHORT_NAMES_IN_TYPES$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRenderer$lambda9(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->DEBUG_TEXT$lambda$0(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic renderAnnotation$default(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/AnnotationDescriptor;Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/AnnotationUseSiteTarget;ILjava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    if-nez p4, :cond_1

    .line 2
    .line 3
    and-int/lit8 p3, p3, 0x2

    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    invoke-virtual {p0, p1, p2}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;->renderAnnotation(Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/AnnotationDescriptor;Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/AnnotationUseSiteTarget;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 14
    .line 15
    const-string p1, "Super calls with default arguments not supported in this target, function: renderAnnotation"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public abstract render(Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;)Ljava/lang/String;
.end method

.method public abstract renderAnnotation(Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/AnnotationDescriptor;Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/AnnotationUseSiteTarget;)Ljava/lang/String;
.end method

.method public abstract renderFlexibleType(Ljava/lang/String;Ljava/lang/String;Lkotlin/reflect/jvm/internal/impl/builtins/KotlinBuiltIns;)Ljava/lang/String;
.end method

.method public abstract renderFqName(Lkotlin/reflect/jvm/internal/impl/name/FqNameUnsafe;)Ljava/lang/String;
.end method

.method public abstract renderName(Lkotlin/reflect/jvm/internal/impl/name/Name;Z)Ljava/lang/String;
.end method

.method public abstract renderType(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Ljava/lang/String;
.end method

.method public abstract renderTypeProjection(Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;)Ljava/lang/String;
.end method

.method public final withOptions(Lay0/k;)Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")",
            "Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer;"
        }
    .end annotation

    .line 1
    const-string v0, "changeOptions"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererImpl;

    .line 7
    .line 8
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererImpl;->getOptions()Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->copy()Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->lock()V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererImpl;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;)V

    .line 25
    .line 26
    .line 27
    return-object p1
.end method
