.class public final Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final andArguments:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;",
            ">;"
        }
    .end annotation
.end field

.field private constantValue:Lkotlin/reflect/jvm/internal/impl/km/KmConstantValue;

.field private flags:I

.field private isInstanceType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

.field private final orArguments:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;",
            ">;"
        }
    .end annotation
.end field

.field private parameterIndex:Ljava/lang/Integer;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->andArguments:Ljava/util/List;

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->orArguments:Ljava/util/List;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final getAndArguments()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->andArguments:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFlags$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->flags:I

    .line 2
    .line 3
    return p0
.end method

.method public final getOrArguments()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->orArguments:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setConstantValue(Lkotlin/reflect/jvm/internal/impl/km/KmConstantValue;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->constantValue:Lkotlin/reflect/jvm/internal/impl/km/KmConstantValue;

    .line 2
    .line 3
    return-void
.end method

.method public final setFlags$kotlin_metadata(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->flags:I

    .line 2
    .line 3
    return-void
.end method

.method public final setInstanceType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->isInstanceType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-void
.end method

.method public final setParameterIndex(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmEffectExpression;->parameterIndex:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method
