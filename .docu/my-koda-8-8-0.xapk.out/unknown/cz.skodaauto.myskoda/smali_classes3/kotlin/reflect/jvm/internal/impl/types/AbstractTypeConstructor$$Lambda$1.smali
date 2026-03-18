.class Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$$Lambda$1;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/k;


# static fields
.field public static final INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$$Lambda$1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$$Lambda$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$$Lambda$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$$Lambda$1;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$$Lambda$1;

    .line 7
    .line 8
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


# virtual methods
.method public invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor;->accessor$AbstractTypeConstructor$lambda1(Z)Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeConstructor$Supertypes;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
