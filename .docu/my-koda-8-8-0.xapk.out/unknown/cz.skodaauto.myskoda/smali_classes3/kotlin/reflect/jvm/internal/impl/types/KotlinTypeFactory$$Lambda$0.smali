.class Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/k;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

.field private final arg$1:Ljava/util/List;

.field private final arg$2:Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;

.field private final arg$3:Z


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;Ljava/util/List;Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$0:Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 5
    .line 6
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$1:Ljava/util/List;

    .line 7
    .line 8
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$2:Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;

    .line 9
    .line 10
    iput-boolean p4, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$3:Z

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$0:Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 2
    .line 3
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$1:Ljava/util/List;

    .line 4
    .line 5
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$2:Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;

    .line 6
    .line 7
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory$$Lambda$0;->arg$3:Z

    .line 8
    .line 9
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/checker/KotlinTypeRefiner;

    .line 10
    .line 11
    invoke-static {v0, v1, v2, p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory;->accessor$KotlinTypeFactory$lambda0(Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;Ljava/util/List;Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;ZLkotlin/reflect/jvm/internal/impl/types/checker/KotlinTypeRefiner;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
