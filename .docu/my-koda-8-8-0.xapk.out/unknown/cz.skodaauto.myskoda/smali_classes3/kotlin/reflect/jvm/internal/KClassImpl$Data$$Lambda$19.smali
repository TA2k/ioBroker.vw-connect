.class Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/a;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

.field private final arg$1:Lkotlin/reflect/jvm/internal/KClassImpl$Data;

.field private final arg$2:Lkotlin/reflect/jvm/internal/KClassImpl;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;Lkotlin/reflect/jvm/internal/KClassImpl$Data;Lkotlin/reflect/jvm/internal/KClassImpl;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;->arg$0:Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 5
    .line 6
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;->arg$1:Lkotlin/reflect/jvm/internal/KClassImpl$Data;

    .line 7
    .line 8
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;->arg$2:Lkotlin/reflect/jvm/internal/KClassImpl;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;->arg$0:Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 2
    .line 3
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;->arg$1:Lkotlin/reflect/jvm/internal/KClassImpl$Data;

    .line 4
    .line 5
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KClassImpl$Data$$Lambda$19;->arg$2:Lkotlin/reflect/jvm/internal/KClassImpl;

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lkotlin/reflect/jvm/internal/KClassImpl$Data;->accessor$KClassImpl$Data$lambda19(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;Lkotlin/reflect/jvm/internal/KClassImpl$Data;Lkotlin/reflect/jvm/internal/KClassImpl;)Ljava/lang/reflect/Type;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
