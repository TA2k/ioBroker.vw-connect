.class Lkotlin/reflect/jvm/internal/impl/load/java/lazy/descriptors/LazyJavaStaticClassScope$$Lambda$2;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/k;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/impl/name/Name;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/name/Name;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/load/java/lazy/descriptors/LazyJavaStaticClassScope$$Lambda$2;->arg$0:Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/load/java/lazy/descriptors/LazyJavaStaticClassScope$$Lambda$2;->arg$0:Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 2
    .line 3
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/load/java/lazy/descriptors/LazyJavaStaticClassScope;->accessor$LazyJavaStaticClassScope$lambda2(Lkotlin/reflect/jvm/internal/impl/name/Name;Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;)Ljava/util/Collection;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
