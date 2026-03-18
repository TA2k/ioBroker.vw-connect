.class Lkotlin/reflect/jvm/internal/impl/types/IntersectionTypeConstructor$$Lambda$0;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/k;


# instance fields
.field private final arg$0:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/types/IntersectionTypeConstructor$$Lambda$0;->arg$0:Lay0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/types/IntersectionTypeConstructor$$Lambda$0;->arg$0:Lay0/k;

    .line 2
    .line 3
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/IntersectionTypeConstructor;->accessor$IntersectionTypeConstructor$lambda0(Lay0/k;Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Ljava/lang/CharSequence;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
