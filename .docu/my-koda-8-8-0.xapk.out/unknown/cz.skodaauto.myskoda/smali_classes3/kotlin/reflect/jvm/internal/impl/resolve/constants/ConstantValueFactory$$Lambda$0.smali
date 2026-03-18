.class Lkotlin/reflect/jvm/internal/impl/resolve/constants/ConstantValueFactory$$Lambda$0;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/k;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/impl/builtins/PrimitiveType;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/builtins/PrimitiveType;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/resolve/constants/ConstantValueFactory$$Lambda$0;->arg$0:Lkotlin/reflect/jvm/internal/impl/builtins/PrimitiveType;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/resolve/constants/ConstantValueFactory$$Lambda$0;->arg$0:Lkotlin/reflect/jvm/internal/impl/builtins/PrimitiveType;

    .line 2
    .line 3
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/descriptors/ModuleDescriptor;

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/resolve/constants/ConstantValueFactory;->accessor$ConstantValueFactory$lambda0(Lkotlin/reflect/jvm/internal/impl/builtins/PrimitiveType;Lkotlin/reflect/jvm/internal/impl/descriptors/ModuleDescriptor;)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
