.class Lkotlin/reflect/jvm/internal/KCallableImpl$$Lambda$7;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/a;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KCallableImpl$$Lambda$7;->arg$0:Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KCallableImpl$$Lambda$7;->arg$0:Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/KCallableImpl;->accessor$KCallableImpl$lambda7(Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;)Lkotlin/reflect/jvm/internal/impl/descriptors/ParameterDescriptor;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
