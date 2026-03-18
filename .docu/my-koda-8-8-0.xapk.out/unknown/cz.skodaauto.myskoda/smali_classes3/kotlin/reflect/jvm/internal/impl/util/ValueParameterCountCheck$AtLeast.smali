.class public final Lkotlin/reflect/jvm/internal/impl/util/ValueParameterCountCheck$AtLeast;
.super Lkotlin/reflect/jvm/internal/impl/util/ValueParameterCountCheck;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/util/ValueParameterCountCheck;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "AtLeast"
.end annotation


# instance fields
.field private final n:I


# direct methods
.method public constructor <init>(I)V
    .locals 2

    .line 1
    const-string v0, "must have at least "

    .line 2
    .line 3
    const-string v1, " value parameter"

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-le p1, v1, :cond_0

    .line 11
    .line 12
    const-string v1, "s"

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-string v1, ""

    .line 16
    .line 17
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {p0, v0, v1}, Lkotlin/reflect/jvm/internal/impl/util/ValueParameterCountCheck;-><init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V

    .line 26
    .line 27
    .line 28
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/util/ValueParameterCountCheck$AtLeast;->n:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public check(Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;)Z
    .locals 1

    .line 1
    const-string v0, "functionDescriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getValueParameters()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/util/ValueParameterCountCheck$AtLeast;->n:I

    .line 15
    .line 16
    if-lt p1, p0, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0
.end method
