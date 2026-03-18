.class public final Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;
.super Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Success"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0001\n\u0002\u0008\n\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0087\u0008\u0018\u0000*\u0008\u0008\u0002\u0010\u0001*\u00020\u00022\u000e\u0012\u0004\u0012\u0002H\u0001\u0012\u0004\u0012\u00020\u00040\u0003B\u000f\u0012\u0006\u0010\u0005\u001a\u00028\u0002\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000e\u0010\u000b\u001a\u00028\u0002H\u00c6\u0003\u00a2\u0006\u0002\u0010\tJ\u001e\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00028\u00020\u00002\u0008\u0008\u0002\u0010\u0005\u001a\u00028\u0002H\u00c6\u0001\u00a2\u0006\u0002\u0010\rJ\u0013\u0010\u000e\u001a\u00020\u000f2\u0008\u0010\u0010\u001a\u0004\u0018\u00010\u0002H\u00d6\u0003J\t\u0010\u0011\u001a\u00020\u0012H\u00d6\u0001J\t\u0010\u0013\u001a\u00020\u0014H\u00d6\u0001R\u0013\u0010\u0005\u001a\u00028\u0002\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0008\u0010\t\u00a8\u0006\u0015"
    }
    d2 = {
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;",
        "T",
        "",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "",
        "value",
        "<init>",
        "(Ljava/lang/Object;)V",
        "getValue",
        "()Ljava/lang/Object;",
        "Ljava/lang/Object;",
        "component1",
        "copy",
        "(Ljava/lang/Object;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "lib-retrofit-adapter_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final value:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TT;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)V"
        }
    .end annotation

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-direct {p0, v0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;-><init>(Lkotlin/jvm/internal/g;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic copy$default(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;Ljava/lang/Object;ILjava/lang/Object;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->copy(Ljava/lang/Object;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/Object;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success<",
            "TT;>;"
        }
    .end annotation

    .line 1
    const-string p0, "value"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;-><init>(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 12
    .line 13
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object p1, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;->value:Ljava/lang/Object;

    .line 2
    .line 3
    const-string v0, "Success(value="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {p0, v0, v1}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
