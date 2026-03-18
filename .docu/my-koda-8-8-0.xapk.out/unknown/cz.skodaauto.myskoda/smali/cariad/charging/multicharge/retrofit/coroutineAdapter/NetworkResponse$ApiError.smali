.class public final Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;
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
    name = "ApiError"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<Error:",
        "Ljava/lang/Object;",
        ">",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0001\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0012\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0087\u0008\u0018\u0000*\n\u0008\u0002\u0010\u0001 \u0001*\u00020\u00022\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u0002H\u00010\u0003B-\u0012\u0008\u0010\u0005\u001a\u0004\u0018\u00018\u0002\u0012\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\u0006\u0010\u0008\u001a\u00020\t\u0012\u0008\u0010\n\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0010\u0010\u0015\u001a\u0004\u0018\u00018\u0002H\u00c6\u0003\u00a2\u0006\u0002\u0010\u000eJ\u000b\u0010\u0016\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\tH\u00c6\u0003J\u000b\u0010\u0018\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003JB\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00028\u00020\u00002\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00018\u00022\n\u0008\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t2\n\u0008\u0002\u0010\n\u001a\u0004\u0018\u00010\u0007H\u00c6\u0001\u00a2\u0006\u0002\u0010\u001aJ\u0013\u0010\u001b\u001a\u00020\u001c2\u0008\u0010\u001d\u001a\u0004\u0018\u00010\u0002H\u00d6\u0003J\t\u0010\u001e\u001a\u00020\tH\u00d6\u0001J\t\u0010\u001f\u001a\u00020\u0007H\u00d6\u0001R\u0015\u0010\u0005\u001a\u0004\u0018\u00018\u0002\u00a2\u0006\n\n\u0002\u0010\u000f\u001a\u0004\u0008\r\u0010\u000eR\u0013\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u0011R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0012\u0010\u0013R\u0013\u0010\n\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0011\u00a8\u0006 "
    }
    d2 = {
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;",
        "Error",
        "",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "",
        "error",
        "message",
        "",
        "code",
        "",
        "traceContext",
        "<init>",
        "(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V",
        "getError",
        "()Ljava/lang/Object;",
        "Ljava/lang/Object;",
        "getMessage",
        "()Ljava/lang/String;",
        "getCode",
        "()I",
        "getTraceContext",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
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
.field private final code:I

.field private final error:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TError;"
        }
    .end annotation
.end field

.field private final message:Ljava/lang/String;

.field private final traceContext:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TError;",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;-><init>(Lkotlin/jvm/internal/g;)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p2, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 8
    .line 9
    iput p3, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 10
    .line 11
    iput-object p4, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic copy$default(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;ILjava/lang/Object;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget p3, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->copy(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TError;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TError;",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            ")",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError<",
            "TError;>;"
        }
    .end annotation

    .line 1
    new-instance p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;-><init>(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

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
    check-cast p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 12
    .line 13
    iget-object v1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v3, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget v1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 36
    .line 37
    iget v3, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 43
    .line 44
    iget-object p1, p1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    return v0
.end method

.method public final getCode()I
    .locals 0

    .line 1
    iget p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 2
    .line 3
    return p0
.end method

.method public final getError()Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TError;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTraceContext()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v0, v2

    .line 15
    iget-object v3, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 16
    .line 17
    if-nez v3, :cond_1

    .line 18
    .line 19
    move v3, v1

    .line 20
    goto :goto_1

    .line 21
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    :goto_1
    add-int/2addr v0, v3

    .line 26
    mul-int/2addr v0, v2

    .line 27
    iget v3, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 28
    .line 29
    invoke-static {v3, v0, v2}, Lc1/j0;->g(III)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 34
    .line 35
    if-nez p0, :cond_2

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    :goto_2
    add-int/2addr v0, v1

    .line 43
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->error:Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v1, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->message:Ljava/lang/String;

    .line 4
    .line 5
    iget v2, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->code:I

    .line 6
    .line 7
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->traceContext:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "ApiError(error="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", message="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", code="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", traceContext="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
