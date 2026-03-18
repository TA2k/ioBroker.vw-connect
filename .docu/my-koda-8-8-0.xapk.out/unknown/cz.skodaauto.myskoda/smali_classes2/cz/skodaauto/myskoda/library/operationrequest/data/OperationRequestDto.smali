.class public final Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = true
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0016\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0081\u0008\u0018\u00002\u00020\u0001B9\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0005\u0012\u0006\u0010\u0007\u001a\u00020\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0005\u0012\u0006\u0010\t\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\t\u0010\u0014\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0015\u001a\u00020\u0005H\u00c6\u0003J\u000b\u0010\u0016\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0005H\u00c6\u0003JG\u0010\u001a\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\n\u0008\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00052\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u00052\u0008\u0008\u0002\u0010\t\u001a\u00020\u0005H\u00c6\u0001J\u0013\u0010\u001b\u001a\u00020\u001c2\u0008\u0010\u001d\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001e\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u001f\u001a\u00020\u0005H\u00d6\u0001R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\rR\u0016\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\u000fR\u0018\u0010\u0006\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u000fR\u0016\u0010\u0007\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u000fR\u0016\u0010\u0008\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0012\u0010\u000fR\u0016\u0010\t\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u000f\u00a8\u0006 "
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;",
        "",
        "version",
        "",
        "traceId",
        "",
        "errorCode",
        "status",
        "requestId",
        "operation",
        "<init>",
        "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "getVersion",
        "()I",
        "getTraceId",
        "()Ljava/lang/String;",
        "getErrorCode",
        "getStatus",
        "getRequestId",
        "getOperation",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "operation-request_release"
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
.field private final errorCode:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "errorCode"
    .end annotation
.end field

.field private final operation:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "operation"
    .end annotation
.end field

.field private final requestId:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "requestId"
    .end annotation
.end field

.field private final status:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "status"
    .end annotation
.end field

.field private final traceId:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "traceId"
    .end annotation
.end field

.field private final version:I
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "version"
    .end annotation
.end field


# direct methods
.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "traceId"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "status"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "requestId"

    .line 12
    .line 13
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "operation"

    .line 17
    .line 18
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput p1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 25
    .line 26
    iput-object p2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p3, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p4, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p5, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 33
    .line 34
    iput-object p6, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 35
    .line 36
    return-void
.end method

.method public static synthetic copy$default(Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;
    .locals 0

    .line 1
    and-int/lit8 p8, p7, 0x1

    .line 2
    .line 3
    if-eqz p8, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p8, p7, 0x2

    .line 8
    .line 9
    if-eqz p8, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p8, p7, 0x4

    .line 14
    .line 15
    if-eqz p8, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p8, p7, 0x8

    .line 20
    .line 21
    if-eqz p8, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p8, p7, 0x10

    .line 26
    .line 27
    if-eqz p8, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p7, p7, 0x20

    .line 32
    .line 33
    if-eqz p7, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 36
    .line 37
    :cond_5
    move-object p7, p5

    .line 38
    move-object p8, p6

    .line 39
    move-object p5, p3

    .line 40
    move-object p6, p4

    .line 41
    move p3, p1

    .line 42
    move-object p4, p2

    .line 43
    move-object p2, p0

    .line 44
    invoke-virtual/range {p2 .. p8}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->copy(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;
    .locals 7

    .line 1
    const-string p0, "traceId"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "status"

    .line 7
    .line 8
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "requestId"

    .line 12
    .line 13
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "operation"

    .line 17
    .line 18
    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;

    .line 22
    .line 23
    move v1, p1

    .line 24
    move-object v2, p2

    .line 25
    move-object v3, p3

    .line 26
    move-object v4, p4

    .line 27
    move-object v5, p5

    .line 28
    move-object v6, p6

    .line 29
    invoke-direct/range {v0 .. v6}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-object v0
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
    instance-of v1, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;

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
    check-cast p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 14
    .line 15
    iget v3, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 65
    .line 66
    iget-object p1, p1, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-nez p0, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    return v0
.end method

.method public final getErrorCode()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOperation()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRequestId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStatus()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTraceId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVersion()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 17
    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    :goto_0
    add-int/2addr v0, v2

    .line 27
    mul-int/2addr v0, v1

    .line 28
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    add-int/2addr p0, v0

    .line 47
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget v0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->version:I

    .line 2
    .line 3
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->traceId:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->errorCode:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->status:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->requestId:Ljava/lang/String;

    .line 10
    .line 11
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->operation:Ljava/lang/String;

    .line 12
    .line 13
    const-string v5, ", traceId="

    .line 14
    .line 15
    const-string v6, ", errorCode="

    .line 16
    .line 17
    const-string v7, "OperationRequestDto(version="

    .line 18
    .line 19
    invoke-static {v7, v0, v5, v1, v6}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, ", status="

    .line 24
    .line 25
    const-string v5, ", requestId="

    .line 26
    .line 27
    invoke-static {v0, v2, v1, v3, v5}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string v1, ", operation="

    .line 31
    .line 32
    const-string v2, ")"

    .line 33
    .line 34
    invoke-static {v0, v4, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
