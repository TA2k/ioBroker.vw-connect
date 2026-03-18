.class public final Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0013\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B5\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\u0016\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u0017\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u0018\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J7\u0010\u0019\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007H\u00c6\u0001J\u0013\u0010\u001a\u001a\u00020\u001b2\u0008\u0010\u001c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001d\u001a\u00020\u001eH\u00d6\u0001J\t\u0010\u001f\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001e\u0010\u0004\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\rR\u001e\u0010\u0005\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\u000b\u001a\u0004\u0008\u0011\u0010\rR\u001e\u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0012\u0010\u000b\u001a\u0004\u0008\u0013\u0010\u0014\u00a8\u0006 "
    }
    d2 = {
        "Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;",
        "",
        "userInput",
        "",
        "sessionId",
        "vin",
        "routePlanner",
        "Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)V",
        "getUserInput$annotations",
        "()V",
        "getUserInput",
        "()Ljava/lang/String;",
        "getSessionId$annotations",
        "getSessionId",
        "getVin$annotations",
        "getVin",
        "getRoutePlanner$annotations",
        "getRoutePlanner",
        "()Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "bff-api_release"
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
.field private final routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

.field private final sessionId:Ljava/lang/String;

.field private final userInput:Ljava/lang/String;

.field private final vin:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "userInput"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "sessionId"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vin"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "routePlanner"
        .end annotation
    .end param

    const-string v0, "userInput"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x2

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_1

    move-object p3, v0

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    move-object p4, v0

    .line 6
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getRoutePlanner$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "routePlanner"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getSessionId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "sessionId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUserInput$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "userInput"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVin$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vin"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "userInput"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "sessionId"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vin"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "routePlanner"
        .end annotation
    .end param

    .line 1
    const-string p0, "userInput"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)V

    .line 9
    .line 10
    .line 11
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
    instance-of v1, p1, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;

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
    check-cast p1, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 47
    .line 48
    iget-object p1, p1, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final getRoutePlanner()Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSessionId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUserInput()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    move v1, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    :goto_0
    add-int/2addr v0, v1

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 24
    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    move v1, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    :goto_1
    add-int/2addr v0, v1

    .line 34
    mul-int/lit8 v0, v0, 0x1f

    .line 35
    .line 36
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 37
    .line 38
    if-nez p0, :cond_2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {p0}, Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_2
    add-int/2addr v0, v2

    .line 46
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->userInput:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->sessionId:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->vin:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;->routePlanner:Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 8
    .line 9
    const-string v3, ", sessionId="

    .line 10
    .line 11
    const-string v4, ", vin="

    .line 12
    .line 13
    const-string v5, "AIAssistantRequestDto(userInput="

    .line 14
    .line 15
    invoke-static {v5, v0, v3, v1, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, ", routePlanner="

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, ")"

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
