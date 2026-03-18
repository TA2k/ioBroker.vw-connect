.class public final Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0018\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B7\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u000e\u0008\u0001\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\t\u0010\u001a\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001b\u001a\u00020\u0005H\u00c6\u0003J\u000f\u0010\u001c\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u00c6\u0003J\u000b\u0010\u001d\u001a\u0004\u0018\u00010\nH\u00c6\u0003J9\u0010\u001e\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u000e\u0008\u0003\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00072\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\nH\u00c6\u0001J\u0013\u0010\u001f\u001a\u00020\u00052\u0008\u0010 \u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010!\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\"\u001a\u00020#H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\r\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010R\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0011\u0010\u000e\u001a\u0004\u0008\u0012\u0010\u0013R\"\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0014\u0010\u000e\u001a\u0004\u0008\u0015\u0010\u0016R\u001e\u0010\t\u001a\u0004\u0018\u00010\n8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0017\u0010\u000e\u001a\u0004\u0008\u0018\u0010\u0019\u00a8\u0006$"
    }
    d2 = {
        "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;",
        "",
        "accountPointBalance",
        "",
        "dailyCheckInCollected",
        "",
        "challenges",
        "",
        "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;",
        "dailyCheckInChallenge",
        "Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;",
        "<init>",
        "(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;)V",
        "getAccountPointBalance$annotations",
        "()V",
        "getAccountPointBalance",
        "()I",
        "getDailyCheckInCollected$annotations",
        "getDailyCheckInCollected",
        "()Z",
        "getChallenges$annotations",
        "getChallenges",
        "()Ljava/util/List;",
        "getDailyCheckInChallenge$annotations",
        "getDailyCheckInChallenge",
        "()Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "other",
        "hashCode",
        "toString",
        "",
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
.field private final accountPointBalance:I

.field private final challenges:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;",
            ">;"
        }
    .end annotation
.end field

.field private final dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

.field private final dailyCheckInCollected:Z


# direct methods
.method public constructor <init>(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;)V
    .locals 1
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "accountPointBalance"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "dailyCheckInCollected"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "challenges"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "dailyCheckInChallenge"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IZ",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;",
            ">;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;",
            ")V"
        }
    .end annotation

    const-string v0, "challenges"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 3
    iput-boolean p2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    return-void
.end method

.method public synthetic constructor <init>(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;-><init>(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->copy(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;)Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getAccountPointBalance$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "accountPointBalance"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getChallenges$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "challenges"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getDailyCheckInChallenge$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "dailyCheckInChallenge"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getDailyCheckInCollected$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "dailyCheckInCollected"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;)Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "accountPointBalance"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "dailyCheckInCollected"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "challenges"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "dailyCheckInChallenge"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IZ",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;",
            ">;",
            "Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;",
            ")",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;"
        }
    .end annotation

    .line 1
    const-string p0, "challenges"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;-><init>(IZLjava/util/List;Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;

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
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 14
    .line 15
    iget v3, p1, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 28
    .line 29
    iget-object v3, p1, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 30
    .line 31
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 39
    .line 40
    iget-object p1, p1, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 41
    .line 42
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-nez p0, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    return v0
.end method

.method public final getAccountPointBalance()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 2
    .line 3
    return p0
.end method

.method public final getChallenges()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDailyCheckInChallenge()Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDailyCheckInCollected()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

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
    iget-boolean v2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 23
    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    :goto_0
    add-int/2addr v0, p0

    .line 33
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->accountPointBalance:I

    .line 2
    .line 3
    iget-boolean v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInCollected:Z

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->challenges:Ljava/util/List;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->dailyCheckInChallenge:Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "ChallengesDto(accountPointBalance="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", dailyCheckInCollected="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", challenges="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", dailyCheckInChallenge="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

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
