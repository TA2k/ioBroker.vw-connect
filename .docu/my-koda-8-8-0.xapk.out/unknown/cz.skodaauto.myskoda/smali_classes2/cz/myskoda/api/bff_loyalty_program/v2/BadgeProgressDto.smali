.class public final Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0019\u0008\u0086\u0008\u0018\u00002\u00020\u0001B1\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0007\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\t\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\t\u0010\u0019\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u001b\u001a\u00020\u0007H\u00c6\u0003J\u000b\u0010\u001c\u001a\u0004\u0018\u00010\tH\u00c6\u0003J3\u0010\u001d\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00072\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\tH\u00c6\u0001J\u0013\u0010\u001e\u001a\u00020\u00072\u0008\u0010\u001f\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010 \u001a\u00020\u0005H\u00d6\u0001J\t\u0010!\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000c\u0010\r\u001a\u0004\u0008\u000e\u0010\u000fR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\r\u001a\u0004\u0008\u0011\u0010\u0012R\u001c\u0010\u0006\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\r\u001a\u0004\u0008\u0014\u0010\u0015R\u001e\u0010\u0008\u001a\u0004\u0018\u00010\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0016\u0010\r\u001a\u0004\u0008\u0017\u0010\u0018\u00a8\u0006\""
    }
    d2 = {
        "Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;",
        "",
        "status",
        "",
        "progressInPct",
        "",
        "collected",
        "",
        "collectedAt",
        "Ljava/time/OffsetDateTime;",
        "<init>",
        "(Ljava/lang/String;IZLjava/time/OffsetDateTime;)V",
        "getStatus$annotations",
        "()V",
        "getStatus",
        "()Ljava/lang/String;",
        "getProgressInPct$annotations",
        "getProgressInPct",
        "()I",
        "getCollected$annotations",
        "getCollected",
        "()Z",
        "getCollectedAt$annotations",
        "getCollectedAt",
        "()Ljava/time/OffsetDateTime;",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "other",
        "hashCode",
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
.field private final collected:Z

.field private final collectedAt:Ljava/time/OffsetDateTime;

.field private final progressInPct:I

.field private final status:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;IZLjava/time/OffsetDateTime;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "status"
        .end annotation
    .end param
    .param p2    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "progressInPct"
        .end annotation
    .end param
    .param p3    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "collected"
        .end annotation
    .end param
    .param p4    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "collectedAt"
        .end annotation
    .end param

    const-string v0, "status"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 3
    iput p2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 4
    iput-boolean p3, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;IZLjava/time/OffsetDateTime;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;-><init>(Ljava/lang/String;IZLjava/time/OffsetDateTime;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;Ljava/lang/String;IZLjava/time/OffsetDateTime;ILjava/lang/Object;)Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->copy(Ljava/lang/String;IZLjava/time/OffsetDateTime;)Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getCollected$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "collected"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCollectedAt$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "collectedAt"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getProgressInPct$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "progressInPct"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getStatus$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "status"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;IZLjava/time/OffsetDateTime;)Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "status"
        .end annotation
    .end param
    .param p2    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "progressInPct"
        .end annotation
    .end param
    .param p3    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "collected"
        .end annotation
    .end param
    .param p4    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "collectedAt"
        .end annotation
    .end param

    .line 1
    const-string p0, "status"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;-><init>(Ljava/lang/String;IZLjava/time/OffsetDateTime;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;

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
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

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
    iget v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 25
    .line 26
    iget v3, p1, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

    .line 39
    .line 40
    iget-object p1, p1, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

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

.method public final getCollected()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getCollectedAt()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getProgressInPct()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 2
    .line 3
    return p0
.end method

.method public final getStatus()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget v2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

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
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

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
    .locals 6

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->status:Ljava/lang/String;

    .line 2
    .line 3
    iget v1, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->progressInPct:I

    .line 4
    .line 5
    iget-boolean v2, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collected:Z

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->collectedAt:Ljava/time/OffsetDateTime;

    .line 8
    .line 9
    const-string v3, ", progressInPct="

    .line 10
    .line 11
    const-string v4, ", collected="

    .line 12
    .line 13
    const-string v5, "BadgeProgressDto(status="

    .line 14
    .line 15
    invoke-static {v5, v1, v0, v3, v4}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, ", collectedAt="

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
