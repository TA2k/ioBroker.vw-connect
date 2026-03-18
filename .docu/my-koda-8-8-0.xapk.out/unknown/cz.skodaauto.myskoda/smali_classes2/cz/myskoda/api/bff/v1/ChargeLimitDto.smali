.class public final Lcz/myskoda/api/bff/v1/ChargeLimitDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\t\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u0011\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\t\u0010\n\u001a\u00020\u0003H\u00c6\u0003J\u0013\u0010\u000b\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u000c\u001a\u00020\r2\u0008\u0010\u000e\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u000f\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u0010\u001a\u00020\u0011H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0006\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\u00a8\u0006\u0012"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/ChargeLimitDto;",
        "",
        "targetSOCInPercent",
        "",
        "<init>",
        "(I)V",
        "getTargetSOCInPercent$annotations",
        "()V",
        "getTargetSOCInPercent",
        "()I",
        "component1",
        "copy",
        "equals",
        "",
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
.field private final targetSOCInPercent:I


# direct methods
.method public constructor <init>(I)V
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "targetSOCInPercent"
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 5
    .line 6
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/ChargeLimitDto;IILjava/lang/Object;)Lcz/myskoda/api/bff/v1/ChargeLimitDto;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->copy(I)Lcz/myskoda/api/bff/v1/ChargeLimitDto;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public static synthetic getTargetSOCInPercent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "targetSOCInPercent"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(I)Lcz/myskoda/api/bff/v1/ChargeLimitDto;
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "targetSOCInPercent"
        .end annotation
    .end param

    .line 1
    new-instance p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcz/myskoda/api/bff/v1/ChargeLimitDto;-><init>(I)V

    .line 4
    .line 5
    .line 6
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/ChargeLimitDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargeLimitDto;

    .line 12
    .line 13
    iget p0, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 14
    .line 15
    iget p1, p1, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public final getTargetSOCInPercent()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

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
    iget p0, p0, Lcz/myskoda/api/bff/v1/ChargeLimitDto;->targetSOCInPercent:I

    .line 2
    .line 3
    const-string v0, "ChargeLimitDto(targetSOCInPercent="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
