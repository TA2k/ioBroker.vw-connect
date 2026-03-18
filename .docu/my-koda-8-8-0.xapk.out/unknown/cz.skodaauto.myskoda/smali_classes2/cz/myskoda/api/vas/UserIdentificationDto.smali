.class public final Lcz/myskoda/api/vas/UserIdentificationDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/vas/UserIdentificationDto$Status;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001:\u0001\u0013B\u0013\u0012\n\u0008\u0003\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u000b\u0010\n\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u0015\u0010\u000b\u001a\u00020\u00002\n\u0008\u0003\u0010\u0002\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001J\u0013\u0010\u000c\u001a\u00020\r2\u0008\u0010\u000e\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u000f\u001a\u00020\u0010H\u00d6\u0001J\t\u0010\u0011\u001a\u00020\u0012H\u00d6\u0001R\u001e\u0010\u0002\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0006\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\u00a8\u0006\u0014"
    }
    d2 = {
        "Lcz/myskoda/api/vas/UserIdentificationDto;",
        "",
        "status",
        "Lcz/myskoda/api/vas/UserIdentificationDto$Status;",
        "<init>",
        "(Lcz/myskoda/api/vas/UserIdentificationDto$Status;)V",
        "getStatus$annotations",
        "()V",
        "getStatus",
        "()Lcz/myskoda/api/vas/UserIdentificationDto$Status;",
        "component1",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "Status",
        "vas-api_release"
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
.field private final status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    const/4 v1, 0x1

    invoke-direct {p0, v0, v1, v0}, Lcz/myskoda/api/vas/UserIdentificationDto;-><init>(Lcz/myskoda/api/vas/UserIdentificationDto$Status;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcz/myskoda/api/vas/UserIdentificationDto$Status;)V
    .locals 0
    .param p1    # Lcz/myskoda/api/vas/UserIdentificationDto$Status;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "status"
        .end annotation
    .end param

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    return-void
.end method

.method public synthetic constructor <init>(Lcz/myskoda/api/vas/UserIdentificationDto$Status;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    const/4 p1, 0x0

    .line 4
    :cond_0
    invoke-direct {p0, p1}, Lcz/myskoda/api/vas/UserIdentificationDto;-><init>(Lcz/myskoda/api/vas/UserIdentificationDto$Status;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/vas/UserIdentificationDto;Lcz/myskoda/api/vas/UserIdentificationDto$Status;ILjava/lang/Object;)Lcz/myskoda/api/vas/UserIdentificationDto;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcz/myskoda/api/vas/UserIdentificationDto;->copy(Lcz/myskoda/api/vas/UserIdentificationDto$Status;)Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
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
.method public final component1()Lcz/myskoda/api/vas/UserIdentificationDto$Status;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/vas/UserIdentificationDto$Status;)Lcz/myskoda/api/vas/UserIdentificationDto;
    .locals 0
    .param p1    # Lcz/myskoda/api/vas/UserIdentificationDto$Status;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "status"
        .end annotation
    .end param

    .line 1
    new-instance p0, Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcz/myskoda/api/vas/UserIdentificationDto;-><init>(Lcz/myskoda/api/vas/UserIdentificationDto$Status;)V

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
    instance-of v1, p1, Lcz/myskoda/api/vas/UserIdentificationDto;

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
    check-cast p1, Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 12
    .line 13
    iget-object p0, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    .line 14
    .line 15
    iget-object p1, p1, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

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

.method public final getStatus()Lcz/myskoda/api/vas/UserIdentificationDto$Status;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserIdentificationDto;->status:Lcz/myskoda/api/vas/UserIdentificationDto$Status;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "UserIdentificationDto(status="

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
