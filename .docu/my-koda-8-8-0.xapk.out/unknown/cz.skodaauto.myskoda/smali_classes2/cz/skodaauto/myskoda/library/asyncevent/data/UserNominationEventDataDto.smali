.class public final Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\n\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\t\u0010\n\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000b\u001a\u00020\u0003H\u00c6\u0003J\u001d\u0010\u000c\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\r\u001a\u00020\u000e2\u0008\u0010\u000f\u001a\u0004\u0018\u00010\u0010H\u00d6\u0003J\t\u0010\u0011\u001a\u00020\u0012H\u00d6\u0001J\t\u0010\u0013\u001a\u00020\u0003H\u00d6\u0001R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008R\u0016\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\u0008\u00a8\u0006\u0014"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;",
        "Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;",
        "userId",
        "",
        "vin",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        "getUserId",
        "()Ljava/lang/String;",
        "getVin",
        "component1",
        "component2",
        "copy",
        "equals",
        "",
        "other",
        "",
        "hashCode",
        "",
        "toString",
        "async-event_release"
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
.field private final userId:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "userId"
    .end annotation
.end field

.field private final vin:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vin"
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "userId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vin"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 17
    .line 18
    return-void
.end method

.method public static synthetic copy$default(Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->copy(Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;
    .locals 0

    .line 1
    const-string p0, "userId"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "vin"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2}, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
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
    instance-of v1, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;

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
    check-cast p1, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 25
    .line 26
    iget-object p1, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public final getUserId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->userId:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->vin:Ljava/lang/String;

    .line 4
    .line 5
    const-string v1, ", vin="

    .line 6
    .line 7
    const-string v2, ")"

    .line 8
    .line 9
    const-string v3, "UserNominationEventDataDto(userId="

    .line 10
    .line 11
    invoke-static {v3, v0, v1, p0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
