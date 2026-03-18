.class public final Lcz/myskoda/api/bff/v1/PagingMetadataDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0010\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u001b\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\t\u0010\u000f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0010\u001a\u00020\u0005H\u00c6\u0003J\u001d\u0010\u0011\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u0005H\u00c6\u0001J\u0013\u0010\u0012\u001a\u00020\u00052\u0008\u0010\u0013\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0014\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u0015\u001a\u00020\u0016H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0008\u0010\t\u001a\u0004\u0008\n\u0010\u000bR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000c\u0010\t\u001a\u0004\u0008\r\u0010\u000e\u00a8\u0006\u0017"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/PagingMetadataDto;",
        "",
        "pageNumber",
        "",
        "hasNextPage",
        "",
        "<init>",
        "(IZ)V",
        "getPageNumber$annotations",
        "()V",
        "getPageNumber",
        "()I",
        "getHasNextPage$annotations",
        "getHasNextPage",
        "()Z",
        "component1",
        "component2",
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
.field private final hasNextPage:Z

.field private final pageNumber:I


# direct methods
.method public constructor <init>(IZ)V
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pageNumber"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "hasNextPage"
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 5
    .line 6
    iput-boolean p2, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 7
    .line 8
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/PagingMetadataDto;IZILjava/lang/Object;)Lcz/myskoda/api/bff/v1/PagingMetadataDto;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->copy(IZ)Lcz/myskoda/api/bff/v1/PagingMetadataDto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static synthetic getHasNextPage$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "hasNextPage"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPageNumber$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "pageNumber"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(IZ)Lcz/myskoda/api/bff/v1/PagingMetadataDto;
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pageNumber"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "hasNextPage"
        .end annotation
    .end param

    .line 1
    new-instance p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lcz/myskoda/api/bff/v1/PagingMetadataDto;-><init>(IZ)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/PagingMetadataDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/PagingMetadataDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 14
    .line 15
    iget v3, p1, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 21
    .line 22
    iget-boolean p1, p1, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 23
    .line 24
    if-eq p0, p1, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    return v0
.end method

.method public final getHasNextPage()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getPageNumber()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    .locals 3

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->pageNumber:I

    .line 2
    .line 3
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/PagingMetadataDto;->hasNextPage:Z

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "PagingMetadataDto(pageNumber="

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", hasNextPage="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
