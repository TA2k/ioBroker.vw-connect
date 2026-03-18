.class public final Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\r\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0087\u0008\u0018\u00002\u00020\u0001B#\u0012\u0008\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000b\u0010\u000c\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\t\u0010\r\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J)\u0010\u000f\u001a\u00020\u00002\n\u0008\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u0010\u001a\u00020\u00112\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0013\u001a\u00020\u0014H\u00d6\u0001J\t\u0010\u0015\u001a\u00020\u0003H\u00d6\u0001R\u0013\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\tR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\tR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\t\u00a8\u0006\u0016"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;",
        "",
        "country",
        "",
        "brand",
        "partnerNumber",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "getCountry",
        "()Ljava/lang/String;",
        "getBrand",
        "getPartnerNumber",
        "component1",
        "component2",
        "component3",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "accident-damage-report_release"
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
.field private final brand:Ljava/lang/String;

.field private final country:Ljava/lang/String;

.field private final partnerNumber:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "brand"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "partnerNumber"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p4, p4, 0x2

    if-eqz p4, :cond_0

    .line 5
    const-string p2, "C"

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3}, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;
    .locals 0

    .line 1
    const-string p0, "brand"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "partnerNumber"

    .line 7
    .line 8
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3}, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

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
    instance-of v1, p1, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;

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
    check-cast p1, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    return v0
.end method

.method public final getBrand()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCountry()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPartnerNumber()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    add-int/2addr p0, v0

    .line 27
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->country:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->brand:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/accidentdamagereport/infrastructure/AdmPreferredDealer;->partnerNumber:Ljava/lang/String;

    .line 6
    .line 7
    const-string v2, ", brand="

    .line 8
    .line 9
    const-string v3, ", partnerNumber="

    .line 10
    .line 11
    const-string v4, "AdmPreferredDealer(country="

    .line 12
    .line 13
    invoke-static {v4, v0, v2, v1, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, ")"

    .line 18
    .line 19
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
