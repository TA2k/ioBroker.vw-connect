.class public final Lcom/salesforce/marketingcloud/location/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "ShiftFlags"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/location/b$a;,
        Lcom/salesforce/marketingcloud/location/b$b;,
        Lcom/salesforce/marketingcloud/location/b$c;
    }
.end annotation


# static fields
.field public static final f:Lcom/salesforce/marketingcloud/location/b$a;

.field public static final g:I = 0x1

.field public static final h:I = 0x2

.field public static final i:I = 0x4


# instance fields
.field private final a:Ljava/lang/String;

.field private final b:F

.field private final c:D

.field private final d:D

.field private final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/location/b$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/location/b$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/location/b;->f:Lcom/salesforce/marketingcloud/location/b$a;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;FDDI)V
    .locals 1

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput p2, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 12
    .line 13
    iput-wide p3, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 14
    .line 15
    iput-wide p5, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 16
    .line 17
    iput p7, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 18
    .line 19
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/location/b;Ljava/lang/String;FDDIILjava/lang/Object;)Lcom/salesforce/marketingcloud/location/b;
    .locals 0

    and-int/lit8 p9, p8, 0x1

    if-eqz p9, :cond_0

    .line 3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

    :cond_0
    and-int/lit8 p9, p8, 0x2

    if-eqz p9, :cond_1

    iget p2, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    :cond_1
    and-int/lit8 p9, p8, 0x4

    if-eqz p9, :cond_2

    iget-wide p3, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    :cond_2
    and-int/lit8 p9, p8, 0x8

    if-eqz p9, :cond_3

    iget-wide p5, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    :cond_3
    and-int/lit8 p8, p8, 0x10

    if-eqz p8, :cond_4

    iget p7, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    :cond_4
    move p9, p7

    move-wide p7, p5

    move-wide p5, p3

    move-object p3, p1

    move p4, p2

    move-object p2, p0

    invoke-virtual/range {p2 .. p9}, Lcom/salesforce/marketingcloud/location/b;->a(Ljava/lang/String;FDDI)Lcom/salesforce/marketingcloud/location/b;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;FDDI)Lcom/salesforce/marketingcloud/location/b;
    .locals 8

    .line 2
    const-string p0, "id"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lcom/salesforce/marketingcloud/location/b;

    move-object v1, p1

    move v2, p2

    move-wide v3, p3

    move-wide v5, p5

    move v7, p7

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/location/b;-><init>(Ljava/lang/String;FDDI)V

    return-object v0
.end method

.method public final a()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

    return-object p0
.end method

.method public final b()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 2
    .line 3
    return p0
.end method

.method public final c()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final d()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final e()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/location/b;

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
    check-cast p1, Lcom/salesforce/marketingcloud/location/b;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

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
    iget v1, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 25
    .line 26
    iget v3, p1, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 27
    .line 28
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 36
    .line 37
    iget-wide v5, p1, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 38
    .line 39
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 47
    .line 48
    iget-wide v5, p1, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 49
    .line 50
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 58
    .line 59
    iget p1, p1, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 60
    .line 61
    if-eq p0, p1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    return v0
.end method

.method public final f()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final h()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

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
    iget v2, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 23
    .line 24
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 29
    .line 30
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, v0

    .line 35
    return p0
.end method

.method public final i()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 2
    .line 3
    return p0
.end method

.method public final j()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/b;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/location/b;->b:F

    .line 4
    .line 5
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/location/b;->c:D

    .line 6
    .line 7
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/location/b;->d:D

    .line 8
    .line 9
    iget p0, p0, Lcom/salesforce/marketingcloud/location/b;->e:I

    .line 10
    .line 11
    new-instance v6, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v7, "GeofenceRegion(id="

    .line 14
    .line 15
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v0, ", radius="

    .line 22
    .line 23
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, ", latitude="

    .line 30
    .line 31
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v6, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v0, ", longitude="

    .line 38
    .line 39
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v6, v4, v5}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v0, ", transition="

    .line 46
    .line 47
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v0, ")"

    .line 51
    .line 52
    invoke-static {p0, v0, v6}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
