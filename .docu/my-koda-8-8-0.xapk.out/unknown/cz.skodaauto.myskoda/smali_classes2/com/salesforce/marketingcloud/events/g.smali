.class public final Lcom/salesforce/marketingcloud/events/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/events/g$a;,
        Lcom/salesforce/marketingcloud/events/g$b;
    }
.end annotation


# instance fields
.field private final a:I

.field private final b:Ljava/lang/String;

.field private final c:Lcom/salesforce/marketingcloud/events/g$a;

.field private final d:Lcom/salesforce/marketingcloud/events/g$b;

.field private final e:Ljava/lang/String;


# direct methods
.method public constructor <init>(ILjava/lang/String;Lcom/salesforce/marketingcloud/events/g$a;Lcom/salesforce/marketingcloud/events/g$b;Ljava/lang/String;)V
    .locals 1

    const-string v0, "key"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "operator"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "valueType"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "value"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 8

    const-string v0, "json"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    const-string v0, "index"

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v3

    .line 8
    const-string v0, "key"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    const-string v0, "getString(...)"

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    const-string v1, "operator"

    invoke-virtual {p1, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/events/g$a;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/events/g$a;

    move-result-object v5

    .line 10
    const-string v1, "valueType"

    invoke-virtual {p1, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/events/g$b;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/events/g$b;

    move-result-object v6

    .line 11
    const-string v1, "value"

    invoke-virtual {p1, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v2, p0

    .line 12
    invoke-direct/range {v2 .. v7}, Lcom/salesforce/marketingcloud/events/g;-><init>(ILjava/lang/String;Lcom/salesforce/marketingcloud/events/g$a;Lcom/salesforce/marketingcloud/events/g$b;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/events/g;ILjava/lang/String;Lcom/salesforce/marketingcloud/events/g$a;Lcom/salesforce/marketingcloud/events/g$b;Ljava/lang/String;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/events/g;
    .locals 0

    and-int/lit8 p7, p6, 0x1

    if-eqz p7, :cond_0

    .line 3
    iget p1, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    :cond_0
    and-int/lit8 p7, p6, 0x2

    if-eqz p7, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    :cond_1
    and-int/lit8 p7, p6, 0x4

    if-eqz p7, :cond_2

    iget-object p3, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    :cond_2
    and-int/lit8 p7, p6, 0x8

    if-eqz p7, :cond_3

    iget-object p4, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    :cond_3
    and-int/lit8 p6, p6, 0x10

    if-eqz p6, :cond_4

    iget-object p5, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    :cond_4
    move-object p6, p4

    move-object p7, p5

    move-object p4, p2

    move-object p5, p3

    move-object p2, p0

    move p3, p1

    invoke-virtual/range {p2 .. p7}, Lcom/salesforce/marketingcloud/events/g;->a(ILjava/lang/String;Lcom/salesforce/marketingcloud/events/g$a;Lcom/salesforce/marketingcloud/events/g$b;Ljava/lang/String;)Lcom/salesforce/marketingcloud/events/g;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    return p0
.end method

.method public final a(ILjava/lang/String;Lcom/salesforce/marketingcloud/events/g$a;Lcom/salesforce/marketingcloud/events/g$b;Ljava/lang/String;)Lcom/salesforce/marketingcloud/events/g;
    .locals 6

    .line 2
    const-string p0, "key"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "operator"

    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "valueType"

    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "value"

    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lcom/salesforce/marketingcloud/events/g;

    move v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/events/g;-><init>(ILjava/lang/String;Lcom/salesforce/marketingcloud/events/g$a;Lcom/salesforce/marketingcloud/events/g$b;Ljava/lang/String;)V

    return-object v0
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()Lcom/salesforce/marketingcloud/events/g$a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()Lcom/salesforce/marketingcloud/events/g$b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 2
    .line 3
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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/events/g;

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
    check-cast p1, Lcom/salesforce/marketingcloud/events/g;

    .line 12
    .line 13
    iget v1, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    .line 14
    .line 15
    iget v3, p1, Lcom/salesforce/marketingcloud/events/g;->a:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 32
    .line 33
    iget-object v3, p1, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 39
    .line 40
    iget-object v3, p1, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 46
    .line 47
    iget-object p1, p1, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-nez p0, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    return v0
.end method

.method public final f()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    .line 2
    .line 3
    return p0
.end method

.method public final g()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Lcom/salesforce/marketingcloud/events/g$a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    add-int/2addr v0, v2

    .line 31
    mul-int/2addr v0, v1

    .line 32
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    add-int/2addr p0, v0

    .line 39
    return p0
.end method

.method public final i()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j()Lcom/salesforce/marketingcloud/events/g$b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    .line 7
    .line 8
    const-string v2, "index"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 14
    .line 15
    const-string v2, "key"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    const-string v2, "operator"

    .line 27
    .line 28
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    const-string v2, "valueType"

    .line 38
    .line 39
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 43
    .line 44
    const-string v1, "value"

    .line 45
    .line 46
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 47
    .line 48
    .line 49
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/events/g;->a:I

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/g;->b:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/events/g;->c:Lcom/salesforce/marketingcloud/events/g$a;

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/events/g;->d:Lcom/salesforce/marketingcloud/events/g$b;

    .line 8
    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/g;->e:Ljava/lang/String;

    .line 10
    .line 11
    const-string v4, ", key="

    .line 12
    .line 13
    const-string v5, ", operator="

    .line 14
    .line 15
    const-string v6, "Rule(index="

    .line 16
    .line 17
    invoke-static {v6, v0, v4, v1, v5}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string v1, ", valueType="

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, ", value="

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v1, ")"

    .line 38
    .line 39
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
