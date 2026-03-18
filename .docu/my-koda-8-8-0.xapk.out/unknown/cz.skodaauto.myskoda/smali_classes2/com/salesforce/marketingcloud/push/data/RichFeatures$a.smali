.class public final Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/RichFeatures;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;
    .locals 5

    const-string p0, "optString(...)"

    const-string v0, "json"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    :try_start_0
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0, p1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 2
    const-string p1, "lic"

    invoke-virtual {v0, p1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 3
    const-string v1, "sic"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 4
    const-string v1, "vt"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    .line 5
    sget-object v3, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->Companion:Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

    invoke-virtual {v3, v1}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;->a(Ljava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/Template$Type;

    move-result-object v3

    .line 6
    sget-object v4, Lcom/salesforce/marketingcloud/push/j$a;->a:Lcom/salesforce/marketingcloud/push/j$a$a;

    invoke-virtual {v4, v3}, Lcom/salesforce/marketingcloud/push/j$a$a;->a(Lcom/salesforce/marketingcloud/push/data/Template$Type;)Lcom/salesforce/marketingcloud/push/j;

    move-result-object v3

    if-eqz v3, :cond_0

    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v3, v1}, Lcom/salesforce/marketingcloud/push/j;->parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Template;

    move-result-object v1

    goto :goto_0

    :cond_0
    move-object v1, v2

    .line 8
    :goto_0
    const-string v3, "btn"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 9
    sget-object v3, Lcom/salesforce/marketingcloud/push/j$a;->a:Lcom/salesforce/marketingcloud/push/j$a$a;

    sget-object v4, Lcom/salesforce/marketingcloud/push/data/Template$Type;->RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    invoke-virtual {v3, v4}, Lcom/salesforce/marketingcloud/push/j$a$a;->a(Lcom/salesforce/marketingcloud/push/data/Template$Type;)Lcom/salesforce/marketingcloud/push/j;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-interface {v3, v0}, Lcom/salesforce/marketingcloud/push/j;->parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Template;

    move-result-object v2

    .line 10
    :cond_1
    check-cast v2, Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    invoke-direct {v0, p1, p0, v1, v2}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Template;Lcom/salesforce/marketingcloud/push/buttons/a;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 12
    new-instance p1, Lcom/salesforce/marketingcloud/push/d;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/push/d;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final a(Ljava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/Template$Type;
    .locals 1

    .line 13
    instance-of p0, p1, Lorg/json/JSONObject;

    if-eqz p0, :cond_1

    .line 14
    check-cast p1, Lorg/json/JSONObject;

    const-string p0, "t"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 15
    sget-object p1, Lcom/salesforce/marketingcloud/push/data/Template$Type;->CarouselFull:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/Template$Type;->getValue()Ljava/lang/String;

    move-result-object v0

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p1

    .line 16
    :cond_0
    new-instance p1, Lcom/salesforce/marketingcloud/push/m;

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/push/m;-><init>(Ljava/lang/String;)V

    throw p1

    .line 17
    :cond_1
    new-instance p0, Lcom/salesforce/marketingcloud/push/m;

    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/m;-><init>(Ljava/lang/String;)V

    throw p0
.end method
