.class public final Lcom/salesforce/marketingcloud/push/data/b$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/b;
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/push/data/b$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/b;
    .locals 9

    const-string p0, "json"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    const-string p0, "ul"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "optString(...)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_2

    .line 2
    const-string p0, "at"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p0

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    sget-object v1, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    invoke-virtual {v1, p0}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object p0

    move-object v4, p0

    goto :goto_0

    :cond_0
    move-object v4, v0

    .line 3
    :goto_0
    const-string p0, "s"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p0

    if-eqz p0, :cond_1

    sget-object p1, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object v0

    :cond_1
    move-object v5, v0

    .line 4
    new-instance v2, Lcom/salesforce/marketingcloud/push/data/b;

    const/16 v7, 0x8

    const/4 v8, 0x0

    const/4 v6, 0x0

    invoke-direct/range {v2 .. v8}, Lcom/salesforce/marketingcloud/push/data/b;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    return-object v2

    .line 5
    :cond_2
    new-instance p1, Lcom/salesforce/marketingcloud/push/e;

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/push/e;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final a(Lcom/salesforce/marketingcloud/push/data/b;)Lorg/json/JSONObject;
    .locals 2

    const-string p0, "media"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 7
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/b;->o()Ljava/lang/String;

    move-result-object v0

    const-string v1, "ul"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 8
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/b;->n()Lcom/salesforce/marketingcloud/push/data/c;

    move-result-object v0

    if-eqz v0, :cond_0

    sget-object v1, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lcom/salesforce/marketingcloud/push/data/c;)Lorg/json/JSONObject;

    move-result-object v0

    const-string v1, "at"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 9
    :cond_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/b;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    move-result-object p1

    if-eqz p1, :cond_1

    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lcom/salesforce/marketingcloud/push/data/Style;)Lorg/json/JSONObject;

    move-result-object p1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    const-string v0, "s"

    invoke-virtual {p0, v0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    return-object p0
.end method
