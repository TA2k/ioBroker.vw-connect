.class public interface abstract Lcom/salesforce/marketingcloud/analytics/piwama/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract a()Ljava/lang/String;
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;
    .locals 0

    const-string p0, "<this>"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "fieldName"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-static {p1}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    if-eqz p1, :cond_1

    const/16 p2, 0x400

    if-le p1, p2, :cond_0

    const/4 p1, 0x0

    .line 7
    invoke-virtual {p0, p1, p2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p0

    const-string p1, "substring(...)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    :cond_0
    return-object p0

    .line 8
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "PiEvent must contain a "

    const-string p3, "."

    .line 9
    invoke-static {p1, p2, p3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 10
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public a(Lorg/json/JSONObject;)V
    .locals 2

    const-string v0, "<this>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->b()I

    move-result v0

    const-string v1, "analyticType"

    invoke-virtual {p1, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 2
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->d()Ljava/lang/String;

    move-result-object v0

    const-string v1, "api_endpoint"

    invoke-virtual {p1, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 3
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-lez v0, :cond_0

    invoke-interface {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a()Ljava/lang/String;

    move-result-object v0

    const-string v1, "event_name"

    invoke-virtual {p1, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 4
    :cond_0
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->e()Ljava/util/Date;

    move-result-object p0

    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p0

    const-string v0, "timestamp"

    invoke-virtual {p1, v0, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    return-void
.end method

.method public abstract b()I
.end method

.method public abstract c()Lorg/json/JSONObject;
.end method

.method public abstract d()Ljava/lang/String;
.end method

.method public abstract e()Ljava/util/Date;
.end method
