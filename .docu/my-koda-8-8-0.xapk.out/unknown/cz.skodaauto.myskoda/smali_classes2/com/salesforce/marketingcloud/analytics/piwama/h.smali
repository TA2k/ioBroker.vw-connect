.class public final Lcom/salesforce/marketingcloud/analytics/piwama/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/analytics/piwama/c;


# instance fields
.field private final a:Ljava/util/Date;

.field private final b:Ljava/lang/String;

.field private final c:Ljava/lang/String;

.field private final d:Ljava/lang/String;

.field private final e:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;)V
    .locals 2

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v1, "timestamp"

    .line 7
    .line 8
    invoke-static {p5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->a:Ljava/util/Date;

    .line 15
    .line 16
    const/4 p5, 0x1

    .line 17
    invoke-interface {p0, p1, v0, p5}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->b:Ljava/lang/String;

    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    const/4 p5, 0x0

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    const-string v0, "title"

    .line 28
    .line 29
    invoke-interface {p0, p2, v0, p5}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move-object p2, p1

    .line 35
    :goto_0
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->c:Ljava/lang/String;

    .line 36
    .line 37
    if-eqz p3, :cond_1

    .line 38
    .line 39
    const-string p2, "item"

    .line 40
    .line 41
    invoke-interface {p0, p3, p2, p5}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    move-object p2, p1

    .line 47
    :goto_1
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->d:Ljava/lang/String;

    .line 48
    .line 49
    if-eqz p4, :cond_2

    .line 50
    .line 51
    const-string p1, "search"

    .line 52
    .line 53
    invoke-interface {p0, p4, p1, p5}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    :cond_2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->e:Ljava/lang/String;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public a()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, ""

    .line 2
    .line 3
    return-object p0
.end method

.method public b()I
    .locals 0

    .line 1
    const/16 p0, 0x22b8

    .line 2
    .line 3
    return p0
.end method

.method public c()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/h;->d()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "api_endpoint"

    .line 11
    .line 12
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/h;->e()Ljava/util/Date;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v2, "timestamp"

    .line 24
    .line 25
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->b:Ljava/lang/String;

    .line 29
    .line 30
    const-string v2, "url"

    .line 31
    .line 32
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->c:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_0

    .line 42
    .line 43
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->c:Ljava/lang/String;

    .line 44
    .line 45
    const-string v2, "title"

    .line 46
    .line 47
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 48
    .line 49
    .line 50
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->d:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_1

    .line 57
    .line 58
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->d:Ljava/lang/String;

    .line 59
    .line 60
    const-string v2, "item"

    .line 61
    .line 62
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 63
    .line 64
    .line 65
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->e:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_2

    .line 72
    .line 73
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->e:Ljava/lang/String;

    .line 74
    .line 75
    const-string v1, "search"

    .line 76
    .line 77
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 78
    .line 79
    .line 80
    :cond_2
    return-object v0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "track_view"

    .line 2
    .line 3
    return-object p0
.end method

.method public e()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->a:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/h;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
