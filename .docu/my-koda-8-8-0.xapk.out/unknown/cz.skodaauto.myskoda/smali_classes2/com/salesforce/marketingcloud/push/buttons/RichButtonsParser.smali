.class public final Lcom/salesforce/marketingcloud/push/buttons/RichButtonsParser;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/push/j;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/salesforce/marketingcloud/push/j<",
        "Lcom/salesforce/marketingcloud/push/buttons/a;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public hydrate(Lcom/salesforce/marketingcloud/push/data/Template;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string p0, "obj"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of p0, p1, Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 7
    .line 8
    if-eqz p0, :cond_1

    .line 9
    .line 10
    check-cast p1, Lcom/salesforce/marketingcloud/push/buttons/a;

    .line 11
    .line 12
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/buttons/a;->k()Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    new-instance p1, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/16 v0, 0xa

    .line 19
    .line 20
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lcom/salesforce/marketingcloud/push/buttons/a$c;

    .line 42
    .line 43
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/buttons/a$c;->q()Lorg/json/JSONObject;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    new-instance p0, Lorg/json/JSONArray;

    .line 52
    .line 53
    invoke-direct {p0, p1}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    const-string p1, "toString(...)"

    .line 61
    .line 62
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    return-object p0

    .line 66
    :cond_1
    new-instance p0, Lcom/salesforce/marketingcloud/push/m;

    .line 67
    .line 68
    const-string p1, "obj is not a RichButtonTemplate"

    .line 69
    .line 70
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/m;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0
.end method

.method public parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/buttons/a;
    .locals 2

    const-string p0, "obj"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance p0, Lorg/json/JSONArray;

    invoke-direct {p0, p1}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    .line 3
    invoke-static {p0}, Lcom/salesforce/marketingcloud/push/buttons/b;->a(Lorg/json/JSONArray;)Ljava/util/List;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result p1

    if-nez p1, :cond_0

    .line 4
    new-instance p1, Lcom/salesforce/marketingcloud/push/buttons/a;

    const/4 v0, 0x2

    const/4 v1, 0x0

    invoke-direct {p1, p0, v1, v0, v1}, Lcom/salesforce/marketingcloud/push/buttons/a;-><init>(Ljava/util/List;Lcom/salesforce/marketingcloud/push/data/Style;ILkotlin/jvm/internal/g;)V

    return-object p1

    .line 5
    :cond_0
    new-instance p0, Lcom/salesforce/marketingcloud/push/m;

    const-string p1, "Button is empty"

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/m;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public bridge synthetic parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Template;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/push/buttons/RichButtonsParser;->parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/buttons/a;

    move-result-object p0

    return-object p0
.end method
