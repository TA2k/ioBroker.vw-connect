.class public final Lcom/salesforce/marketingcloud/push/carousel/CarouselParser;
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
        "Lcom/salesforce/marketingcloud/push/carousel/a;",
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
    .locals 2

    .line 1
    const-string p0, "obj"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of p0, p1, Lcom/salesforce/marketingcloud/push/carousel/a;

    .line 7
    .line 8
    if-eqz p0, :cond_2

    .line 9
    .line 10
    new-instance p0, Lorg/json/JSONObject;

    .line 11
    .line 12
    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Template;->f()Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/data/Template$Type;->getValue()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "t"

    .line 24
    .line 25
    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 26
    .line 27
    .line 28
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Template;->a()Lcom/salesforce/marketingcloud/push/data/Style;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    sget-object v1, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 35
    .line 36
    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lcom/salesforce/marketingcloud/push/data/Style;)Lorg/json/JSONObject;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    const-string v1, "s"

    .line 41
    .line 42
    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 43
    .line 44
    .line 45
    :cond_0
    check-cast p1, Lcom/salesforce/marketingcloud/push/carousel/a;

    .line 46
    .line 47
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    new-instance v0, Ljava/util/ArrayList;

    .line 52
    .line 53
    const/16 v1, 0xa

    .line 54
    .line 55
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 60
    .line 61
    .line 62
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_1

    .line 71
    .line 72
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    check-cast v1, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 77
    .line 78
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->s()Lorg/json/JSONObject;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_1
    new-instance p1, Lorg/json/JSONArray;

    .line 87
    .line 88
    invoke-direct {p1, v0}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 89
    .line 90
    .line 91
    const-string v0, "it"

    .line 92
    .line 93
    invoke-virtual {p0, v0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    const-string p1, "toString(...)"

    .line 101
    .line 102
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    return-object p0

    .line 106
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/push/m;

    .line 107
    .line 108
    const-string p1, "Carousel is not a CarouselFullTemplate"

    .line 109
    .line 110
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/m;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0
.end method

.method public parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/carousel/a;
    .locals 7

    const-string p0, "obj"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0, p1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 3
    const-string p1, "it"

    invoke-virtual {p0, p1}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v0

    if-eqz v0, :cond_2

    .line 4
    invoke-static {v0}, Lcom/salesforce/marketingcloud/push/carousel/c;->a(Lorg/json/JSONArray;)Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result p1

    if-nez p1, :cond_1

    .line 5
    const-string p1, "s"

    invoke-virtual {p0, p1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p0

    if-eqz p0, :cond_0

    sget-object p1, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/Style$b;

    move-result-object p0

    :goto_0
    move-object v4, p0

    goto :goto_1

    :cond_0
    const/4 p0, 0x0

    goto :goto_0

    .line 6
    :goto_1
    new-instance v1, Lcom/salesforce/marketingcloud/push/carousel/a;

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v3, 0x0

    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/push/carousel/a;-><init>(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;ILkotlin/jvm/internal/g;)V

    return-object v1

    .line 7
    :cond_1
    new-instance p0, Lcom/salesforce/marketingcloud/push/m;

    const-string p1, "Carousel is empty"

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/m;-><init>(Ljava/lang/String;)V

    throw p0

    .line 8
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/push/e;

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/e;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public bridge synthetic parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Template;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/push/carousel/CarouselParser;->parse(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/carousel/a;

    move-result-object p0

    return-object p0
.end method
