.class public final Lcom/salesforce/marketingcloud/events/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "EventUtilsKt"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/events/d;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)Lcom/salesforce/marketingcloud/events/Event;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/events/EventManager$Companion;

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->name()Ljava/lang/String;

    move-result-object v1

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->attributes()Ljava/util/Map;

    move-result-object v2

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->getProducer()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    move-result-object p0

    .line 8
    invoke-virtual {v0, v1, v2, p0}, Lcom/salesforce/marketingcloud/events/EventManager$Companion;->customEvent(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;)Lcom/salesforce/marketingcloud/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final a(Lcom/salesforce/marketingcloud/events/Event;)Ljava/util/Map;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/events/Event;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;"
        }
    .end annotation

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {p0}, Lcom/salesforce/marketingcloud/events/Event;->attributes()Ljava/util/Map;

    move-result-object p0

    const/4 v1, 0x0

    const/4 v2, 0x4

    invoke-static {v0, p0, v1, v2, v1}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/String;ILjava/lang/Object;)Ljava/util/Map;

    move-result-object p0

    return-object p0
.end method

.method private static final a(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/String;)Ljava/util/Map;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;",
            "Ljava/lang/Object;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;"
        }
    .end annotation

    .line 25
    :try_start_0
    instance-of v0, p1, Ljava/util/List;

    if-eqz v0, :cond_0

    check-cast p1, Ljava/util/List;

    invoke-static {p1}, Lkotlin/jvm/internal/j0;->b(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/util/Map;Ljava/util/List;Ljava/lang/String;)Ljava/util/Map;

    move-result-object p0

    return-object p0

    .line 26
    :cond_0
    instance-of v0, p1, Ljava/util/Map;

    if-eqz v0, :cond_1

    invoke-static {p1}, Lkotlin/jvm/internal/j0;->c(Ljava/lang/Object;)Ljava/util/Map;

    move-result-object p1

    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/util/Map;Ljava/util/Map;Ljava/lang/String;)Ljava/util/Map;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_1
    return-object p0
.end method

.method public static synthetic a(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/String;ILjava/lang/Object;)Ljava/util/Map;
    .locals 0

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    .line 23
    const-string p2, ""

    .line 24
    :cond_0
    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/String;)Ljava/util/Map;

    move-result-object p0

    return-object p0
.end method

.method private static final a(Ljava/util/Map;Ljava/util/List;Ljava/lang/String;)Ljava/util/Map;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;"
        }
    .end annotation

    .line 36
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    .line 37
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v1

    const-string v2, "getDefault(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "toLowerCase(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz v0, :cond_0

    .line 38
    invoke-static {v0}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    .line 39
    invoke-static {p0, v0, p2}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/String;)Ljava/util/Map;

    move-result-object v0

    invoke-interface {p0, v0}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    goto :goto_0

    .line 40
    :cond_1
    invoke-interface {p0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Collection;

    if-eqz v2, :cond_3

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_2

    goto :goto_1

    .line 41
    :cond_2
    invoke-interface {p0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    if-eqz v1, :cond_0

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 42
    :cond_3
    :goto_1
    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-interface {p0, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_4
    return-object p0
.end method

.method private static final a(Ljava/util/Map;Ljava/util/Map;Ljava/lang/String;)Ljava/util/Map;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;",
            "Ljava/util/Map<",
            "Ljava/lang/Object;",
            "Ljava/lang/Object;",
            ">;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;"
        }
    .end annotation

    .line 27
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map$Entry;

    .line 28
    invoke-static {p2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    move-result v1

    const-string v2, "toLowerCase(...)"

    const-string v3, "getDefault(...)"

    if-nez v1, :cond_1

    .line 29
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "."

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v4

    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_1

    .line 30
    :cond_1
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    const-string v4, "null cannot be cast to non-null type kotlin.String"

    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Ljava/lang/String;

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v4

    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    :goto_1
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v2}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    .line 32
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-static {p0, v0, v1}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/String;)Ljava/util/Map;

    move-result-object v0

    invoke-interface {p0, v0}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    goto :goto_0

    .line 33
    :cond_2
    invoke-interface {p0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Collection;

    if-eqz v2, :cond_4

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_3

    goto :goto_2

    .line 34
    :cond_3
    invoke-interface {p0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    .line 35
    :cond_4
    :goto_2
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-interface {p0, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto/16 :goto_0

    :cond_5
    return-object p0
.end method

.method private static final a(Ljava/lang/Object;)Z
    .locals 5

    .line 43
    instance-of v0, p0, Ljava/util/Map;

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    return v1

    .line 44
    :cond_0
    instance-of v0, p0, Ljava/util/List;

    const/4 v2, 0x0

    if-eqz v0, :cond_3

    .line 45
    check-cast p0, Ljava/lang/Iterable;

    .line 46
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    move v0, v2

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    add-int/lit8 v4, v0, 0x1

    if-ltz v0, :cond_2

    if-eqz v3, :cond_1

    .line 47
    invoke-static {v3}, Lcom/salesforce/marketingcloud/events/d;->a(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    return v1

    :cond_1
    move v0, v4

    goto :goto_0

    .line 48
    :cond_2
    invoke-static {}, Ljp/k1;->r()V

    const/4 p0, 0x0

    throw p0

    :cond_3
    return v2
.end method

.method public static final a([Ljava/lang/Object;)[Lcom/salesforce/marketingcloud/events/Event;
    .locals 2

    .line 1
    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x3

    invoke-static {p0, v0, v0, v1, v0}, Lcom/salesforce/marketingcloud/events/d;->a([Ljava/lang/Object;Ljava/util/EnumSet;Ljava/util/EnumSet;ILjava/lang/Object;)[Lcom/salesforce/marketingcloud/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final a([Ljava/lang/Object;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/events/Event;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Ljava/lang/Object;",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
            ">;)[",
            "Lcom/salesforce/marketingcloud/events/Event;"
        }
    .end annotation

    .line 2
    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "producers"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x2

    invoke-static {p0, p1, v0, v1, v0}, Lcom/salesforce/marketingcloud/events/d;->a([Ljava/lang/Object;Ljava/util/EnumSet;Ljava/util/EnumSet;ILjava/lang/Object;)[Lcom/salesforce/marketingcloud/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final a([Ljava/lang/Object;Ljava/util/EnumSet;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/events/Event;
    .locals 22
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Ljava/lang/Object;",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
            ">;",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;",
            ">;)[",
            "Lcom/salesforce/marketingcloud/events/Event;"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    const-string v3, "<this>"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "producers"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "categories"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 13
    array-length v4, v0

    const/4 v5, 0x0

    move v6, v5

    :goto_0
    if-ge v6, v4, :cond_2

    aget-object v7, v0, v6

    if-eqz v7, :cond_1

    .line 14
    :try_start_0
    move-object v8, v7

    check-cast v8, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 15
    invoke-virtual {v8}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->getProducer()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    move-result-object v9

    invoke-virtual {v1, v9}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_1

    invoke-virtual {v8}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->getCategory()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    move-result-object v9

    invoke-virtual {v2, v9}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_1

    .line 16
    invoke-static {v8}, Lcom/salesforce/marketingcloud/events/d;->a(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)Lcom/salesforce/marketingcloud/events/Event;

    move-result-object v9

    if-eqz v9, :cond_0

    .line 17
    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-result v9

    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v9

    goto :goto_1

    :cond_0
    const/4 v9, 0x0

    :goto_1
    if-nez v9, :cond_1

    .line 18
    sget-object v10, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v11, Lcom/salesforce/marketingcloud/events/d;->a:Ljava/lang/String;

    new-instance v13, Lcom/salesforce/marketingcloud/events/d$a;

    invoke-direct {v13, v8}, Lcom/salesforce/marketingcloud/events/d$a;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    const/4 v14, 0x2

    const/4 v15, 0x0

    const/4 v12, 0x0

    invoke-static/range {v10 .. v15}, Lcom/salesforce/marketingcloud/g;->c(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    .line 19
    :catch_0
    sget-object v16, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v17, Lcom/salesforce/marketingcloud/events/d;->a:Ljava/lang/String;

    new-instance v8, Lcom/salesforce/marketingcloud/events/d$b;

    invoke-direct {v8, v7}, Lcom/salesforce/marketingcloud/events/d$b;-><init>(Ljava/lang/Object;)V

    const/16 v20, 0x2

    const/16 v21, 0x0

    const/16 v18, 0x0

    move-object/from16 v19, v8

    invoke-static/range {v16 .. v21}, Lcom/salesforce/marketingcloud/g;->b(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    :cond_1
    :goto_2
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    .line 20
    :cond_2
    new-array v0, v5, [Lcom/salesforce/marketingcloud/events/Event;

    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lcom/salesforce/marketingcloud/events/Event;

    return-object v0
.end method

.method public static synthetic a([Ljava/lang/Object;Ljava/util/EnumSet;Ljava/util/EnumSet;ILjava/lang/Object;)[Lcom/salesforce/marketingcloud/events/Event;
    .locals 1

    and-int/lit8 p4, p3, 0x1

    const-string v0, "allOf(...)"

    if-eqz p4, :cond_0

    .line 9
    const-class p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    invoke-static {p1}, Ljava/util/EnumSet;->allOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    move-result-object p1

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    .line 10
    const-class p2, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    invoke-static {p2}, Ljava/util/EnumSet;->allOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    move-result-object p2

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    :cond_1
    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/events/d;->a([Ljava/lang/Object;Ljava/util/EnumSet;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic a([Ljava/lang/Object;Ljava/util/EnumSet;ILjava/lang/Object;)[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    .line 21
    const-class p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    invoke-static {p1}, Ljava/util/EnumSet;->allOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    move-result-object p1

    const-string p2, "allOf(...)"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    :cond_0
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/events/d;->b([Ljava/lang/Object;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final b(Lcom/salesforce/marketingcloud/events/Event;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 8

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    .line 3
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/events/Event;->name()Ljava/lang/String;

    move-result-object v2

    .line 4
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/events/Event;->attributes()Ljava/util/Map;

    move-result-object v3

    .line 5
    sget-object v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    const/16 v6, 0x8

    const/4 v7, 0x0

    const/4 v5, 0x0

    .line 6
    invoke-static/range {v1 .. v7}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->customEvent$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final b([Ljava/lang/Object;)[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 2

    .line 1
    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x1

    invoke-static {p0, v0, v1, v0}, Lcom/salesforce/marketingcloud/events/d;->a([Ljava/lang/Object;Ljava/util/EnumSet;ILjava/lang/Object;)[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    return-object p0
.end method

.method public static final b([Ljava/lang/Object;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;
    .locals 21
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Ljava/lang/Object;",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;",
            ">;)[",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-string v2, "<this>"

    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "producers"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 8
    array-length v3, v0

    const/4 v4, 0x0

    move v5, v4

    :goto_0
    if-ge v5, v3, :cond_2

    aget-object v6, v0, v5

    if-eqz v6, :cond_1

    .line 9
    :try_start_0
    move-object v7, v6

    check-cast v7, Lcom/salesforce/marketingcloud/events/Event;

    .line 10
    invoke-interface {v7}, Lcom/salesforce/marketingcloud/events/Event;->getProducer()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    move-result-object v8

    invoke-virtual {v1, v8}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_1

    .line 11
    invoke-static {v7}, Lcom/salesforce/marketingcloud/events/d;->b(Lcom/salesforce/marketingcloud/events/Event;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object v8

    if-eqz v8, :cond_0

    .line 12
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-result v8

    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v8

    goto :goto_1

    :cond_0
    const/4 v8, 0x0

    :goto_1
    if-nez v8, :cond_1

    .line 13
    sget-object v9, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v10, Lcom/salesforce/marketingcloud/events/d;->a:Ljava/lang/String;

    new-instance v12, Lcom/salesforce/marketingcloud/events/d$c;

    invoke-direct {v12, v7}, Lcom/salesforce/marketingcloud/events/d$c;-><init>(Lcom/salesforce/marketingcloud/events/Event;)V

    const/4 v13, 0x2

    const/4 v14, 0x0

    const/4 v11, 0x0

    invoke-static/range {v9 .. v14}, Lcom/salesforce/marketingcloud/g;->c(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    .line 14
    :catch_0
    sget-object v15, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v16, Lcom/salesforce/marketingcloud/events/d;->a:Ljava/lang/String;

    new-instance v7, Lcom/salesforce/marketingcloud/events/d$d;

    invoke-direct {v7, v6}, Lcom/salesforce/marketingcloud/events/d$d;-><init>(Ljava/lang/Object;)V

    const/16 v19, 0x2

    const/16 v20, 0x0

    const/16 v17, 0x0

    move-object/from16 v18, v7

    invoke-static/range {v15 .. v20}, Lcom/salesforce/marketingcloud/g;->e(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    :cond_1
    :goto_2
    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    .line 15
    :cond_2
    new-array v0, v4, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    return-object v0
.end method
