.class public final Lcom/salesforce/marketingcloud/http/c$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/http/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field private a:Ljava/lang/String;

.field private b:Ljava/lang/String;

.field private c:I

.field private d:Ljava/lang/String;

.field private e:Ljava/lang/String;

.field private f:Lcom/salesforce/marketingcloud/http/b;

.field private g:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private h:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x7530

    .line 5
    .line 6
    iput v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->c:I

    .line 7
    .line 8
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->g:Ljava/util/Map;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(I)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 0

    .line 3
    iput p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->c:I

    return-object p0
.end method

.method public final a(Lcom/salesforce/marketingcloud/http/b;)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    const-string v0, "requestId"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->f:Lcom/salesforce/marketingcloud/http/b;

    return-object p0
.end method

.method public final a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    const-string v0, "contentType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->e:Ljava/lang/String;

    return-object p0
.end method

.method public final a(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "value"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->g:Ljava/util/Map;

    invoke-static {p2}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p0
.end method

.method public final a()Lcom/salesforce/marketingcloud/http/c;
    .locals 9

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->h:Ljava/util/List;

    if-nez v0, :cond_2

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->g:Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->g:Ljava/util/Map;

    .line 9
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 10
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map$Entry;

    .line 11
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-static {v3, v2}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v2

    .line 12
    invoke-static {v2, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_0
    move-object v7, v1

    goto :goto_1

    .line 13
    :cond_1
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    :cond_2
    move-object v7, v0

    .line 14
    :goto_1
    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/c$a;->d:Ljava/lang/String;

    if-nez v3, :cond_3

    .line 15
    const-string v0, ""

    iput-object v0, p0, Lcom/salesforce/marketingcloud/http/c$a;->e:Ljava/lang/String;

    .line 16
    :cond_3
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c$a;->a:Ljava/lang/String;

    const-string v0, "Required value was null."

    if-eqz v2, :cond_7

    .line 17
    iget-object v6, p0, Lcom/salesforce/marketingcloud/http/c$a;->b:Ljava/lang/String;

    if-eqz v6, :cond_6

    .line 18
    iget v4, p0, Lcom/salesforce/marketingcloud/http/c$a;->c:I

    .line 19
    iget-object v5, p0, Lcom/salesforce/marketingcloud/http/c$a;->e:Ljava/lang/String;

    if-eqz v5, :cond_5

    .line 20
    iget-object v8, p0, Lcom/salesforce/marketingcloud/http/c$a;->f:Lcom/salesforce/marketingcloud/http/b;

    if-eqz v8, :cond_4

    .line 21
    new-instance v1, Lcom/salesforce/marketingcloud/http/c;

    invoke-direct/range {v1 .. v8}, Lcom/salesforce/marketingcloud/http/c;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lcom/salesforce/marketingcloud/http/b;)V

    return-object v1

    .line 22
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 23
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 24
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 25
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final a(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    const-string v0, "headers"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->h:Ljava/util/List;

    return-void
.end method

.method public final b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    .line 1
    const-string v0, "method"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->a:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final c(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    .line 1
    const-string v0, "requestBody"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->d:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final d(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c$a;->b:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method
