.class abstract Lcom/squareup/moshi/CollectionJsonAdapter;
.super Lcom/squareup/moshi/JsonAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<C::",
        "Ljava/util/Collection<",
        "TT;>;T:",
        "Ljava/lang/Object;",
        ">",
        "Lcom/squareup/moshi/JsonAdapter<",
        "TC;>;"
    }
.end annotation


# static fields
.field public static final b:Lcom/squareup/moshi/JsonAdapter$Factory;


# instance fields
.field public final a:Lcom/squareup/moshi/JsonAdapter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/squareup/moshi/CollectionJsonAdapter$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/squareup/moshi/CollectionJsonAdapter$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/squareup/moshi/CollectionJsonAdapter;->b:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lcom/squareup/moshi/JsonAdapter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/squareup/moshi/JsonAdapter;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/CollectionJsonAdapter;->a:Lcom/squareup/moshi/JsonAdapter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public bridge synthetic a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/CollectionJsonAdapter;->g(Lcom/squareup/moshi/JsonReader;)Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Ljava/util/Collection;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcom/squareup/moshi/CollectionJsonAdapter;->i(Lcom/squareup/moshi/JsonWriter;Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final g(Lcom/squareup/moshi/JsonReader;)Ljava/util/Collection;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/CollectionJsonAdapter;->h()Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->a()V

    .line 6
    .line 7
    .line 8
    :goto_0
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->h()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Lcom/squareup/moshi/CollectionJsonAdapter;->a:Lcom/squareup/moshi/JsonAdapter;

    .line 15
    .line 16
    invoke-virtual {v1, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->d()V

    .line 25
    .line 26
    .line 27
    return-object v0
.end method

.method public abstract h()Ljava/util/Collection;
.end method

.method public final i(Lcom/squareup/moshi/JsonWriter;Ljava/util/Collection;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->a()Lcom/squareup/moshi/JsonWriter;

    .line 2
    .line 3
    .line 4
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 5
    .line 6
    .line 7
    move-result-object p2

    .line 8
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, p0, Lcom/squareup/moshi/CollectionJsonAdapter;->a:Lcom/squareup/moshi/JsonAdapter;

    .line 19
    .line 20
    invoke-virtual {v1, p1, v0}, Lcom/squareup/moshi/JsonAdapter;->e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->f()Lcom/squareup/moshi/JsonWriter;

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/squareup/moshi/CollectionJsonAdapter;->a:Lcom/squareup/moshi/JsonAdapter;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, ".collection()"

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
