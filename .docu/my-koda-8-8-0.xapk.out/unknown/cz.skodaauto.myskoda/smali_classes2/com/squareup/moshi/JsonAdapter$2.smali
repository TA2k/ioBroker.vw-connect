.class Lcom/squareup/moshi/JsonAdapter$2;
.super Lcom/squareup/moshi/JsonAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/squareup/moshi/JsonAdapter<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# virtual methods
.method public final a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-boolean p0, p1, Lcom/squareup/moshi/JsonReader;->h:Z

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    iput-boolean v0, p1, Lcom/squareup/moshi/JsonReader;->h:Z

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    :try_start_0
    throw v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    :catchall_0
    move-exception v0

    .line 9
    iput-boolean p0, p1, Lcom/squareup/moshi/JsonReader;->h:Z

    .line 10
    .line 11
    throw v0
.end method

.method public final e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-boolean p0, p1, Lcom/squareup/moshi/JsonWriter;->i:Z

    .line 2
    .line 3
    const/4 p2, 0x1

    .line 4
    iput-boolean p2, p1, Lcom/squareup/moshi/JsonWriter;->i:Z

    .line 5
    .line 6
    const/4 p2, 0x0

    .line 7
    :try_start_0
    throw p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    :catchall_0
    move-exception p2

    .line 9
    iput-boolean p0, p1, Lcom/squareup/moshi/JsonWriter;->i:Z

    .line 10
    .line 11
    throw p2
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 8
    .line 9
    .line 10
    const-string v0, ".lenient()"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
