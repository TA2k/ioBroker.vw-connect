.class public abstract Lcom/squareup/moshi/JsonAdapter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/squareup/moshi/JsonAdapter$Factory;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
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
.method public abstract a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
.end method

.method public final b(Ljava/lang/String;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance v0, Lu01/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lu01/f;->x0(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    new-instance p1, Lcom/squareup/moshi/JsonUtf8Reader;

    .line 10
    .line 11
    invoke-direct {p1, v0}, Lcom/squareup/moshi/JsonUtf8Reader;-><init>(Lu01/h;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->c()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-nez p0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonUtf8Reader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    sget-object p1, Lcom/squareup/moshi/JsonReader$Token;->m:Lcom/squareup/moshi/JsonReader$Token;

    .line 29
    .line 30
    if-ne p0, p1, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance p0, Lcom/squareup/moshi/JsonDataException;

    .line 34
    .line 35
    const-string p1, "JSON document was not fully consumed."

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    :goto_0
    return-object v0
.end method

.method public c()Z
    .locals 0

    .line 1
    instance-of p0, p0, Lcom/squareup/moshi/JsonAdapter$2;

    .line 2
    .line 3
    return p0
.end method

.method public final d()Lax/a;
    .locals 1

    .line 1
    instance-of v0, p0, Lax/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lax/a;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Lax/a;

    .line 9
    .line 10
    invoke-direct {v0, p0}, Lax/a;-><init>(Lcom/squareup/moshi/JsonAdapter;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public abstract e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
.end method

.method public final f(Lu01/g;Ljava/lang/Object;)V
    .locals 1

    .line 1
    new-instance v0, Lcom/squareup/moshi/JsonUtf8Writer;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lcom/squareup/moshi/JsonUtf8Writer;-><init>(Lu01/g;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0, p2}, Lcom/squareup/moshi/JsonAdapter;->e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method
