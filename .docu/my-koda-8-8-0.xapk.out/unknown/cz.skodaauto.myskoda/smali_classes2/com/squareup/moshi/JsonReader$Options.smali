.class public final Lcom/squareup/moshi/JsonReader$Options;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/JsonReader;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Options"
.end annotation


# instance fields
.field public final a:[Ljava/lang/String;

.field public final b:Lu01/w;


# direct methods
.method public constructor <init>([Ljava/lang/String;Lu01/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/JsonReader$Options;->a:[Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/squareup/moshi/JsonReader$Options;->b:Lu01/w;

    .line 7
    .line 8
    return-void
.end method

.method public static varargs a([Ljava/lang/String;)Lcom/squareup/moshi/JsonReader$Options;
    .locals 5

    .line 1
    :try_start_0
    array-length v0, p0

    .line 2
    new-array v0, v0, [Lu01/i;

    .line 3
    .line 4
    new-instance v1, Lu01/f;

    .line 5
    .line 6
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    array-length v3, p0

    .line 11
    if-ge v2, v3, :cond_0

    .line 12
    .line 13
    aget-object v3, p0, v2

    .line 14
    .line 15
    invoke-static {v1, v3}, Lcom/squareup/moshi/JsonUtf8Writer;->l0(Lu01/g;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Lu01/f;->readByte()B

    .line 19
    .line 20
    .line 21
    iget-wide v3, v1, Lu01/f;->e:J

    .line 22
    .line 23
    invoke-virtual {v1, v3, v4}, Lu01/f;->S(J)Lu01/i;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    aput-object v3, v0, v2

    .line 28
    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance v1, Lcom/squareup/moshi/JsonReader$Options;

    .line 33
    .line 34
    invoke-virtual {p0}, [Ljava/lang/String;->clone()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, [Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {v0}, Lu01/b;->f([Lu01/i;)Lu01/w;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-direct {v1, p0, v0}, Lcom/squareup/moshi/JsonReader$Options;-><init>([Ljava/lang/String;Lu01/w;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    .line 47
    return-object v1

    .line 48
    :catch_0
    move-exception p0

    .line 49
    new-instance v0, Ljava/lang/AssertionError;

    .line 50
    .line 51
    invoke-direct {v0, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    throw v0
.end method
