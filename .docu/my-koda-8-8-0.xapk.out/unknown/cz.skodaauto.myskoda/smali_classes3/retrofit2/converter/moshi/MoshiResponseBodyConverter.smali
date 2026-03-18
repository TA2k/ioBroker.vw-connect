.class final Lretrofit2/converter/moshi/MoshiResponseBodyConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Converter;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lretrofit2/Converter<",
        "Ld01/v0;",
        "TT;>;"
    }
.end annotation


# static fields
.field public static final e:Lu01/i;


# instance fields
.field public final d:Lcom/squareup/moshi/JsonAdapter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 2
    .line 3
    const-string v0, "EFBBBF"

    .line 4
    .line 5
    invoke-static {v0}, Lpy/a;->l(Ljava/lang/String;)Lu01/i;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lretrofit2/converter/moshi/MoshiResponseBodyConverter;->e:Lu01/i;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lcom/squareup/moshi/JsonAdapter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/converter/moshi/MoshiResponseBodyConverter;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ld01/v0;->p0()Lu01/h;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :try_start_0
    sget-object v1, Lretrofit2/converter/moshi/MoshiResponseBodyConverter;->e:Lu01/i;

    .line 8
    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    invoke-interface {v0, v2, v3, v1}, Lu01/h;->v(JLu01/i;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    iget-object v1, v1, Lu01/i;->d:[B

    .line 18
    .line 19
    array-length v1, v1

    .line 20
    int-to-long v1, v1

    .line 21
    invoke-interface {v0, v1, v2}, Lu01/h;->skip(J)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    :goto_0
    invoke-static {v0}, Lcom/squareup/moshi/JsonReader;->M(Lu01/h;)Lcom/squareup/moshi/JsonReader;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iget-object p0, p0, Lretrofit2/converter/moshi/MoshiResponseBodyConverter;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {v0}, Lcom/squareup/moshi/JsonReader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sget-object v1, Lcom/squareup/moshi/JsonReader$Token;->m:Lcom/squareup/moshi/JsonReader$Token;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    if-ne v0, v1, :cond_1

    .line 44
    .line 45
    invoke-virtual {p1}, Ld01/v0;->close()V

    .line 46
    .line 47
    .line 48
    return-object p0

    .line 49
    :cond_1
    :try_start_1
    new-instance p0, Lcom/squareup/moshi/JsonDataException;

    .line 50
    .line 51
    const-string v0, "JSON document was not fully consumed."

    .line 52
    .line 53
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    :goto_1
    invoke-virtual {p1}, Ld01/v0;->close()V

    .line 58
    .line 59
    .line 60
    throw p0
.end method
