.class Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody$1;
.super Lu01/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;


# direct methods
.method public constructor <init>(Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;Lu01/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody$1;->e:Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lu01/n;-><init>(Lu01/h0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 0

    .line 1
    :try_start_0
    invoke-super {p0, p1, p2, p3}, Lu01/n;->A(Lu01/f;J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-wide p0

    .line 6
    :catch_0
    move-exception p1

    .line 7
    iget-object p0, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody$1;->e:Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;

    .line 8
    .line 9
    iput-object p1, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->g:Ljava/io/IOException;

    .line 10
    .line 11
    throw p1
.end method
