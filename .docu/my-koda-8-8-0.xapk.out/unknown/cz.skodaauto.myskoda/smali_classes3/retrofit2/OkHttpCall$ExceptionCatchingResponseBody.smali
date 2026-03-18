.class final Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;
.super Ld01/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/OkHttpCall;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ExceptionCatchingResponseBody"
.end annotation


# instance fields
.field public final e:Ld01/v0;

.field public final f:Lu01/b0;

.field public g:Ljava/io/IOException;


# direct methods
.method public constructor <init>(Ld01/v0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->e:Ld01/v0;

    .line 5
    .line 6
    new-instance v0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody$1;

    .line 7
    .line 8
    invoke-virtual {p1}, Ld01/v0;->p0()Lu01/h;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-direct {v0, p0, p1}, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody$1;-><init>(Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;Lu01/h;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->f:Lu01/b0;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final b()J
    .locals 2

    .line 1
    iget-object p0, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->e:Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/v0;->b()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->e:Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/v0;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->e:Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/v0;->d()Ld01/d0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final p0()Lu01/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/OkHttpCall$ExceptionCatchingResponseBody;->f:Lu01/b0;

    .line 2
    .line 3
    return-object p0
.end method
