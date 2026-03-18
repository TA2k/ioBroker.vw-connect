.class final Lretrofit2/OkHttpCall$NoContentResponseBody;
.super Ld01/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/OkHttpCall;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "NoContentResponseBody"
.end annotation


# instance fields
.field public final e:Ld01/d0;

.field public final f:J


# direct methods
.method public constructor <init>(Ld01/d0;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/OkHttpCall$NoContentResponseBody;->e:Ld01/d0;

    .line 5
    .line 6
    iput-wide p2, p0, Lretrofit2/OkHttpCall$NoContentResponseBody;->f:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lretrofit2/OkHttpCall$NoContentResponseBody;->f:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final d()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/OkHttpCall$NoContentResponseBody;->e:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p0()Lu01/h;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string v0, "Cannot read raw response body of a converted body."

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
