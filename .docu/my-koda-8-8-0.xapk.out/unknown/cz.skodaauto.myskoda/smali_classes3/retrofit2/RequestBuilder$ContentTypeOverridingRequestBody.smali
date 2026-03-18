.class Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/RequestBuilder;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ContentTypeOverridingRequestBody"
.end annotation


# instance fields
.field public final a:Ld01/r0;

.field public final b:Ld01/d0;


# direct methods
.method public constructor <init>(Ld01/r0;Ld01/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;->a:Ld01/r0;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;->b:Ld01/d0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final contentLength()J
    .locals 2

    .line 1
    iget-object p0, p0, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;->a:Ld01/r0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/r0;->contentLength()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public final contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;->b:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final writeTo(Lu01/g;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;->a:Ld01/r0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ld01/r0;->writeTo(Lu01/g;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
