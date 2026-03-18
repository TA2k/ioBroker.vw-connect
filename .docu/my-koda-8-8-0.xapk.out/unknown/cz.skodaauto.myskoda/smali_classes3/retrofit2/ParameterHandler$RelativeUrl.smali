.class final Lretrofit2/ParameterHandler$RelativeUrl;
.super Lretrofit2/ParameterHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/ParameterHandler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "RelativeUrl"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lretrofit2/ParameterHandler<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field public final a:Ljava/lang/reflect/Method;

.field public final b:I


# direct methods
.method public constructor <init>(ILjava/lang/reflect/Method;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/ParameterHandler;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lretrofit2/ParameterHandler$RelativeUrl;->a:Ljava/lang/reflect/Method;

    .line 5
    .line 6
    iput p1, p0, Lretrofit2/ParameterHandler$RelativeUrl;->b:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lretrofit2/RequestBuilder;Ljava/lang/Object;)V
    .locals 1

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iput-object p0, p1, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const/4 p1, 0x0

    .line 11
    new-array p1, p1, [Ljava/lang/Object;

    .line 12
    .line 13
    iget-object p2, p0, Lretrofit2/ParameterHandler$RelativeUrl;->a:Ljava/lang/reflect/Method;

    .line 14
    .line 15
    iget p0, p0, Lretrofit2/ParameterHandler$RelativeUrl;->b:I

    .line 16
    .line 17
    const-string v0, "@Url parameter is null."

    .line 18
    .line 19
    invoke-static {p2, p0, v0, p1}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    throw p0
.end method
