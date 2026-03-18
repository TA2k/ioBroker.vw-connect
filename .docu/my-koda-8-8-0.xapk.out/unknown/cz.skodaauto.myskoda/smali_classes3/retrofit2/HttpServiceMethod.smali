.class abstract Lretrofit2/HttpServiceMethod;
.super Lretrofit2/ServiceMethod;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lretrofit2/HttpServiceMethod$SuspendForBody;,
        Lretrofit2/HttpServiceMethod$SuspendForResponse;,
        Lretrofit2/HttpServiceMethod$CallAdapted;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<ResponseT:",
        "Ljava/lang/Object;",
        "ReturnT:",
        "Ljava/lang/Object;",
        ">",
        "Lretrofit2/ServiceMethod<",
        "TReturnT;>;"
    }
.end annotation


# instance fields
.field public final a:Lretrofit2/RequestFactory;

.field public final b:Ld01/i;

.field public final c:Lretrofit2/Converter;


# direct methods
.method public constructor <init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/ServiceMethod;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/HttpServiceMethod;->a:Lretrofit2/RequestFactory;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/HttpServiceMethod;->b:Ld01/i;

    .line 7
    .line 8
    iput-object p3, p0, Lretrofit2/HttpServiceMethod;->c:Lretrofit2/Converter;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lretrofit2/OkHttpCall;

    .line 2
    .line 3
    iget-object v4, p0, Lretrofit2/HttpServiceMethod;->b:Ld01/i;

    .line 4
    .line 5
    iget-object v5, p0, Lretrofit2/HttpServiceMethod;->c:Lretrofit2/Converter;

    .line 6
    .line 7
    iget-object v1, p0, Lretrofit2/HttpServiceMethod;->a:Lretrofit2/RequestFactory;

    .line 8
    .line 9
    move-object v2, p1

    .line 10
    move-object v3, p2

    .line 11
    invoke-direct/range {v0 .. v5}, Lretrofit2/OkHttpCall;-><init>(Lretrofit2/RequestFactory;Ljava/lang/Object;[Ljava/lang/Object;Ld01/i;Lretrofit2/Converter;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v0, v3}, Lretrofit2/HttpServiceMethod;->c(Lretrofit2/Call;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public abstract c(Lretrofit2/Call;[Ljava/lang/Object;)Ljava/lang/Object;
.end method
