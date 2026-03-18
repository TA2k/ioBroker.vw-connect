.class final Lretrofit2/ParameterHandler$QueryName;
.super Lretrofit2/ParameterHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/ParameterHandler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "QueryName"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lretrofit2/ParameterHandler<",
        "TT;>;"
    }
.end annotation


# instance fields
.field public final a:Lretrofit2/Converter;

.field public final b:Z


# direct methods
.method public constructor <init>(Lretrofit2/Converter;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/ParameterHandler;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/ParameterHandler$QueryName;->a:Lretrofit2/Converter;

    .line 5
    .line 6
    iput-boolean p2, p0, Lretrofit2/ParameterHandler$QueryName;->b:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lretrofit2/RequestBuilder;Ljava/lang/Object;)V
    .locals 1

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Lretrofit2/ParameterHandler$QueryName;->a:Lretrofit2/Converter;

    .line 5
    .line 6
    invoke-interface {v0, p2}, Lretrofit2/Converter;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    check-cast p2, Ljava/lang/String;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iget-boolean p0, p0, Lretrofit2/ParameterHandler$QueryName;->b:Z

    .line 14
    .line 15
    invoke-virtual {p1, p2, v0, p0}, Lretrofit2/RequestBuilder;->d(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
