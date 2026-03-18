.class final Lretrofit2/ParameterHandler$Part;
.super Lretrofit2/ParameterHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/ParameterHandler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Part"
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
.field public final a:Ljava/lang/reflect/Method;

.field public final b:I

.field public final c:Ld01/y;

.field public final d:Lretrofit2/Converter;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Method;ILd01/y;Lretrofit2/Converter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/ParameterHandler;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/ParameterHandler$Part;->a:Ljava/lang/reflect/Method;

    .line 5
    .line 6
    iput p2, p0, Lretrofit2/ParameterHandler$Part;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lretrofit2/ParameterHandler$Part;->c:Ld01/y;

    .line 9
    .line 10
    iput-object p4, p0, Lretrofit2/ParameterHandler$Part;->d:Lretrofit2/Converter;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lretrofit2/RequestBuilder;Ljava/lang/Object;)V
    .locals 2

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    :try_start_0
    iget-object v0, p0, Lretrofit2/ParameterHandler$Part;->d:Lretrofit2/Converter;

    .line 5
    .line 6
    invoke-interface {v0, p2}, Lretrofit2/Converter;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Ld01/r0;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    iget-object p0, p0, Lretrofit2/ParameterHandler$Part;->c:Ld01/y;

    .line 13
    .line 14
    invoke-virtual {p1, p0, v0}, Lretrofit2/RequestBuilder;->c(Ld01/y;Ld01/r0;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :catch_0
    move-exception p1

    .line 19
    const-string v0, "Unable to convert "

    .line 20
    .line 21
    const-string v1, " to RequestBody"

    .line 22
    .line 23
    invoke-static {p2, v0, v1}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iget-object v0, p0, Lretrofit2/ParameterHandler$Part;->a:Ljava/lang/reflect/Method;

    .line 32
    .line 33
    iget p0, p0, Lretrofit2/ParameterHandler$Part;->b:I

    .line 34
    .line 35
    invoke-static {v0, p0, p2, p1}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    throw p0
.end method
