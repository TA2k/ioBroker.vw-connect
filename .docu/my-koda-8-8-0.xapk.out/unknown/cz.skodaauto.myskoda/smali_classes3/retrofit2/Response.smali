.class public final Lretrofit2/Response;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field public final a:Ld01/t0;

.field public final b:Ljava/lang/Object;

.field public final c:Ld01/v0;


# direct methods
.method public constructor <init>(Ld01/t0;Ljava/lang/Object;Ld01/u0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/Response;->a:Ld01/t0;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/Response;->b:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Lretrofit2/Response;->c:Ld01/v0;

    .line 9
    .line 10
    return-void
.end method

.method public static a(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Lretrofit2/Response;
    .locals 18

    .line 1
    sget-object v7, Ld01/v0;->d:Ld01/u0;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v1, 0x14

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Ld01/i0;->g:Ld01/i0;

    .line 11
    .line 12
    new-instance v1, Ld01/j0;

    .line 13
    .line 14
    invoke-direct {v1}, Ld01/j0;-><init>()V

    .line 15
    .line 16
    .line 17
    const-string v3, "http://localhost/"

    .line 18
    .line 19
    invoke-virtual {v1, v3}, Ld01/j0;->f(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    new-instance v3, Ld01/k0;

    .line 23
    .line 24
    invoke-direct {v3, v1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 25
    .line 26
    .line 27
    new-instance v6, Ld01/y;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    new-array v1, v1, [Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, [Ljava/lang/String;

    .line 37
    .line 38
    invoke-direct {v6, v0}, Ld01/y;-><init>([Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance v0, Ld01/t0;

    .line 42
    .line 43
    move-object v1, v3

    .line 44
    const-string v3, "OK"

    .line 45
    .line 46
    const/16 v4, 0xc8

    .line 47
    .line 48
    const/4 v5, 0x0

    .line 49
    const/4 v8, 0x0

    .line 50
    const/4 v9, 0x0

    .line 51
    const/4 v10, 0x0

    .line 52
    const/4 v11, 0x0

    .line 53
    const-wide/16 v12, 0x0

    .line 54
    .line 55
    const-wide/16 v14, 0x0

    .line 56
    .line 57
    const/16 v16, 0x0

    .line 58
    .line 59
    sget-object v17, Ld01/y0;->v0:Ld01/r;

    .line 60
    .line 61
    invoke-direct/range {v0 .. v17}, Ld01/t0;-><init>(Ld01/k0;Ld01/i0;Ljava/lang/String;ILd01/w;Ld01/y;Ld01/v0;Lu01/g0;Ld01/t0;Ld01/t0;Ld01/t0;JJLh01/g;Ld01/y0;)V

    .line 62
    .line 63
    .line 64
    move-object v1, v0

    .line 65
    move-object/from16 v0, p0

    .line 66
    .line 67
    invoke-static {v0, v1}, Lretrofit2/Response;->b(Ljava/lang/Object;Ld01/t0;)Lretrofit2/Response;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    return-object v0
.end method

.method public static b(Ljava/lang/Object;Ld01/t0;)Lretrofit2/Response;
    .locals 2

    .line 1
    iget-boolean v0, p1, Ld01/t0;->t:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lretrofit2/Response;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p1, p0, v1}, Lretrofit2/Response;-><init>(Ld01/t0;Ljava/lang/Object;Ld01/u0;)V

    .line 9
    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    const-string p1, "rawResponse must be successful response"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/Response;->a:Ld01/t0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/t0;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
