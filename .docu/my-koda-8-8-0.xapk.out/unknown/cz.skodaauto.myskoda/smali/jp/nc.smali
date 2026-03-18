.class public final Ljp/nc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljp/ug;


# instance fields
.field public a:Ljp/ac;


# virtual methods
.method public h()Lbb/g0;
    .locals 2

    .line 1
    new-instance v0, Lin/z1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Llv/a;->c()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    sget-object v1, Ljp/zb;->f:Ljp/zb;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    sget-object v1, Ljp/zb;->e:Ljp/zb;

    .line 16
    .line 17
    :goto_0
    iget-object p0, p0, Ljp/nc;->a:Ljp/ac;

    .line 18
    .line 19
    iput-object v1, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 20
    .line 21
    new-instance v1, Ljp/nc;

    .line 22
    .line 23
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p0, v1, Ljp/nc;->a:Ljp/ac;

    .line 27
    .line 28
    new-instance p0, Ljp/oc;

    .line 29
    .line 30
    invoke-direct {p0, v1}, Ljp/oc;-><init>(Ljp/nc;)V

    .line 31
    .line 32
    .line 33
    iput-object p0, v0, Lin/z1;->e:Ljava/lang/Object;

    .line 34
    .line 35
    new-instance p0, Lbb/g0;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-direct {p0, v0, v1}, Lbb/g0;-><init>(Lin/z1;I)V

    .line 39
    .line 40
    .line 41
    return-object p0
.end method
