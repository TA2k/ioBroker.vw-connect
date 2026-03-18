.class public final Llp/mg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llp/hg;


# instance fields
.field public final a:Lgs/o;

.field public final b:Llp/gg;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llp/gg;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Llp/mg;->b:Llp/gg;

    .line 5
    .line 6
    sget-object p2, Lpn/a;->e:Lpn/a;

    .line 7
    .line 8
    invoke-static {p1}, Lrn/r;->b(Landroid/content/Context;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lrn/r;->a()Lrn/r;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p1, p2}, Lrn/r;->c(Lrn/l;)Lrn/p;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    sget-object p2, Lpn/a;->d:Ljava/util/Set;

    .line 20
    .line 21
    new-instance v0, Lon/c;

    .line 22
    .line 23
    const-string v1, "json"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p2, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    if-eqz p2, :cond_0

    .line 33
    .line 34
    new-instance p2, Lgs/o;

    .line 35
    .line 36
    new-instance v0, Ljp/wg;

    .line 37
    .line 38
    const/4 v1, 0x4

    .line 39
    invoke-direct {v0, p1, v1}, Ljp/wg;-><init>(Lrn/p;I)V

    .line 40
    .line 41
    .line 42
    invoke-direct {p2, v0}, Lgs/o;-><init>(Lgt/b;)V

    .line 43
    .line 44
    .line 45
    :cond_0
    new-instance p2, Lgs/o;

    .line 46
    .line 47
    new-instance v0, Ljp/wg;

    .line 48
    .line 49
    const/4 v1, 0x5

    .line 50
    invoke-direct {v0, p1, v1}, Ljp/wg;-><init>(Lrn/p;I)V

    .line 51
    .line 52
    .line 53
    invoke-direct {p2, v0}, Lgs/o;-><init>(Lgt/b;)V

    .line 54
    .line 55
    .line 56
    iput-object p2, p0, Llp/mg;->a:Lgs/o;

    .line 57
    .line 58
    return-void
.end method


# virtual methods
.method public final a(Lbb/g0;)V
    .locals 3

    .line 1
    iget-object v0, p0, Llp/mg;->b:Llp/gg;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llp/mg;->a:Lgs/o;

    .line 7
    .line 8
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lrn/q;

    .line 13
    .line 14
    iget v0, p1, Lbb/g0;->e:I

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p1}, Lbb/g0;->w()[B

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    new-instance v0, Lon/a;

    .line 24
    .line 25
    sget-object v2, Lon/d;->d:Lon/d;

    .line 26
    .line 27
    invoke-direct {v0, p1, v2, v1}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {p1}, Lbb/g0;->w()[B

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    new-instance v0, Lon/a;

    .line 36
    .line 37
    sget-object v2, Lon/d;->e:Lon/d;

    .line 38
    .line 39
    invoke-direct {v0, p1, v2, v1}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 40
    .line 41
    .line 42
    :goto_0
    new-instance p1, Lj9/d;

    .line 43
    .line 44
    const/16 v1, 0x19

    .line 45
    .line 46
    invoke-direct {p1, v1}, Lj9/d;-><init>(I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v0, p1}, Lrn/q;->a(Lon/a;Lon/g;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method
