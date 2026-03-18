.class public final Ljp/xg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljp/sg;


# instance fields
.field public final a:Lgs/o;

.field public final b:Lgs/o;

.field public final c:Ljp/rg;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljp/rg;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Ljp/xg;->c:Ljp/rg;

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
    const/4 v1, 0x0

    .line 39
    invoke-direct {v0, p1, v1}, Ljp/wg;-><init>(Lrn/p;I)V

    .line 40
    .line 41
    .line 42
    invoke-direct {p2, v0}, Lgs/o;-><init>(Lgt/b;)V

    .line 43
    .line 44
    .line 45
    iput-object p2, p0, Ljp/xg;->a:Lgs/o;

    .line 46
    .line 47
    :cond_0
    new-instance p2, Lgs/o;

    .line 48
    .line 49
    new-instance v0, Ljp/wg;

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    invoke-direct {v0, p1, v1}, Ljp/wg;-><init>(Lrn/p;I)V

    .line 53
    .line 54
    .line 55
    invoke-direct {p2, v0}, Lgs/o;-><init>(Lgt/b;)V

    .line 56
    .line 57
    .line 58
    iput-object p2, p0, Ljp/xg;->b:Lgs/o;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final a(Lbb/g0;)V
    .locals 5

    .line 1
    iget-object v0, p0, Ljp/xg;->c:Ljp/rg;

    .line 2
    .line 3
    iget v1, v0, Ljp/rg;->b:I

    .line 4
    .line 5
    iget v0, v0, Ljp/rg;->b:I

    .line 6
    .line 7
    sget-object v2, Lon/d;->e:Lon/d;

    .line 8
    .line 9
    sget-object v3, Lon/d;->d:Lon/d;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    if-nez v1, :cond_2

    .line 13
    .line 14
    iget-object p0, p0, Ljp/xg;->a:Lgs/o;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lrn/q;

    .line 23
    .line 24
    iget v1, p1, Lbb/g0;->e:I

    .line 25
    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Lbb/g0;->x(I)[B

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    new-instance v0, Lon/a;

    .line 33
    .line 34
    invoke-direct {v0, p1, v3, v4}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-virtual {p1, v0}, Lbb/g0;->x(I)[B

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance v0, Lon/a;

    .line 43
    .line 44
    invoke-direct {v0, p1, v2, v4}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 45
    .line 46
    .line 47
    :goto_0
    new-instance p1, Lj9/d;

    .line 48
    .line 49
    const/16 v1, 0x19

    .line 50
    .line 51
    invoke-direct {p1, v1}, Lj9/d;-><init>(I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0, v0, p1}, Lrn/q;->a(Lon/a;Lon/g;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    return-void

    .line 58
    :cond_2
    iget-object p0, p0, Ljp/xg;->b:Lgs/o;

    .line 59
    .line 60
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Lrn/q;

    .line 65
    .line 66
    iget v1, p1, Lbb/g0;->e:I

    .line 67
    .line 68
    if-eqz v1, :cond_3

    .line 69
    .line 70
    invoke-virtual {p1, v0}, Lbb/g0;->x(I)[B

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    new-instance v0, Lon/a;

    .line 75
    .line 76
    invoke-direct {v0, p1, v3, v4}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    invoke-virtual {p1, v0}, Lbb/g0;->x(I)[B

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    new-instance v0, Lon/a;

    .line 85
    .line 86
    invoke-direct {v0, p1, v2, v4}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 87
    .line 88
    .line 89
    :goto_1
    new-instance p1, Lj9/d;

    .line 90
    .line 91
    const/16 v1, 0x19

    .line 92
    .line 93
    invoke-direct {p1, v1}, Lj9/d;-><init>(I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0, v0, p1}, Lrn/q;->a(Lon/a;Lon/g;)V

    .line 97
    .line 98
    .line 99
    return-void
.end method
