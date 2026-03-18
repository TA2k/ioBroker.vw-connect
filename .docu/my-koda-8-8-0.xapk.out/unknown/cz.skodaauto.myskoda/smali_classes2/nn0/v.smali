.class public final Lnn0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lnn0/w;

.field public final b:Lnn0/q;


# direct methods
.method public constructor <init>(Lnn0/w;Lnn0/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnn0/v;->a:Lnn0/w;

    .line 5
    .line 6
    iput-object p2, p0, Lnn0/v;->b:Lnn0/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lon0/r;)V
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lnn0/v;->b:Lnn0/q;

    .line 7
    .line 8
    check-cast v0, Lln0/e;

    .line 9
    .line 10
    iget-object v0, v0, Lln0/e;->a:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    iget-object v0, p1, Lon0/r;->f:Lon0/s;

    .line 20
    .line 21
    iget-object p0, p0, Lnn0/v;->a:Lnn0/w;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object v2, v0, Lon0/s;->b:Lon0/a;

    .line 26
    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    iget-object v2, v2, Lon0/a;->a:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    const/4 v3, 0x1

    .line 36
    xor-int/2addr v2, v3

    .line 37
    if-ne v2, v3, :cond_0

    .line 38
    .line 39
    iget-boolean v2, p1, Lon0/r;->i:Z

    .line 40
    .line 41
    if-nez v2, :cond_0

    .line 42
    .line 43
    check-cast p0, Liy/b;

    .line 44
    .line 45
    sget-object p1, Lly/b;->I2:Lly/b;

    .line 46
    .line 47
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_0
    if-eqz v0, :cond_1

    .line 52
    .line 53
    iget-object v1, v0, Lon0/s;->a:Lon0/v;

    .line 54
    .line 55
    :cond_1
    if-eqz v1, :cond_2

    .line 56
    .line 57
    iget-object p1, p1, Lon0/r;->h:Ljava/lang/String;

    .line 58
    .line 59
    if-nez p1, :cond_2

    .line 60
    .line 61
    check-cast p0, Liy/b;

    .line 62
    .line 63
    sget-object p1, Lly/b;->H2:Lly/b;

    .line 64
    .line 65
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_2
    check-cast p0, Liy/b;

    .line 70
    .line 71
    sget-object p1, Lly/b;->G2:Lly/b;

    .line 72
    .line 73
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lon0/r;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lnn0/v;->a(Lon0/r;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
