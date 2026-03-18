.class public final Le30/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lbh0/g;

.field public final i:Lbh0/j;

.field public final j:Ltr0/b;

.field public final k:Lud0/b;

.field public final l:Lc30/a;

.field public final m:Lrq0/f;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Lc30/e;Lbh0/g;Lbh0/j;Ltr0/b;Lud0/b;Lc30/a;Lrq0/f;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Le30/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v1, v2, v2}, Le30/b;-><init>(Le30/v;Lql0/g;ZZ)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Le30/d;->h:Lbh0/g;

    .line 12
    .line 13
    iput-object p3, p0, Le30/d;->i:Lbh0/j;

    .line 14
    .line 15
    iput-object p4, p0, Le30/d;->j:Ltr0/b;

    .line 16
    .line 17
    iput-object p5, p0, Le30/d;->k:Lud0/b;

    .line 18
    .line 19
    iput-object p6, p0, Le30/d;->l:Lc30/a;

    .line 20
    .line 21
    iput-object p7, p0, Le30/d;->m:Lrq0/f;

    .line 22
    .line 23
    iput-object p8, p0, Le30/d;->n:Lij0/a;

    .line 24
    .line 25
    invoke-virtual {p1}, Lc30/e;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p1, Lne0/t;

    .line 30
    .line 31
    instance-of p2, p1, Lne0/e;

    .line 32
    .line 33
    if-eqz p2, :cond_0

    .line 34
    .line 35
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    move-object p3, p2

    .line 40
    check-cast p3, Le30/b;

    .line 41
    .line 42
    check-cast p1, Lne0/e;

    .line 43
    .line 44
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Ld30/a;

    .line 47
    .line 48
    invoke-static {p1, p8, v2}, Lkp/y;->c(Ld30/a;Lij0/a;Z)Le30/v;

    .line 49
    .line 50
    .line 51
    move-result-object p5

    .line 52
    const/4 p7, 0x0

    .line 53
    const/16 p8, 0xd

    .line 54
    .line 55
    const/4 p4, 0x0

    .line 56
    const/4 p6, 0x0

    .line 57
    invoke-static/range {p3 .. p8}, Le30/b;->a(Le30/b;Lql0/g;Le30/v;ZZI)Le30/b;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_0
    instance-of p0, p1, Lne0/c;

    .line 66
    .line 67
    if-eqz p0, :cond_1

    .line 68
    .line 69
    invoke-virtual {p4}, Ltr0/b;->invoke()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :cond_1
    new-instance p0, La8/r0;

    .line 74
    .line 75
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 76
    .line 77
    .line 78
    throw p0
.end method
