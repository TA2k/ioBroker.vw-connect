.class public final Lqi0/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lhq0/h;

.field public final j:Lkg0/a;

.field public final k:Lij0/a;

.field public final l:Lrq0/f;

.field public final m:Lrq0/d;

.field public final n:Loi0/b;


# direct methods
.method public constructor <init>(Loi0/c;Ltr0/b;Lhq0/h;Lkg0/a;Lij0/a;Lrq0/f;Lrq0/d;Loi0/b;)V
    .locals 1

    .line 1
    new-instance v0, Lqi0/a;

    .line 2
    .line 3
    invoke-direct {v0}, Lqi0/a;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lqi0/d;->h:Ltr0/b;

    .line 10
    .line 11
    iput-object p3, p0, Lqi0/d;->i:Lhq0/h;

    .line 12
    .line 13
    iput-object p4, p0, Lqi0/d;->j:Lkg0/a;

    .line 14
    .line 15
    iput-object p5, p0, Lqi0/d;->k:Lij0/a;

    .line 16
    .line 17
    iput-object p6, p0, Lqi0/d;->l:Lrq0/f;

    .line 18
    .line 19
    iput-object p7, p0, Lqi0/d;->m:Lrq0/d;

    .line 20
    .line 21
    iput-object p8, p0, Lqi0/d;->n:Loi0/b;

    .line 22
    .line 23
    invoke-virtual {p1}, Loi0/c;->invoke()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Lpi0/b;

    .line 28
    .line 29
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    check-cast p2, Lqi0/a;

    .line 34
    .line 35
    iget-object p3, p1, Lpi0/b;->a:Ljava/lang/Object;

    .line 36
    .line 37
    iget p1, p1, Lpi0/b;->b:I

    .line 38
    .line 39
    const/4 p4, 0x0

    .line 40
    const/4 p5, 0x4

    .line 41
    invoke-static {p2, p1, p3, p4, p5}, Lqi0/a;->a(Lqi0/a;ILjava/util/List;ZI)Lqi0/a;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final h()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lqi0/a;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x3

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static {v0, v3, v1, v3, v2}, Lqi0/a;->a(Lqi0/a;ILjava/util/List;ZI)Lqi0/a;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
