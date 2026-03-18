.class public final Lh50/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lpp0/c1;

.field public final j:Lpp0/s;

.field public final k:Lpp0/e;

.field public final l:Lrq0/d;

.field public final m:Lpp0/g;

.field public final n:Lf50/j;

.field public final o:Ltr0/b;

.field public p:Lvy0/x1;


# direct methods
.method public constructor <init>(Lpp0/r;Lij0/a;Lpp0/c1;Lpp0/s;Lpp0/e;Lrq0/d;Lpp0/g;Lf50/j;Ltr0/b;)V
    .locals 4

    .line 1
    new-instance v0, Lh50/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v2, v3}, Lh50/e;-><init>(ZZLjava/lang/String;Lyj0/a;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lh50/h;->h:Lij0/a;

    .line 14
    .line 15
    iput-object p3, p0, Lh50/h;->i:Lpp0/c1;

    .line 16
    .line 17
    iput-object p4, p0, Lh50/h;->j:Lpp0/s;

    .line 18
    .line 19
    iput-object p5, p0, Lh50/h;->k:Lpp0/e;

    .line 20
    .line 21
    iput-object p6, p0, Lh50/h;->l:Lrq0/d;

    .line 22
    .line 23
    iput-object p7, p0, Lh50/h;->m:Lpp0/g;

    .line 24
    .line 25
    iput-object p8, p0, Lh50/h;->n:Lf50/j;

    .line 26
    .line 27
    iput-object p9, p0, Lh50/h;->o:Ltr0/b;

    .line 28
    .line 29
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    move-object p4, p3

    .line 34
    check-cast p4, Lh50/e;

    .line 35
    .line 36
    invoke-virtual {p1}, Lpp0/r;->invoke()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    move-object p7, p1

    .line 41
    check-cast p7, Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {p2}, Lh50/h;->h(Lij0/a;)Lyj0/a;

    .line 44
    .line 45
    .line 46
    move-result-object p8

    .line 47
    const/4 p9, 0x3

    .line 48
    const/4 p5, 0x0

    .line 49
    const/4 p6, 0x0

    .line 50
    invoke-static/range {p4 .. p9}, Lh50/e;->a(Lh50/e;ZZLjava/lang/String;Lyj0/a;I)Lh50/e;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public static h(Lij0/a;)Lyj0/a;
    .locals 4

    .line 1
    new-instance v0, Lyj0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Ljj0/f;

    .line 7
    .line 8
    const v3, 0x7f120664

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const v3, 0x7f120668

    .line 16
    .line 17
    .line 18
    new-array v1, v1, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-virtual {p0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const/4 v1, 0x2

    .line 25
    invoke-direct {v0, v2, p0, v1}, Lyj0/a;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method
