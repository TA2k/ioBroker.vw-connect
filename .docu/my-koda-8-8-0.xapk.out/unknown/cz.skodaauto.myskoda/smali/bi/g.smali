.class public final Lbi/g;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lzg/h;

.field public final e:Lai/a;

.field public final f:Lzg/c1;

.field public final g:Lbi/b;

.field public final h:Lzb/d;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/l1;


# direct methods
.method public constructor <init>(Ly1/i;Lzg/h;Lai/a;Lzg/c1;La7/o;Lbi/b;Lzb/d;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lbi/g;->d:Lzg/h;

    .line 5
    .line 6
    iput-object p3, p0, Lbi/g;->e:Lai/a;

    .line 7
    .line 8
    iput-object p4, p0, Lbi/g;->f:Lzg/c1;

    .line 9
    .line 10
    iput-object p6, p0, Lbi/g;->g:Lbi/b;

    .line 11
    .line 12
    iput-object p7, p0, Lbi/g;->h:Lzb/d;

    .line 13
    .line 14
    new-instance p1, Lbi/f;

    .line 15
    .line 16
    iget-object p4, p2, Lzg/h;->t:Lzg/q1;

    .line 17
    .line 18
    const/4 p5, 0x0

    .line 19
    if-eqz p4, :cond_0

    .line 20
    .line 21
    iget-boolean p4, p4, Lzg/q1;->d:Z

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move p4, p5

    .line 25
    :goto_0
    if-eqz p3, :cond_1

    .line 26
    .line 27
    iget-object p6, p3, Lai/a;->a:Lzg/h1;

    .line 28
    .line 29
    if-eqz p6, :cond_1

    .line 30
    .line 31
    iget-object p6, p6, Lzg/h1;->h:Ljava/lang/String;

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const/4 p6, 0x0

    .line 35
    :goto_1
    if-eqz p6, :cond_2

    .line 36
    .line 37
    const/4 p5, 0x1

    .line 38
    :cond_2
    const/4 p6, 0x0

    .line 39
    move v0, p4

    .line 40
    move-object p4, p3

    .line 41
    move p3, v0

    .line 42
    invoke-direct/range {p1 .. p6}, Lbi/f;-><init>(Lzg/h;ZLai/a;ZZ)V

    .line 43
    .line 44
    .line 45
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iput-object p1, p0, Lbi/g;->i:Lyy0/c2;

    .line 50
    .line 51
    new-instance p2, Lyy0/l1;

    .line 52
    .line 53
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 54
    .line 55
    .line 56
    iput-object p2, p0, Lbi/g;->j:Lyy0/l1;

    .line 57
    .line 58
    return-void
.end method
