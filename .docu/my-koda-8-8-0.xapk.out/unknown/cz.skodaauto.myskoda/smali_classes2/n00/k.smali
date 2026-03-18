.class public final Ln00/k;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ll00/i;

.field public final i:Ll00/e;

.field public final j:Ll00/n;

.field public final k:Lbd0/c;

.field public final l:Ltr0/b;


# direct methods
.method public constructor <init>(Ll00/i;Ll00/e;Ll00/n;Lbd0/c;Ltr0/b;)V
    .locals 2

    .line 1
    new-instance v0, Ln00/j;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ln00/j;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Ln00/k;->h:Ll00/i;

    .line 12
    .line 13
    iput-object p2, p0, Ln00/k;->i:Ll00/e;

    .line 14
    .line 15
    iput-object p3, p0, Ln00/k;->j:Ll00/n;

    .line 16
    .line 17
    iput-object p4, p0, Ln00/k;->k:Lbd0/c;

    .line 18
    .line 19
    iput-object p5, p0, Ln00/k;->l:Ltr0/b;

    .line 20
    .line 21
    new-instance p1, Ln00/i;

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    const/4 p3, 0x0

    .line 25
    invoke-direct {p1, p0, p3, p2}, Ln00/i;-><init>(Ln00/k;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    new-instance p2, Ln00/i;

    .line 36
    .line 37
    const/4 p4, 0x1

    .line 38
    invoke-direct {p2, p0, p3, p4}, Ln00/i;-><init>(Ln00/k;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    invoke-static {p1, p3, p3, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    return-void
.end method
