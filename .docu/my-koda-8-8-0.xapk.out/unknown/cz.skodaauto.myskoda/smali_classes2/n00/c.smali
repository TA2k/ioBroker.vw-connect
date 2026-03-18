.class public final Ln00/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ll00/i;

.field public final i:Ll00/j;

.field public final j:Ll00/k;

.field public final k:Ll00/c;

.field public final l:Lhh0/a;


# direct methods
.method public constructor <init>(Ll00/i;Ll00/j;Ll00/k;Ll00/c;Lhh0/a;)V
    .locals 3

    .line 1
    new-instance v0, Ln00/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    invoke-direct {v0, v1, v2}, Ln00/b;-><init>(ZLjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Ln00/c;->h:Ll00/i;

    .line 13
    .line 14
    iput-object p2, p0, Ln00/c;->i:Ll00/j;

    .line 15
    .line 16
    iput-object p3, p0, Ln00/c;->j:Ll00/k;

    .line 17
    .line 18
    iput-object p4, p0, Ln00/c;->k:Ll00/c;

    .line 19
    .line 20
    iput-object p5, p0, Ln00/c;->l:Lhh0/a;

    .line 21
    .line 22
    new-instance p1, Ln00/a;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    const/4 p3, 0x0

    .line 26
    invoke-direct {p1, p0, p3, p2}, Ln00/a;-><init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 30
    .line 31
    .line 32
    new-instance p1, Ln00/a;

    .line 33
    .line 34
    const/4 p2, 0x1

    .line 35
    invoke-direct {p1, p0, p3, p2}, Ln00/a;-><init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method
