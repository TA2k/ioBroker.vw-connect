.class public final Lh40/t;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lf40/i1;

.field public final i:Lf40/r;

.field public final j:Lf40/m4;

.field public final k:Lrq0/f;

.field public final l:Lij0/a;

.field public final m:Lf40/w1;

.field public final n:Lf40/f4;

.field public final o:Lf40/y2;

.field public final p:Lf40/q1;

.field public final q:Lbq0/b;

.field public final r:Lf40/z2;

.field public final s:Lrq0/d;

.field public final t:Lf40/b3;


# direct methods
.method public constructor <init>(Lf40/i1;Lf40/r;Lf40/m4;Lrq0/f;Lij0/a;Lf40/w1;Lf40/f4;Lf40/y2;Lf40/q1;Lbq0/b;Lf40/z2;Lrq0/d;Lf40/b3;)V
    .locals 3

    .line 1
    new-instance v0, Lh40/q;

    .line 2
    .line 3
    const/16 v1, 0xfff

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v2, v2, v1}, Lh40/q;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/ArrayList;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lh40/t;->h:Lf40/i1;

    .line 13
    .line 14
    iput-object p2, p0, Lh40/t;->i:Lf40/r;

    .line 15
    .line 16
    iput-object p3, p0, Lh40/t;->j:Lf40/m4;

    .line 17
    .line 18
    iput-object p4, p0, Lh40/t;->k:Lrq0/f;

    .line 19
    .line 20
    iput-object p5, p0, Lh40/t;->l:Lij0/a;

    .line 21
    .line 22
    iput-object p6, p0, Lh40/t;->m:Lf40/w1;

    .line 23
    .line 24
    iput-object p7, p0, Lh40/t;->n:Lf40/f4;

    .line 25
    .line 26
    iput-object p8, p0, Lh40/t;->o:Lf40/y2;

    .line 27
    .line 28
    iput-object p9, p0, Lh40/t;->p:Lf40/q1;

    .line 29
    .line 30
    iput-object p10, p0, Lh40/t;->q:Lbq0/b;

    .line 31
    .line 32
    iput-object p11, p0, Lh40/t;->r:Lf40/z2;

    .line 33
    .line 34
    iput-object p12, p0, Lh40/t;->s:Lrq0/d;

    .line 35
    .line 36
    move-object/from16 p1, p13

    .line 37
    .line 38
    iput-object p1, p0, Lh40/t;->t:Lf40/b3;

    .line 39
    .line 40
    new-instance p1, Lh40/p;

    .line 41
    .line 42
    const/4 p2, 0x0

    .line 43
    invoke-direct {p1, p0, v2, p2}, Lh40/p;-><init>(Lh40/t;Lkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method
