.class public final Ltz/k1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lqd0/m1;

.field public final i:Lqd0/l;

.field public final j:Lrz/b;

.field public final k:Lrz/l0;

.field public final l:Ljn0/c;

.field public final m:Lyt0/b;

.field public final n:Lrq0/f;

.field public final o:Lij0/a;

.field public final p:Ltr0/b;

.field public final q:Lhh0/a;


# direct methods
.method public constructor <init>(Lqd0/o0;Lqd0/j0;Lqd0/m1;Lqd0/l;Lrz/b;Lrz/l0;Ljn0/c;Lyt0/b;Lrq0/f;Lij0/a;Ltr0/b;Lhh0/a;)V
    .locals 6

    .line 1
    new-instance v0, Ltz/j1;

    .line 2
    .line 3
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const/4 v1, 0x1

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Ltz/j1;-><init>(ZLjava/util/List;Lrd0/h;Lrd0/h;Z)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p3, p0, Ltz/k1;->h:Lqd0/m1;

    .line 16
    .line 17
    iput-object p4, p0, Ltz/k1;->i:Lqd0/l;

    .line 18
    .line 19
    iput-object p5, p0, Ltz/k1;->j:Lrz/b;

    .line 20
    .line 21
    iput-object p6, p0, Ltz/k1;->k:Lrz/l0;

    .line 22
    .line 23
    iput-object p7, p0, Ltz/k1;->l:Ljn0/c;

    .line 24
    .line 25
    iput-object p8, p0, Ltz/k1;->m:Lyt0/b;

    .line 26
    .line 27
    iput-object p9, p0, Ltz/k1;->n:Lrq0/f;

    .line 28
    .line 29
    move-object/from16 p3, p10

    .line 30
    .line 31
    iput-object p3, p0, Ltz/k1;->o:Lij0/a;

    .line 32
    .line 33
    move-object/from16 p3, p11

    .line 34
    .line 35
    iput-object p3, p0, Ltz/k1;->p:Ltr0/b;

    .line 36
    .line 37
    move-object/from16 p3, p12

    .line 38
    .line 39
    iput-object p3, p0, Ltz/k1;->q:Lhh0/a;

    .line 40
    .line 41
    new-instance p3, Ltr0/e;

    .line 42
    .line 43
    const/4 p8, 0x0

    .line 44
    const/4 p4, 0x2

    .line 45
    move-object p7, p0

    .line 46
    move-object p5, p1

    .line 47
    move-object p6, p2

    .line 48
    invoke-direct/range {p3 .. p8}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, p3}, Lql0/j;->b(Lay0/n;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method
