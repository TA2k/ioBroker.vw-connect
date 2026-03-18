.class public final Lnt0/i;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Llt0/b;

.field public final i:Llt0/a;

.field public final j:Lkf0/m;

.field public final k:Lgn0/f;

.field public final l:Llt0/f;

.field public final m:Ltj0/a;

.field public final n:Llt0/h;

.field public final o:Ltr0/b;

.field public final p:Lrs0/g;

.field public final q:Lqf0/g;

.field public final r:Lij0/a;


# direct methods
.method public constructor <init>(Llt0/b;Llt0/a;Lkf0/m;Lgn0/f;Llt0/f;Ltj0/a;Llt0/h;Ltr0/b;Lrs0/g;Lqf0/g;Lij0/a;)V
    .locals 8

    .line 1
    new-instance v0, Lnt0/e;

    .line 2
    .line 3
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v7, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    const-string v5, ""

    .line 11
    .line 12
    invoke-direct/range {v0 .. v7}, Lnt0/e;-><init>(Lql0/g;ZZZLjava/lang/String;Ljava/util/List;Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lnt0/i;->h:Llt0/b;

    .line 19
    .line 20
    iput-object p2, p0, Lnt0/i;->i:Llt0/a;

    .line 21
    .line 22
    iput-object p3, p0, Lnt0/i;->j:Lkf0/m;

    .line 23
    .line 24
    iput-object p4, p0, Lnt0/i;->k:Lgn0/f;

    .line 25
    .line 26
    iput-object p5, p0, Lnt0/i;->l:Llt0/f;

    .line 27
    .line 28
    iput-object p6, p0, Lnt0/i;->m:Ltj0/a;

    .line 29
    .line 30
    iput-object p7, p0, Lnt0/i;->n:Llt0/h;

    .line 31
    .line 32
    move-object/from16 p1, p8

    .line 33
    .line 34
    iput-object p1, p0, Lnt0/i;->o:Ltr0/b;

    .line 35
    .line 36
    move-object/from16 p1, p9

    .line 37
    .line 38
    iput-object p1, p0, Lnt0/i;->p:Lrs0/g;

    .line 39
    .line 40
    move-object/from16 p1, p10

    .line 41
    .line 42
    iput-object p1, p0, Lnt0/i;->q:Lqf0/g;

    .line 43
    .line 44
    move-object/from16 p1, p11

    .line 45
    .line 46
    iput-object p1, p0, Lnt0/i;->r:Lij0/a;

    .line 47
    .line 48
    new-instance p1, Lnt0/d;

    .line 49
    .line 50
    const/4 p2, 0x0

    .line 51
    const/4 p3, 0x0

    .line 52
    invoke-direct {p1, p2, p3, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 56
    .line 57
    .line 58
    new-instance p1, Lnt0/d;

    .line 59
    .line 60
    const/4 p2, 0x1

    .line 61
    invoke-direct {p1, p2, p3, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method
