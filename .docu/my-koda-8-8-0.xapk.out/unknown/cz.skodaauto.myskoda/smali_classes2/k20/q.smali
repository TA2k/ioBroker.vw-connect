.class public final Lk20/q;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Li20/t;

.field public final i:Lkf0/a;

.field public final j:Li20/l;

.field public final k:Li20/j;

.field public final l:Li20/m;

.field public final m:Li20/k;

.field public final n:Lkf0/i;

.field public final o:Li20/g;

.field public final p:Li20/u;

.field public final q:Li20/b;

.field public final r:Ltr0/b;

.field public final s:Lrq0/d;

.field public final t:Lij0/a;


# direct methods
.method public constructor <init>(Li20/t;Lkf0/a;Li20/l;Li20/j;Li20/m;Li20/k;Lkf0/i;Li20/g;Li20/u;Li20/b;Ltr0/b;Lrq0/d;Lij0/a;)V
    .locals 8

    .line 1
    new-instance v0, Lk20/o;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    sget-object v7, Lj20/h;->d:Lj20/h;

    .line 5
    .line 6
    const-string v1, ""

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    move-object v5, v1

    .line 11
    move-object v6, v1

    .line 12
    invoke-direct/range {v0 .. v7}, Lk20/o;-><init>(Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Lj20/h;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lk20/q;->h:Li20/t;

    .line 19
    .line 20
    iput-object p2, p0, Lk20/q;->i:Lkf0/a;

    .line 21
    .line 22
    iput-object p3, p0, Lk20/q;->j:Li20/l;

    .line 23
    .line 24
    iput-object p4, p0, Lk20/q;->k:Li20/j;

    .line 25
    .line 26
    iput-object p5, p0, Lk20/q;->l:Li20/m;

    .line 27
    .line 28
    iput-object p6, p0, Lk20/q;->m:Li20/k;

    .line 29
    .line 30
    iput-object p7, p0, Lk20/q;->n:Lkf0/i;

    .line 31
    .line 32
    move-object/from16 p1, p8

    .line 33
    .line 34
    iput-object p1, p0, Lk20/q;->o:Li20/g;

    .line 35
    .line 36
    move-object/from16 p1, p9

    .line 37
    .line 38
    iput-object p1, p0, Lk20/q;->p:Li20/u;

    .line 39
    .line 40
    move-object/from16 p1, p10

    .line 41
    .line 42
    iput-object p1, p0, Lk20/q;->q:Li20/b;

    .line 43
    .line 44
    move-object/from16 p1, p11

    .line 45
    .line 46
    iput-object p1, p0, Lk20/q;->r:Ltr0/b;

    .line 47
    .line 48
    move-object/from16 p1, p12

    .line 49
    .line 50
    iput-object p1, p0, Lk20/q;->s:Lrq0/d;

    .line 51
    .line 52
    move-object/from16 p1, p13

    .line 53
    .line 54
    iput-object p1, p0, Lk20/q;->t:Lij0/a;

    .line 55
    .line 56
    new-instance p1, Lk20/a;

    .line 57
    .line 58
    const/4 p2, 0x0

    .line 59
    const/4 p3, 0x1

    .line 60
    invoke-direct {p1, p0, p2, p3}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 64
    .line 65
    .line 66
    return-void
.end method
