.class public final Ltz/h3;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lqd0/i;

.field public final i:Ltr0/b;

.field public final j:Lrz/p;

.field public final k:Lbh0/d;

.field public final l:Lqd0/s0;

.field public final m:Lqd0/w0;

.field public final n:Lij0/a;

.field public o:Ljava/util/List;


# direct methods
.method public constructor <init>(Lqd0/e0;Lqd0/i;Ltr0/b;Lrz/p;Lbh0/d;Lqd0/s0;Lqd0/w0;Lij0/a;)V
    .locals 8

    .line 1
    new-instance v0, Ltz/f3;

    .line 2
    .line 3
    const-string v5, ""

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
    const/4 v6, 0x0

    .line 11
    invoke-direct/range {v0 .. v7}, Ltz/f3;-><init>(Lql0/g;ZZZLjava/lang/String;Ljava/util/List;Z)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p2, p0, Ltz/h3;->h:Lqd0/i;

    .line 18
    .line 19
    iput-object p3, p0, Ltz/h3;->i:Ltr0/b;

    .line 20
    .line 21
    iput-object p4, p0, Ltz/h3;->j:Lrz/p;

    .line 22
    .line 23
    iput-object p5, p0, Ltz/h3;->k:Lbh0/d;

    .line 24
    .line 25
    iput-object p6, p0, Ltz/h3;->l:Lqd0/s0;

    .line 26
    .line 27
    iput-object p7, p0, Ltz/h3;->m:Lqd0/w0;

    .line 28
    .line 29
    move-object/from16 p2, p8

    .line 30
    .line 31
    iput-object p2, p0, Ltz/h3;->n:Lij0/a;

    .line 32
    .line 33
    new-instance p2, Ltz/o2;

    .line 34
    .line 35
    const/4 p3, 0x0

    .line 36
    const/4 p4, 0x2

    .line 37
    invoke-direct {p2, p4, p1, p0, p3}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method
