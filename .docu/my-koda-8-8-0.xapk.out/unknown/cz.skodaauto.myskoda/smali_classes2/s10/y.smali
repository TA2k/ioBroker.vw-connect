.class public final Ls10/y;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lq10/v;

.field public final j:Lyn0/p;

.field public final k:Lyn0/q;

.field public final l:Lyn0/r;

.field public final m:Lij0/a;

.field public final n:Lq10/w;

.field public o:Lr10/b;

.field public p:Lr10/b;


# direct methods
.method public constructor <init>(Lq10/r;Ltr0/b;Lq10/v;Lyn0/p;Lyn0/q;Lyn0/r;Lij0/a;Lq10/w;)V
    .locals 10

    .line 1
    new-instance v0, Ls10/x;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, ""

    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v8, 0x0

    .line 12
    const/4 v9, 0x0

    .line 13
    invoke-direct/range {v0 .. v9}, Ls10/x;-><init>(Lql0/g;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/List;Ls10/w;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 17
    .line 18
    .line 19
    iput-object p2, p0, Ls10/y;->h:Ltr0/b;

    .line 20
    .line 21
    iput-object p3, p0, Ls10/y;->i:Lq10/v;

    .line 22
    .line 23
    iput-object p4, p0, Ls10/y;->j:Lyn0/p;

    .line 24
    .line 25
    iput-object p5, p0, Ls10/y;->k:Lyn0/q;

    .line 26
    .line 27
    move-object/from16 p2, p6

    .line 28
    .line 29
    iput-object p2, p0, Ls10/y;->l:Lyn0/r;

    .line 30
    .line 31
    move-object/from16 p2, p7

    .line 32
    .line 33
    iput-object p2, p0, Ls10/y;->m:Lij0/a;

    .line 34
    .line 35
    move-object/from16 p2, p8

    .line 36
    .line 37
    iput-object p2, p0, Ls10/y;->n:Lq10/w;

    .line 38
    .line 39
    new-instance p2, Lr60/t;

    .line 40
    .line 41
    const/4 p3, 0x0

    .line 42
    const/16 p4, 0x9

    .line 43
    .line 44
    invoke-direct {p2, p4, p1, p0, p3}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method
