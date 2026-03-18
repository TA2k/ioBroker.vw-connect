.class public final Lwk0/i0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Luk0/y;

.field public final i:Lbd0/c;

.field public final j:Luk0/k0;

.field public final k:Lck0/d;

.field public final l:Ltr0/b;

.field public final m:Lij0/a;

.field public final n:Luk0/p0;

.field public final o:Lrq0/d;


# direct methods
.method public constructor <init>(Luk0/y;Lbd0/c;Luk0/k0;Lck0/d;Ltr0/b;Lij0/a;Luk0/p0;Lrq0/d;)V
    .locals 9

    .line 1
    new-instance v0, Lwk0/h0;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    const/4 v8, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const-string v3, ""

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v7, 0x0

    .line 12
    invoke-direct/range {v0 .. v8}, Lwk0/h0;-><init>(Ljava/lang/String;Lwk0/j0;Ljava/lang/String;Ljava/lang/String;ZZLwk0/g0;Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lwk0/i0;->h:Luk0/y;

    .line 19
    .line 20
    iput-object p2, p0, Lwk0/i0;->i:Lbd0/c;

    .line 21
    .line 22
    iput-object p3, p0, Lwk0/i0;->j:Luk0/k0;

    .line 23
    .line 24
    iput-object p4, p0, Lwk0/i0;->k:Lck0/d;

    .line 25
    .line 26
    iput-object p5, p0, Lwk0/i0;->l:Ltr0/b;

    .line 27
    .line 28
    iput-object p6, p0, Lwk0/i0;->m:Lij0/a;

    .line 29
    .line 30
    move-object/from16 p1, p7

    .line 31
    .line 32
    iput-object p1, p0, Lwk0/i0;->n:Luk0/p0;

    .line 33
    .line 34
    move-object/from16 p1, p8

    .line 35
    .line 36
    iput-object p1, p0, Lwk0/i0;->o:Lrq0/d;

    .line 37
    .line 38
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance p2, Lvo0/e;

    .line 43
    .line 44
    const/16 p3, 0xd

    .line 45
    .line 46
    const/4 p4, 0x0

    .line 47
    invoke-direct {p2, p0, p4, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x3

    .line 51
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 52
    .line 53
    .line 54
    return-void
.end method
