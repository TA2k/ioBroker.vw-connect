.class public final Lh40/h1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/b;

.field public final i:Lfo0/c;

.field public final j:Lij0/a;

.field public final k:Lf40/v1;

.field public final l:Lf40/o2;

.field public final m:Lf40/o;

.field public final n:Llm0/c;


# direct methods
.method public constructor <init>(Lfo0/b;Lfo0/c;Lij0/a;Lf40/v1;Lf40/o2;Lf40/o;Llm0/c;Lf40/g1;Lf40/u;)V
    .locals 9

    .line 1
    new-instance v0, Lh40/g1;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    const/4 v7, 0x1

    .line 5
    const-string v1, ""

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v8, 0x0

    .line 10
    move-object v2, v1

    .line 11
    move-object v5, v1

    .line 12
    invoke-direct/range {v0 .. v8}, Lh40/g1;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/net/URL;Ljava/lang/String;ZZLql0/g;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lh40/h1;->h:Lfo0/b;

    .line 19
    .line 20
    iput-object p2, p0, Lh40/h1;->i:Lfo0/c;

    .line 21
    .line 22
    iput-object p3, p0, Lh40/h1;->j:Lij0/a;

    .line 23
    .line 24
    iput-object p4, p0, Lh40/h1;->k:Lf40/v1;

    .line 25
    .line 26
    iput-object p5, p0, Lh40/h1;->l:Lf40/o2;

    .line 27
    .line 28
    iput-object p6, p0, Lh40/h1;->m:Lf40/o;

    .line 29
    .line 30
    move-object/from16 p1, p7

    .line 31
    .line 32
    iput-object p1, p0, Lh40/h1;->n:Llm0/c;

    .line 33
    .line 34
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    new-instance p2, Lg1/y2;

    .line 39
    .line 40
    const/16 p3, 0x9

    .line 41
    .line 42
    const/4 p4, 0x0

    .line 43
    move-object p5, p0

    .line 44
    move-object/from16 p7, p4

    .line 45
    .line 46
    move-object/from16 p6, p8

    .line 47
    .line 48
    move-object/from16 p4, p9

    .line 49
    .line 50
    invoke-direct/range {p2 .. p7}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 51
    .line 52
    .line 53
    move-object/from16 p3, p7

    .line 54
    .line 55
    const/4 p4, 0x3

    .line 56
    invoke-static {p1, p3, p3, p2, p4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 57
    .line 58
    .line 59
    new-instance p1, La7/y0;

    .line 60
    .line 61
    const/4 p2, 0x2

    .line 62
    invoke-direct {p1, p0, p3, p2}, La7/y0;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method
