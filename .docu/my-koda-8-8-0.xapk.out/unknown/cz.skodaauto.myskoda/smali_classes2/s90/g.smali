.class public final Ls90/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lgn0/i;

.field public final j:Lgn0/a;

.field public final k:Lks0/s;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lgn0/i;Lgn0/a;Lks0/s;Lij0/a;)V
    .locals 11

    .line 1
    new-instance v0, Ls90/f;

    .line 2
    .line 3
    const/4 v7, 0x0

    .line 4
    sget-object v9, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const-string v2, ""

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v10, 0x0

    .line 13
    move-object v3, v2

    .line 14
    move-object v8, v2

    .line 15
    invoke-direct/range {v0 .. v10}, Ls90/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/List;Lql0/g;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Ls90/g;->h:Ltr0/b;

    .line 22
    .line 23
    iput-object p2, p0, Ls90/g;->i:Lgn0/i;

    .line 24
    .line 25
    iput-object p3, p0, Ls90/g;->j:Lgn0/a;

    .line 26
    .line 27
    iput-object p4, p0, Ls90/g;->k:Lks0/s;

    .line 28
    .line 29
    move-object/from16 p1, p5

    .line 30
    .line 31
    iput-object p1, p0, Ls90/g;->l:Lij0/a;

    .line 32
    .line 33
    new-instance p1, Lrp0/a;

    .line 34
    .line 35
    const/4 p2, 0x0

    .line 36
    const/4 p3, 0x7

    .line 37
    invoke-direct {p1, p0, p2, p3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method
