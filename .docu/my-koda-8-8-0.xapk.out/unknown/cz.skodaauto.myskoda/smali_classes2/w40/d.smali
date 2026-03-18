.class public final Lw40/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lnn0/u;

.field public final i:Lnn0/v;

.field public final j:Lu40/m;

.field public final k:Lud0/b;

.field public final l:Lrq0/f;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Lnn0/u;Lnn0/v;Lu40/m;Lud0/b;Lrq0/f;Lij0/a;)V
    .locals 6

    .line 1
    new-instance v0, Lw40/c;

    .line 2
    .line 3
    const/4 v2, 0x1

    .line 4
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const-string v1, ""

    .line 7
    .line 8
    const/4 v5, 0x0

    .line 9
    move-object v3, v1

    .line 10
    invoke-direct/range {v0 .. v5}, Lw40/c;-><init>(Ljava/lang/String;ZLjava/lang/String;Ljava/util/List;Lon0/u;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lw40/d;->h:Lnn0/u;

    .line 17
    .line 18
    iput-object p2, p0, Lw40/d;->i:Lnn0/v;

    .line 19
    .line 20
    iput-object p3, p0, Lw40/d;->j:Lu40/m;

    .line 21
    .line 22
    iput-object p4, p0, Lw40/d;->k:Lud0/b;

    .line 23
    .line 24
    iput-object p5, p0, Lw40/d;->l:Lrq0/f;

    .line 25
    .line 26
    iput-object p6, p0, Lw40/d;->m:Lij0/a;

    .line 27
    .line 28
    new-instance p1, Lw40/b;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    const/4 p3, 0x0

    .line 32
    invoke-direct {p1, p0, p2, p3}, Lw40/b;-><init>(Lw40/d;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
